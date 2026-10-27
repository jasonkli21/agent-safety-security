"""Adversarial witnesses for the foundation-readiness review."""

import asyncio
import sqlite3

import pytest
from test_runtime_policy import NOW, contract_with
from test_runtime_state import Broker, runtime, tool

from agentsec.contracts.models import Budgets
from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.store import DDL, MAX_AUDIT_ROWS, ScopedStore
from agentsec.domain.taxonomy import EventType, PolicyOutcome
from agentsec.policy.native import NativePolicyEngine
from agentsec.runtime.budgets import BudgetLedger
from agentsec.runtime.models import RuntimeFailure, ToolResponse


@pytest.mark.parametrize("ceiling", ["DENY", "REQUIRE_APPROVAL"])
def test_backend_cannot_widen_compiled_ceiling(ceiling):
    class AllowBackend:
        def decide(self, request, plan):
            return (
                NativePolicyEngine(lambda: NOW)
                .decide(request, plan)
                .model_copy(update={"outcome": PolicyOutcome.ALLOW})
            )

    contract = contract_with(
        tools={"rules": [{"rule_id": "ceiling", "capability": "web.search", "decision": ceiling}]}
    )
    gateway, sink = runtime(contract, policy=AllowBackend())
    calls = []

    async def dispatch(arguments):
        calls.append(arguments)
        return ToolResponse(body={}, success=True)

    if ceiling == "DENY":
        with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
            asyncio.run(gateway.call(tool(), {}, None, dispatch, bound=True))
        assert not calls
    else:
        asyncio.run(gateway.call(tool(), {}, None, dispatch, bound=True))
        assert len(calls) == 1
        assert any(e.event_type == EventType.APPROVAL_REQUESTED for e in sink.events)


def test_finish_fences_pending_approvals_and_is_idempotent():
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()

        class PendingBroker(Broker):
            async def decide(self, request, presentation):
                entered.set()
                await release.wait()
                return await super().decide(request, presentation)

        gateway, sink = runtime(
            contract_with(
                tools={
                    "rules": [
                        {
                            "rule_id": "approval",
                            "capability": "web.search",
                            "decision": "REQUIRE_APPROVAL",
                        }
                    ]
                }
            )
        )
        gateway.broker = PendingBroker()
        calls = []

        async def dispatch(arguments):
            calls.append(arguments)
            return ToolResponse(body={}, success=True)

        pending = asyncio.create_task(gateway.call(tool(), {}, None, dispatch, bound=True))
        await entered.wait()
        gateway.finish()
        gateway.finish()
        release.set()
        with pytest.raises(RuntimeFailure, match="SESSION_CLOSED"):
            await pending
        assert not calls
        assert [e.event_type for e in sink.events].count(EventType.RUN_FINISHED) == 1
        assert sink.events[-1].event_type == EventType.RUN_FINISHED
        assert not gateway.budgets._pending and not gateway.approvals._requests

    asyncio.run(scenario())


def test_global_audit_capacity_exact_boundary_and_rollback():
    connection = sqlite3.connect(":memory:")
    connection.executescript(DDL)
    connection.executemany("INSERT INTO orgs VALUES (?)", [("a",), ("b",)])
    connection.executemany(
        "INSERT INTO audit(org,actor,action,target,version,at) "
        "VALUES ('a','actor','action','id',1,'now')",
        [() for _ in range(MAX_AUDIT_ROWS - 1)],
    )
    connection.commit()
    with connection:
        ScopedStore(connection, "b").audit("actor", "action", "last", 1, "now")
    with pytest.raises(TeamError, match="AUDIT_CAPACITY"), connection:
        store = ScopedStore(connection, "a")
        store.put("member", "rolled-back", "{}")
        store.audit("actor", "action", "over", 1, "now")
    assert connection.execute("SELECT count(*) FROM audit").fetchone()[0] == MAX_AUDIT_ROWS
    assert ScopedStore(connection, "a").get("member", "rolled-back") is None


def test_slow_dispatch_evidence_records_preentry_abort():
    elapsed = [0.0]
    gateway, sink = runtime(
        budgets=BudgetLedger(Budgets(max_runtime_seconds=5), lambda: elapsed[0])
    )
    original = sink.append

    def append(event):
        original(event)
        if event.event_type == EventType.TOOL_DISPATCHED:
            elapsed[0] = 5.0

    sink.append = append
    calls = []

    async def dispatch(arguments):
        calls.append(arguments)
        return ToolResponse(body={}, success=True)

    with pytest.raises(RuntimeFailure, match="BUDGET_EXCEEDED"):
        asyncio.run(gateway.call(tool(), {}, None, dispatch, bound=True))
    assert not calls
    aborts = [
        e.payload
        for e in sink.events
        if e.event_type == EventType.SECURITY_SIGNAL
        and e.payload.redacted_summary == "DISPATCH_ABORTED_BEFORE_ENTRY"
    ]
    assert len(aborts) == 1
    dispatch_id = next(
        e.payload.dispatch_id for e in sink.events if e.event_type == EventType.TOOL_DISPATCHED
    )
    assert aborts[0].artifact_refs == {dispatch_id}
    assert not gateway.budgets._pending and not gateway.budgets._receipts
    from agentsec.domain.replay import ReplayError, ReplayProgram
    from agentsec.evidence.dispatch import dispatch_admissions
    from agentsec.replay.bundle import validate_program

    assert not dispatch_admissions(sink.events)
    from uuid import UUID

    from agentsec.control_plane.metadata import project_events

    metadata = project_events(
        events=sink.events,
        run_id=UUID(gateway.events.run_id),
        agent_id="agent",
        environment="test",
        repository="test",
        start=NOW,
        end=NOW,
    )
    assert metadata.counters.dispatched == 0
    with pytest.raises(ReplayError, match="PREENTRY_ABORT_REPLAY_UNSUPPORTED"):
        validate_program(ReplayProgram(schema_version="0.1", events=sink.events, tools=(tool(),)))


@pytest.mark.parametrize(
    "violation", ["request_id", "contract_id", "effective_policy_hash", "exception", "deny"]
)
def test_backend_failures_and_restrictions_remain_closed(violation):
    class Backend:
        def decide(self, request, plan):
            if violation == "exception":
                raise ValueError("synthetic backend failure")
            decision = NativePolicyEngine(lambda: NOW).decide(request, plan)
            if violation == "deny":
                return decision.model_copy(update={"outcome": PolicyOutcome.DENY})
            value = "sha256:" + "0" * 64 if violation == "effective_policy_hash" else "wrong"
            return decision.model_copy(update={violation: value})

    gateway, _ = runtime(policy=Backend())

    async def forbidden(arguments):
        pytest.fail("dispatcher must not be entered")

    with pytest.raises(RuntimeFailure, match=r"POLICY_DENIED|POLICY_ENGINE_ERROR"):
        asyncio.run(gateway.call(tool(), {}, None, forbidden, bound=True))


def test_finish_drains_already_entered_dispatch_before_terminal():
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        gateway, sink = runtime()

        async def dispatch(arguments):
            entered.set()
            await release.wait()
            return ToolResponse(body={}, success=True)

        pending = asyncio.create_task(gateway.call(tool(), {}, None, dispatch, bound=True))
        await entered.wait()
        gateway.finish()
        assert not any(e.event_type == EventType.RUN_FINISHED for e in sink.events)
        with pytest.raises(RuntimeFailure, match="SESSION_CLOSED"):
            await gateway.call(tool(), {}, None, dispatch, bound=True)
        release.set()
        assert (await pending).success
        assert sink.events[-1].event_type == EventType.RUN_FINISHED

    asyncio.run(scenario())


def test_reentrant_finish_during_dispatch_evidence_prevents_entry():
    gateway, sink = runtime()
    original = sink.append

    def append(event):
        original(event)
        if event.event_type == EventType.TOOL_DISPATCHED:
            gateway.finish()

    sink.append = append

    async def forbidden(arguments):
        pytest.fail("closed session entered dispatcher")

    with pytest.raises(RuntimeFailure, match="SESSION_CLOSED"):
        asyncio.run(gateway.call(tool(), {}, None, forbidden, bound=True))
    assert sink.events[-1].event_type == EventType.RUN_FINISHED


def test_expiry_during_evidence_is_rechecked_at_actual_entry():
    from datetime import timedelta

    from agentsec.domain.authority import AuthorityContext
    from agentsec.identity.static import StaticIdentityProvider

    expiry = NOW + timedelta(seconds=5)
    credential = StaticIdentityProvider(contract_with().identity.principal).verify(None, NOW)
    authority = AuthorityContext(
        schema_version="0.1", credential=credential.model_copy(update={"expires_at": expiry})
    )
    gateway, sink = runtime(authority=authority)
    original = sink.append

    def append(event):
        original(event)
        if event.event_type == EventType.TOOL_DISPATCHED:
            gateway.events.clock = lambda: expiry + timedelta(seconds=1)

    sink.append = append

    async def forbidden(arguments):
        pytest.fail("expired authority entered dispatcher")

    with pytest.raises(RuntimeFailure):
        asyncio.run(gateway.call(tool(), {}, None, forbidden, bound=True))
    assert any(
        getattr(e.payload, "redacted_summary", None) == "DISPATCH_ABORTED_BEFORE_ENTRY"
        for e in sink.events
    )


def test_current_runtime_incident_replay_active_regression_lifecycle():
    """One actual protected local run becomes a safe regression without live replay effects."""
    from agentsec.compiler import compile_contract
    from agentsec.domain.scenarios import ToolNotCalled
    from agentsec.incident.classify import classify
    from agentsec.incident.promote import promote
    from agentsec.regression.runner import run_case
    from agentsec.replay.bundle import create_bundle
    from agentsec.replay.engine import replay

    contract = contract_with(task_scope=None, budgets={"max_tool_calls": 2})
    gateway, sink = runtime(contract)
    calls = []

    async def dispatch(arguments):
        calls.append(arguments)
        return ToolResponse(body={"synthetic": "response"}, success=True)

    asyncio.run(gateway.call(tool(), {}, None, dispatch, bound=True))
    gateway.finish()
    bundle = create_bundle(
        sink.events,
        contract,
        tools=(tool(),),
        expectations=(ToolNotCalled(type="TOOL_NOT_CALLED", tool_id="tool"),),
    )
    incident = classify(bundle)
    assert replay(bundle).assertions[0].status.value == "FAIL"
    case = promote(bundle, incident)
    assert case.state.value == "ACTIVE"
    assert run_case(case) == "FAIL"
    corrected = contract_with(
        task_scope=None,
        budgets={"max_tool_calls": 2},
        tools={"rules": [{"rule_id": "deny", "capability": "web.search", "decision": "DENY"}]},
    )
    assert run_case(case, compile_contract(corrected)) == "PASS"
    assert calls == [{}]  # Replay/regression never calls the dispatcher again.


@pytest.mark.parametrize("violation", ["orphan", "duplicate", "return_after", "effect_before"])
def test_abort_causality_rejects_contradictory_evidence(violation):
    from test_replay import source

    from agentsec.domain.events import (
        EffectVerifiedPayload,
        SecuritySignalPayload,
        ToolReturnedPayload,
    )
    from agentsec.domain.taxonomy import SecurityCategory, Severity
    from agentsec.eval.observations import EvaluationObservation
    from agentsec.eval.trajectory import EvaluationError, validate_evaluation_trajectory

    contract, original, _ = source(transport=True)
    dispatched = next(e.payload for e in original if e.event_type == EventType.TOOL_DISPATCHED)
    abort = SecuritySignalPayload(
        kind=EventType.SECURITY_SIGNAL,
        category=SecurityCategory.TRACE_INTEGRITY_FAILURE,
        severity=Severity.HIGH,
        redacted_summary="DISPATCH_ABORTED_BEFORE_ENTRY",
        artifact_refs=frozenset({"unknown" if violation == "orphan" else dispatched.dispatch_id}),
    )
    payloads = [abort]
    if violation == "duplicate":
        payloads.append(abort)
    elif violation == "return_after":
        payloads.append(
            ToolReturnedPayload(
                kind=EventType.TOOL_RETURNED,
                dispatch_id=dispatched.dispatch_id,
                request_id=dispatched.request_id,
                tool_id=dispatched.tool_id,
                success=False,
            )
        )
    elif violation == "effect_before":
        payloads.insert(
            0,
            EffectVerifiedPayload(
                kind=EventType.EFFECT_VERIFIED,
                dispatch_id=dispatched.dispatch_id,
                request_id=dispatched.request_id,
                verifier=contract.identity.principal,
                verified=True,
                evidence_artifact_refs=frozenset({"effect"}),
            ),
        )
    events = [*original[:-1]]
    for index, payload in enumerate(payloads):
        events.append(
            original[-1].model_copy(
                update={
                    "event_id": f"inserted-{index}",
                    "payload": payload,
                    "event_type": payload.kind,
                }
            )
        )
    events.append(original[-1])
    events[0] = events[0].model_copy(
        update={"payload": events[0].payload.model_copy(update={"scenario_id": "abort-test"})}
    )
    events = tuple(e.model_copy(update={"sequence": index}) for index, e in enumerate(events))
    with pytest.raises(EvaluationError, match="INVALID_TRAJECTORY"):
        validate_evaluation_trajectory(
            EvaluationObservation(
                scenario_id="abort-test",
                run_id=events[0].run_id,
                trace_id=events[0].trace_id,
                events=events,
            )
        )
