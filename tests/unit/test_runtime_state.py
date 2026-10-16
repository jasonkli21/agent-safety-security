"""Concurrency, exact one-shot redemption, and evidence failures at the real boundary."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from test_runtime_policy import NOW, contract_with

from agentsec.contracts.models import Budgets
from agentsec.domain.approvals import ApprovalDecision, ApprovalRequest
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import (
    ApprovalOutcome,
    EnforcementMode,
    EventType,
    PolicyOutcome,
    SideEffectClass,
)
from agentsec.domain.tools import ToolDescriptor
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.policy.native import NativePolicyEngine
from agentsec.runtime.approvals import ApprovalLedger
from agentsec.runtime.budgets import BudgetLedger
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure, ToolResponse


def tool(side=SideEffectClass.READ, destructive=False):
    return ToolDescriptor(
        schema_version="0.1",
        tool_id="tool",
        namespace="test",
        name="test",
        protocol="test",
        description="test",
        input_schema={"type": "object"},
        side_effect_class=side,
        destructive=destructive,
        capabilities=frozenset({"web.search"}),
    )


class Broker:
    async def decide(self, request, presentation):
        return ApprovalDecision(
            schema_version="0.1",
            approval_id=request.approval_id,
            approver=contract_with().identity.principal,
            outcome=ApprovalOutcome.APPROVE,
            decided_at=NOW,
        )


def runtime(contract=None, **kwargs):
    sink = InMemoryEventSink()
    gateway = RuntimeGateway(
        contract or contract_with(),
        EnforcementMode.ENFORCE,
        RuntimeEvents(sink, lambda: NOW),
        Broker(),
        **kwargs,
    )
    return gateway, sink


@pytest.mark.parametrize(
    "limits,descriptor",
    [
        (Budgets(max_tool_calls=1), tool()),
        (Budgets(max_external_writes=1), tool(SideEffectClass.EXTERNAL_WRITE)),
        (Budgets(max_destructive_calls=1), tool(SideEffectClass.DESTRUCTIVE, True)),
    ],
)
def test_budget_atomic_reservation(limits, descriptor):
    ledger = BudgetLedger(limits)

    def reserve(_):
        try:
            return ledger.reserve(descriptor)[0]
        except RuntimeFailure:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        tokens = [t for t in pool.map(reserve, range(20)) if t]
    assert len(tokens) == 1
    ledger.release(tokens[0])
    token, _ = ledger.reserve(descriptor)
    ledger.commit(token)
    with pytest.raises(RuntimeFailure, match="BUDGET_EXCEEDED"):
        ledger.reserve(descriptor)


def test_elapsed_budget_rechecked_after_approval():
    elapsed = [0.0]
    ledger = BudgetLedger(Budgets(max_runtime_seconds=5), lambda: elapsed[0])
    token, _ = ledger.reserve(tool())
    elapsed[0] = 5
    with pytest.raises(RuntimeFailure, match="BUDGET_EXCEEDED"):
        ledger.commit(token)
    ledger.release(token)


def approval():
    return ApprovalRequest(
        schema_version="0.1",
        approval_id="approval",
        policy_request_id="request",
        action_digest="sha256:" + "a" * 64,
        summary="redacted",
        reason_codes=frozenset(),
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=1),
    )


@pytest.mark.parametrize(
    "violation", ["digest", "expired", "reused", "invalidated", "denied", "future"]
)
def test_approval_exact_expiring_one_shot(violation):
    now = [NOW]
    ledger = ApprovalLedger(lambda: now[0])
    request = approval()
    ledger.create(request)
    decision = asyncio.run(Broker().decide(request, "safe presentation"))
    if violation == "denied":
        decision = decision.model_copy(update={"outcome": ApprovalOutcome.DENY})
    if violation == "future":
        decision = decision.model_copy(update={"decided_at": NOW + timedelta(seconds=1)})
        with pytest.raises(RuntimeFailure, match="INVALID_APPROVAL"):
            ledger.record(decision)
        return
    ledger.record(decision)
    digest = request.action_digest
    if violation == "digest":
        digest = "sha256:" + "b" * 64
    elif violation == "expired":
        now[0] += timedelta(seconds=1)
    elif violation == "reused":
        ledger.redeem(request.approval_id, digest)
    elif violation == "invalidated":
        ledger.invalidate(request.approval_id)
    with pytest.raises(RuntimeFailure, match="APPROVAL_DENIED_OR_EXPIRED"):
        ledger.redeem(request.approval_id, digest)


def test_cancellation_releases_reservation_and_invalidates_approval():
    async def scenario():
        entered = asyncio.Event()

        class PendingBroker:
            async def decide(self, request, presentation):
                self.request = request
                entered.set()
                await asyncio.Event().wait()

        gateway, _sink = runtime(
            contract_with(
                tools={
                    "rules": [
                        {
                            "rule_id": "approval",
                            "capability": "web.search",
                            "decision": "REQUIRE_APPROVAL",
                        }
                    ]
                },
                budgets={"max_tool_calls": 1},
            )
        )
        broker = PendingBroker()
        gateway.broker = broker
        dispatched = []

        async def forward(args):
            dispatched.append(args)
            return ToolResponse(body={}, success=True)

        task = asyncio.create_task(gateway.call(tool(), {}, None, forward, bound=True))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not dispatched
        with pytest.raises(RuntimeFailure):
            gateway.approvals.redeem(broker.request.approval_id, broker.request.action_digest)
        gateway.broker = Broker()
        await gateway.call(tool(), {}, None, forward, bound=True)
        assert len(dispatched) == 1

    asyncio.run(scenario())


def test_attempt_consumes_budget_even_if_upstream_errors():
    async def scenario():
        gateway, sink = runtime(contract_with(budgets={"max_tool_calls": 1}))
        attempts = []

        async def forward(args):
            attempts.append(1)
            raise ValueError("secret upstream diagnostic")

        with pytest.raises(RuntimeFailure, match="UPSTREAM_FAILURE"):
            await gateway.call(tool(), {}, None, forward, bound=True)
        with pytest.raises(RuntimeFailure, match="BUDGET_EXCEEDED"):
            await gateway.call(tool(), {}, None, forward, bound=True)
        assert len(attempts) == 1
        assert [
            e.payload.success for e in sink.events if e.event_type == EventType.TOOL_RETURNED
        ] == [False]

    asyncio.run(scenario())


def test_policy_and_evidence_fail_closed():
    async def scenario():
        attempts = []

        async def forward(args):
            attempts.append(1)
            return ToolResponse(body={}, success=True)

        class BrokenPolicy:
            def decide(self, request, contract):
                raise ValueError("secret")

        gateway, _ = runtime(policy=BrokenPolicy())
        with pytest.raises(RuntimeFailure, match="POLICY_ENGINE_ERROR"):
            await gateway.call(tool(), {}, None, forward, bound=True)
        gateway, _ = runtime()

        class BrokenSink:
            def append(self, event):
                raise OSError("secret")

        gateway.events.sink = BrokenSink()
        with pytest.raises(RuntimeFailure, match="EVIDENCE_WRITE_FAILURE"):
            await gateway.call(tool(), {}, None, forward, bound=True)
        assert not attempts

    asyncio.run(scenario())


def test_runtime_call_requires_explicit_binding_proof():
    gateway, _sink = runtime()

    async def forward(args):
        return ToolResponse(body={}, success=True)

    with pytest.raises(TypeError, match="bound"):
        gateway.call(tool(), {}, None, forward)


def test_resource_scoped_evidence_marks_redaction_and_links_policy_input():
    selected_contract = contract_with(
        task_scope={
            "task_id": "private-task",
            "description": "private task details",
            "requested_capabilities": ["web.search"],
            "resource_scopes": {"web.search": ["private-resource"]},
        },
        tools={
            "rules": [
                {
                    "rule_id": "allow-search",
                    "capability": "web.search",
                    "decision": "ALLOW",
                }
            ]
        },
    )
    actual_requests = []

    class CapturingPolicy:
        def decide(self, request, contract):
            actual_requests.append(request)
            return NativePolicyEngine(lambda: NOW).decide(request, contract)

    gateway, sink = runtime(selected_contract, policy=CapturingPolicy())

    async def forward(args):
        return ToolResponse(body={"ok": True}, success=True)

    asyncio.run(gateway.call(tool(), {}, "private-resource", forward, bound=True))
    requested = next(
        event.payload for event in sink.events if event.event_type == EventType.TOOL_REQUESTED
    )
    evaluated = next(
        event.payload.decision
        for event in sink.events
        if event.event_type == EventType.POLICY_EVALUATED
    )
    actual = actual_requests[0]
    assert requested.request.resource is None and requested.request.task_scope is None
    assert requested.redacted_fields == {"resource", "task_scope"}
    assert requested.resource_digest == content_digest(actual.resource)
    assert requested.task_scope_digest == content_digest(actual.task_scope)
    assert requested.policy_input_digest == content_digest(actual)
    assert evaluated.request_id == requested.request.request_id
    assert evaluated.outcome == PolicyOutcome.ALLOW
    serialized = " ".join(event.model_dump_json() for event in sink.events)
    assert "private-resource" not in serialized
    assert "private task details" not in serialized


def test_unexpected_sink_failure_poisoning_blocks_future_dispatch():
    gateway, _ = runtime(contract_with(budgets={"max_tool_calls": 3}))
    attempts = []

    class BrokenReturnSink:
        def __init__(self):
            self.events = []

        def append(self, event):
            if event.event_type == EventType.TOOL_RETURNED:
                raise RuntimeError("private sink diagnostic")
            self.events.append(event)

    gateway.events.sink = BrokenReturnSink()

    def broken_notification():
        raise RuntimeError("notification failure")

    gateway.events.on_failure = broken_notification

    async def forward(args):
        attempts.append(1)
        return ToolResponse(body={}, success=True)

    with pytest.raises(RuntimeFailure, match="EVIDENCE_WRITE_FAILURE"):
        asyncio.run(gateway.call(tool(), {}, None, forward, bound=True))
    assert gateway.events.failed
    with pytest.raises(RuntimeFailure, match="EVIDENCE_WRITE_FAILURE"):
        asyncio.run(gateway.call(tool(), {}, None, forward, bound=True))
    assert len(attempts) == 1


def test_cancellation_after_dispatch_entry_consumes_budget_and_marks_unknown_effect():
    async def scenario():
        gateway, sink = runtime(contract_with(budgets={"max_tool_calls": 1}))
        entered = asyncio.Event()

        async def forward(args):
            entered.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(gateway.call(tool(), {}, None, forward, bound=True))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert any(
            event.payload.redacted_summary == "DISPATCH_CANCELLED_EFFECT_UNKNOWN"
            for event in sink.events
            if event.event_type == EventType.SECURITY_SIGNAL
        )
        with pytest.raises(RuntimeFailure, match="BUDGET_EXCEEDED"):
            await gateway.call(tool(), {}, None, forward, bound=True)

    asyncio.run(scenario())


def test_unsupported_contract_refuses_enforce():
    with pytest.raises(RuntimeFailure, match="UNSUPPORTED_POLICY_SEMANTICS"):
        runtime(contract_with(budgets={"max_model_calls": 0}))


def test_evidence_failure_at_dispatch_refunds_and_poison_blocks_future_calls():
    async def scenario():
        gateway, sink = runtime(contract_with(budgets={"max_tool_calls": 1}))
        attempts = []

        class FailingDispatchSink:
            def append(self, event):
                if event.event_type == EventType.TOOL_DISPATCHED:
                    raise OSError("no space")
                sink.append(event)

        gateway.events.sink = FailingDispatchSink()

        async def forward(args):
            attempts.append(1)
            return ToolResponse(body={}, success=True)

        for _ in range(2):
            with pytest.raises(RuntimeFailure, match="EVIDENCE_WRITE_FAILURE"):
                await gateway.call(tool(), {}, None, forward, bound=True)
        assert not attempts
        # Refunded counters and released reservation; the poisoned recorder still refuses calls.
        token, _ = gateway.budgets.reserve(tool())
        gateway.budgets.release(token)

    asyncio.run(scenario())


def test_evidence_failure_after_dispatch_does_not_erase_attempt():
    async def scenario():
        gateway, sink = runtime(contract_with(budgets={"max_tool_calls": 1}))
        attempts = []

        class FailingReturnSink:
            def append(self, event):
                if event.event_type == EventType.TOOL_RETURNED:
                    raise OSError("no space")
                sink.append(event)

        gateway.events.sink = FailingReturnSink()

        async def forward(args):
            attempts.append(1)
            return ToolResponse(body={}, success=True)

        with pytest.raises(RuntimeFailure, match="EVIDENCE_WRITE_FAILURE"):
            await gateway.call(tool(), {}, None, forward, bound=True)
        assert len(attempts) == 1
        assert any(e.event_type == EventType.TOOL_DISPATCHED for e in sink.events)
        with pytest.raises(RuntimeFailure, match="BUDGET_EXCEEDED"):
            gateway.budgets.reserve(tool())

    asyncio.run(scenario())


def test_terminal_unavailable_does_not_touch_protocol_streams(monkeypatch):
    import os

    from agentsec.runtime.terminal_approval import TerminalApprovalBroker

    def unavailable(*args, **kwargs):
        raise OSError("no controlling terminal")

    monkeypatch.setattr(os, "open", unavailable)
    with pytest.raises(RuntimeFailure, match="APPROVAL_UNAVAILABLE"):
        asyncio.run(TerminalApprovalBroker().decide(approval(), "safe presentation"))
