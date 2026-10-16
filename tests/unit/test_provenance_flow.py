"""Phase 4 trusted metadata, restrictive composition and finite verification."""

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.compiler import compile_contract
from agentsec.compiler.diff import semantic_diff
from agentsec.compiler.probes import generate_probes, synthetic_artifacts
from agentsec.compiler.reporting import coverage_report, run_conformance
from agentsec.contracts.canonical import effective_policy_hash
from agentsec.contracts.loader import load_contract, validate_data
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.approvals import NormalizedAction, action_digest
from agentsec.domain.events import DataExposedPayload, ToolReturnedPayload
from agentsec.domain.policy import PolicyRequest
from agentsec.domain.provenance import DataArtifactRef, DataOrigin
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import (
    DataLabel,
    EnforcementMode,
    EventType,
    PolicyOutcome,
    ReasonCode,
    TrustClass,
)
from agentsec.domain.tools import ToolDescriptor
from agentsec.eval.contract_cases import run_contract_cases
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.policy.native import NativePolicyEngine
from agentsec.provenance import ProvenanceEngine, ProvenanceError
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure, ToolResponse

NOW = datetime(2026, 10, 16, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]
ORIGIN = DataOrigin(origin_type="test", trust_class=TrustClass.TOOL_OUTPUT)


def contract(*data_rules, base="ALLOW", **updates):
    data = load_contract(ROOT / "examples/mcp/contract.yaml").model_dump(mode="json")
    data.update(
        task_scope=None,
        budgets={},
        data={"rules": list(data_rules)},
        tools={"rules": [{"rule_id": "base", "capability": "web.search", "decision": base}]},
    )
    data.update(updates)
    return validate_data(AgentSecurityContract, data)


def request(c, *, labels=frozenset({DataLabel.SECRET}), destination="external"):
    plan = compile_contract(c)
    return PolicyRequest(
        schema_version="0.1",
        request_id="r",
        principal=plan.principal,
        agent=plan.agent.request_agent(),
        environment=plan.environment,
        capability="web.search",
        tool_id="test",
        requested_at=NOW,
        data_artifact_refs=synthetic_artifacts(labels),
        data_destination=destination,
    )


def test_graph_monotonic_lineage_and_registration():
    ids = iter(["source", "derived"])
    graph = ProvenanceEngine(lambda: NOW, lambda: next(ids))
    a = graph.derive(ORIGIN, labels=frozenset({DataLabel.SECRET}))
    b = graph.derive(ORIGIN, parents=(a,), labels=frozenset({DataLabel.UNTRUSTED_CONTENT}))
    assert b.labels == {DataLabel.SECRET, DataLabel.UNTRUSTED_CONTENT}
    assert graph.lineage(b.artifact_id) == (a,)
    assert graph.get(a.artifact_id) == a and a.created_at == NOW
    for ref in (a, a.model_copy(update={"labels": frozenset()})):
        with pytest.raises(ProvenanceError, match="DUPLICATE_ARTIFACT_ID"):
            graph.register(ref)
    with pytest.raises(ProvenanceError, match="NON_MONOTONIC"):
        graph.register(b.model_copy(update={"artifact_id": "bad", "labels": frozenset()}))
    with pytest.raises(ProvenanceError, match="UNKNOWN_PARENT"):
        graph.register(
            a.model_copy(
                update={"artifact_id": "unknown", "parent_artifact_ids": frozenset({"missing"})}
            )
        )
    with pytest.raises(ProvenanceError, match="UNTRUSTED_PARENT"):
        graph.derive(ORIGIN, parents=(a.model_copy(update={"labels": frozenset()}),))
    with pytest.raises(ValidationError):
        a.labels = frozenset()
    with pytest.raises(ProvenanceError, match="UNKNOWN_ARTIFACT"):
        graph.get("missing")


def test_frontier_concurrent_branches_and_failed_exposure():
    graph = ProvenanceEngine()
    a, b = graph.derive(ORIGIN), graph.derive(ORIGIN)
    assert graph.snapshot() == ()

    def fail():
        raise RuntimeError("record failed")

    with pytest.raises(RuntimeError):
        graph.expose(a, fail)
    assert graph.snapshot() == ()
    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(graph.expose, (a, b)))
    assert set(graph.snapshot()) == {a, b}
    c = graph.derive(ORIGIN, parents=(a,))
    graph.expose(c)
    assert set(graph.snapshot()) == {b, c}
    with pytest.raises(ProvenanceError, match="DUPLICATE_EXPOSURE"):
        graph.expose(a)


@pytest.mark.parametrize(
    "fields,destination,outcome,reason",
    [
        ({"denied_capabilities": ["web.search"]}, "internal", "DENY", "DATA_FLOW_DENIED"),
        ({"allowed_capabilities": ["other.tool"]}, "internal", "DENY", "DATA_FLOW_DENIED"),
        ({"allowed_capabilities": []}, None, "ALLOW", "EXPLICIT_ALLOW"),
        ({"allowed_capabilities": ["web.search"]}, None, "ALLOW", "EXPLICIT_ALLOW"),
        ({"denied_destinations": ["external"]}, "external", "DENY", "DATA_FLOW_DENIED"),
        ({"allowed_destinations": ["internal"]}, "external", "DENY", "DATA_FLOW_DENIED"),
        ({"denied_destinations": ["external"]}, None, "ERROR", "DATA_FLOW_CONTEXT_MISSING"),
        ({"allowed_destinations": ["internal"]}, "internal", "ALLOW", "EXPLICIT_ALLOW"),
    ],
)
def test_data_policy_table(fields, destination, outcome, reason):
    c = contract({"rule_id": "secret", "label": "SECRET", **fields})
    decision = NativePolicyEngine().decide(request(c, destination=destination), compile_contract(c))
    assert decision.outcome == outcome and decision.reason_codes == {ReasonCode(reason)}
    assert decision.matched_rule_ids == {"base", "secret"}


@pytest.mark.parametrize("base", ["DENY", "REQUIRE_APPROVAL", "ALLOW"])
def test_flow_never_grants_and_any_label_can_block(base):
    c = contract(
        {"rule_id": "s", "label": "SECRET", "allowed_destinations": ["external"]},
        {"rule_id": "p", "label": "PII", "denied_destinations": ["external"]},
        base=base,
    )
    engine = NativePolicyEngine()
    d = engine.decide(request(c, labels=frozenset({DataLabel.SECRET, DataLabel.PII})), c)
    assert d.outcome == PolicyOutcome.DENY
    assert d.reason_codes == {
        ReasonCode.EXPLICIT_DENY if base == "DENY" else ReasonCode.DATA_FLOW_DENIED
    }
    assert d.matched_rule_ids == ({"base"} if base == "DENY" else {"base", "s", "p"})
    clean = engine.decide(request(c, labels=frozenset()), c)
    assert clean.outcome.value == base
    no_authority = contract(*[r.model_dump(mode="json") for r in c.data.rules], tools={"rules": []})
    assert engine.decide(request(no_authority), no_authority).reason_codes == {
        ReasonCode.DEFAULT_DENY
    }


def test_canonical_policy_action_and_exact_flow_digest():
    c = contract()
    r = request(c)
    other = r.data_artifact_refs[0].model_copy(update={"artifact_id": "a"})
    refs = (r.data_artifact_refs[0], other)
    a = NormalizedAction(
        schema_version="0.1",
        principal=r.principal,
        agent_id=r.agent.agent_id,
        environment=r.environment,
        tool_id="t",
        capability=r.capability,
        arguments={"x": "private"},
        tool_schema_hash=content_digest({}),
        tool_description_hash=content_digest(""),
        effective_policy_hash=effective_policy_hash(c),
        data_artifact_refs=refs,
        data_destination="external",
    )
    b = NormalizedAction.model_validate_json(a.model_dump_json())
    assert a == b
    reversed_data = a.model_dump(mode="json")
    reversed_data["data_artifact_refs"].reverse()
    assert action_digest(a) == action_digest(
        NormalizedAction.model_validate_json(json.dumps(reversed_data))
    )
    for change in (
        {"data_artifact_refs": ()},
        {"data_destination": "internal"},
        {"data_artifact_refs": (other.model_copy(update={"labels": frozenset()}),)},
    ):
        assert action_digest(a) != action_digest(a.model_copy(update=change))
    for model, data in (
        (PolicyRequest, r.model_dump(mode="json")),
        (NormalizedAction, a.model_dump(mode="json")),
    ):
        data["data_artifact_refs"] = [refs[0].model_dump(mode="json")] * 2
        with pytest.raises(ValidationError, match="DUPLICATE_ARTIFACT_ID"):
            model.model_validate_json(json.dumps(data))


def test_independent_flow_generation_nonvacuity_and_mutant(monkeypatch):
    c = contract(
        {"rule_id": "s", "label": "SECRET", "denied_destinations": ["external"]},
        {"rule_id": "u", "label": "UNTRUSTED_CONTENT", "denied_capabilities": ["web.search"]},
    )
    plan = compile_contract(c)
    assert plan.compiler_version == "phase6-v1" and not plan.gaps
    original = NativePolicyEngine.decide
    monkeypatch.setattr(
        NativePolicyEngine, "decide", lambda *args: (_ for _ in ()).throw(AssertionError())
    )
    probes = generate_probes(plan)
    assert any(p.obligation_kind == "any_deny_wins" for p in probes)
    assert any(p.obligation_kind == "missing_destination" for p in probes)
    monkeypatch.setattr(NativePolicyEngine, "decide", original)
    assert all(r.status in {"PASS", "NOT_RUN"} for r in run_conformance(plan).probes)
    assert all(r.status in {"PASS", "NOT_RUN"} for r in run_contract_cases(c, plan))

    class Broken:
        def decide(self, req, plan):
            return NativePolicyEngine().decide(
                req.model_copy(update={"data_artifact_refs": ()}), plan
            )

    assert any(r.status == "FAIL" for r in run_conformance(plan, Broken()).probes)
    assert any(r.status == "FAIL" for r in run_contract_cases(c, plan, Broken()))
    denied = compile_contract(
        contract(
            {"rule_id": "s", "label": "SECRET", "denied_capabilities": ["web.search"]}, base="DENY"
        )
    )
    rows = [r for r in run_conformance(denied).probes if r.probe_id.startswith("flow-")]
    assert rows and all(r.status == "NOT_RUN" for r in rows)
    coverage = coverage_report(denied, run_conformance(denied))
    atom = next(a for a in coverage.atoms if a.atom_id == "data.rules/s")
    assert atom.probe_status == "NOT_RUN" and atom.adapter_status == "UNPROVEN"
    assert atom.provenance_input_required and atom.source_classification_required
    assert atom.adapter_boundary


def test_finite_data_diff_tightening_relaxation_and_explanation():
    old = compile_contract(contract())
    new = compile_contract(
        contract(
            {
                "rule_id": "s",
                "label": "SECRET",
                "allowed_destinations": ["flow-other"],
                "denied_capabilities": ["flow.other"],
            }
        )
    )
    assert old.effective_policy_hash != new.effective_policy_hash
    diff = semantic_diff(old, new)
    kinds = {c.kind for c in diff.changes}
    assert "data_policy_tightening" in kinds and "unsupported_change" not in kinds
    assert not kinds & {"authority_reduction", "authority_expansion"}
    assert "data_policy_relaxation" in {c.kind for c in semantic_diff(new, old).changes}
    renamed = compile_contract(
        contract(
            {
                "rule_id": "renamed",
                "label": "SECRET",
                "allowed_destinations": ["flow-other"],
                "denied_capabilities": ["flow.other"],
            }
        )
    )
    assert {c.kind for c in semantic_diff(new, renamed).changes} == {
        "data_policy_explanation_change"
    }


class Broker:
    async def decide(self, request, presentation):
        raise AssertionError("unexpected approval")


def runtime(mode=EnforcementMode.ENFORCE, sink=None):
    sink = sink or InMemoryEventSink()
    r = RuntimeGateway(
        contract(),
        mode,
        RuntimeEvents(sink, lambda: NOW, required=mode == EnforcementMode.ENFORCE),
        Broker(),
    )
    return r, sink


def tool():
    from agentsec.domain.taxonomy import SideEffectClass

    return ToolDescriptor(
        schema_version="0.1",
        tool_id="t",
        namespace="test",
        name="test",
        protocol="test",
        description="test",
        input_schema={"type": "object"},
        side_effect_class=SideEffectClass.READ,
        capabilities=frozenset({"web.search"}),
    )


def test_runtime_concurrent_causality_and_policy_input_digest():
    async def scenario():
        r, sink = runtime()
        arrived = asyncio.Event()
        release = asyncio.Event()

        async def slow(args):
            arrived.set()
            await release.wait()
            return ToolResponse(body={"opaque": "not persisted"}, success=True)

        async def fast(args):
            return ToolResponse(body={}, success=True)

        pending = asyncio.create_task(r.call(tool(), {}, None, slow, bound=True))
        await arrived.wait()
        await r.call(
            tool(), {}, None, fast, bound=True, output_data_labels=frozenset({DataLabel.SECRET})
        )
        release.set()
        await pending
        assert len(r.provenance.snapshot()) == 2
        await r.call(tool(), {}, None, fast, bound=True)
        requested = [e.payload for e in sink.events if e.event_type == EventType.TOOL_REQUESTED]
        assert (
            not requested[0].request.data_artifact_refs
            and not requested[1].request.data_artifact_refs
        )
        assert len(requested[2].request.data_artifact_refs) == 2
        assert requested[2].policy_input_digest == content_digest(requested[2].request)
        returned = [e.payload for e in sink.events if isinstance(e.payload, ToolReturnedPayload)]
        assert not returned[0].artifacts[0].parent_artifact_ids
        assert not returned[1].artifacts[0].parent_artifact_ids
        assert DataLabel.SECRET in returned[2].artifacts[0].labels
        assert len(r.provenance.snapshot()) == 1
        assert "not persisted" not in str(sink.events)

    asyncio.run(scenario())


def test_critical_exposure_evidence_failure_poison_and_no_release():
    class FailingSink(InMemoryEventSink):
        def append(self, event):
            if isinstance(event.payload, DataExposedPayload):
                raise OSError("disk")
            super().append(event)

    async def scenario():
        r, sink = runtime(sink=FailingSink())
        calls = []

        async def dispatch(args):
            calls.append(args)
            return ToolResponse(body={}, success=True)

        with pytest.raises(RuntimeFailure, match="EVIDENCE_WRITE_FAILURE"):
            await r.call(tool(), {}, None, dispatch, bound=True)
        assert not r.provenance.snapshot()
        with pytest.raises(RuntimeFailure, match="EVIDENCE_WRITE_FAILURE"):
            await r.call(tool(), {}, None, dispatch, bound=True)
        assert len(calls) == 1
        assert any(isinstance(e.payload, ToolReturnedPayload) for e in sink.events)

    asyncio.run(scenario())


def test_explicit_flow_deny_wins_over_missing_context_independent_of_order():
    rules = [
        {"rule_id": "s", "label": "SECRET", "denied_destinations": ["external"]},
        {"rule_id": "u", "label": "UNTRUSTED_CONTENT", "denied_capabilities": ["web.search"]},
    ]
    for ordered in (rules, list(reversed(rules))):
        c = contract(*ordered)
        d = NativePolicyEngine().decide(
            request(
                c,
                labels=frozenset({DataLabel.SECRET, DataLabel.UNTRUSTED_CONTENT}),
                destination=None,
            ),
            c,
        )
        assert d.reason_codes == {ReasonCode.DATA_FLOW_DENIED}
        assert d.matched_rule_ids == {"base", "s", "u"}


def test_dispatch_exception_creates_no_artifact_or_exposure():
    async def scenario():
        r, sink = runtime()

        async def dispatch(args):
            raise OSError("transport")

        with pytest.raises(RuntimeFailure, match="UPSTREAM_FAILURE"):
            await r.call(tool(), {}, None, dispatch, bound=True)
        assert not r.provenance.snapshot()
        returned = [e.payload for e in sink.events if isinstance(e.payload, ToolReturnedPayload)]
        assert not returned
        assert not any(isinstance(e.payload, DataExposedPayload) for e in sink.events)

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", [EnforcementMode.SHADOW, EnforcementMode.DISABLED])
def test_unprotected_modes_still_track_released_responses(mode):
    async def scenario():
        r, sink = runtime(mode)

        async def dispatch(args):
            return ToolResponse(body={}, success=True)

        await r.call(tool(), {}, None, dispatch, bound=True)
        assert r.provenance.snapshot()
        assert any(isinstance(e.payload, DataExposedPayload) for e in sink.events)
        decisions = [e for e in sink.events if e.event_type == EventType.POLICY_EVALUATED]
        assert bool(decisions) == (mode != EnforcementMode.DISABLED)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "corruption", [None, "before_return", "wrong_artifact", "wrong_request", "duplicate"]
)
def test_exposure_trajectory_requires_exact_prior_return(corruption):
    from agentsec.eval.contract_cases import ContractTarget, case_scenario
    from agentsec.eval.ports import EvaluationContext
    from agentsec.eval.trajectory import EvaluationError, validate_evaluation_trajectory

    c = contract()
    plan = compile_contract(c)
    probe = next(p for p in generate_probes(plan) if p.expected == PolicyOutcome.ALLOW)
    context = EvaluationContext(run_id="run", trace_id="trace")
    observation = ContractTarget(plan, probe).run(
        contract=c, scenario=case_scenario(plan, probe), context=context
    )
    events = list(observation.events)
    index = next(i for i, e in enumerate(events) if isinstance(e.payload, ToolReturnedPayload))
    returned = events[index].payload
    artifact = DataArtifactRef(
        schema_version="0.1",
        artifact_id="trajectory-source",
        labels=frozenset({DataLabel.TOOL_OUTPUT}),
        origin=DataOrigin(origin_type="synthetic", trust_class=TrustClass.TOOL_OUTPUT),
        created_at=NOW,
    )
    events[index] = events[index].model_copy(
        update={"payload": returned.model_copy(update={"artifacts": (artifact,)})}
    )
    exposed = DataExposedPayload(
        kind=EventType.DATA_EXPOSED,
        dispatch_id=returned.dispatch_id,
        request_id=returned.request_id,
        tool_id=returned.tool_id,
        artifact=artifact,
    )
    if corruption == "wrong_artifact":
        exposed = exposed.model_copy(
            update={"artifact": artifact.model_copy(update={"artifact_id": "forged"})}
        )
    if corruption == "wrong_request":
        exposed = exposed.model_copy(update={"request_id": "forged"})
    event = events[index].model_copy(
        update={"event_id": "exposure", "event_type": EventType.DATA_EXPOSED, "payload": exposed}
    )
    events.insert(index if corruption == "before_return" else index + 1, event)
    if corruption == "duplicate":
        events.insert(index + 2, event.model_copy(update={"event_id": "duplicate"}))
    events = tuple(e.model_copy(update={"sequence": i}) for i, e in enumerate(events))
    observation = observation.model_copy(update={"events": events})
    if corruption:
        with pytest.raises(EvaluationError, match="INVALID_TRAJECTORY"):
            validate_evaluation_trajectory(observation)
    else:
        validate_evaluation_trajectory(observation)


def test_flow_eval_case_proves_return_exposure_then_sink_snapshot():
    from agentsec.domain.events import DataExposedPayload, ToolRequestedPayload
    from agentsec.eval.contract_cases import ContractTarget, case_scenario
    from agentsec.eval.ports import EvaluationContext
    from agentsec.eval.trajectory import EvaluationError, validate_evaluation_trajectory

    c = contract({"rule_id": "flow", "label": "SECRET", "denied_destinations": ["external"]})
    plan = compile_contract(c)
    probe = next(
        p
        for p in generate_probes(plan)
        if p.obligation_kind == "denied_destination" and p.expected == PolicyOutcome.DENY
    )
    context = EvaluationContext(run_id="flow-run", trace_id="flow-trace")
    observation = ContractTarget(plan, probe).run(
        contract=c, scenario=case_scenario(plan, probe), context=context
    )
    requests = [
        e.payload for e in observation.events if isinstance(e.payload, ToolRequestedPayload)
    ]
    assert len(requests) == 2
    assert not requests[0].request.data_artifact_refs
    assert len(requests[1].request.data_artifact_refs) == 1
    assert any(isinstance(e.payload, DataExposedPayload) for e in observation.events)
    validate_evaluation_trajectory(observation)

    events = list(observation.events)
    sink_event_index = next(
        i
        for i, event in enumerate(events)
        if isinstance(event.payload, ToolRequestedPayload)
        and event.payload.request.request_id == requests[1].request.request_id
    )
    sink_payload = events[sink_event_index].payload
    forged_request = sink_payload.request.model_copy(update={"data_artifact_refs": ()})
    events[sink_event_index] = events[sink_event_index].model_copy(
        update={"payload": sink_payload.model_copy(update={"request": forged_request})}
    )
    corrupted = observation.model_copy(update={"events": tuple(events)})
    with pytest.raises(EvaluationError, match="INVALID_TRAJECTORY"):
        validate_evaluation_trajectory(corrupted)

    events = list(observation.events)
    first_request_index = next(
        i for i, event in enumerate(events) if isinstance(event.payload, ToolRequestedPayload)
    )
    first_request_event = events[first_request_index]
    first_request_payload = first_request_event.payload
    fabricated = synthetic_artifacts(frozenset({DataLabel.SECRET}))
    fake_request = first_request_payload.request.model_copy(
        update={"data_artifact_refs": fabricated}
    )
    events[first_request_index] = first_request_event.model_copy(
        update={"payload": first_request_payload.model_copy(update={"request": fake_request})}
    )
    corrupted = observation.model_copy(update={"events": tuple(events)})
    with pytest.raises(EvaluationError, match="INVALID_TRAJECTORY"):
        validate_evaluation_trajectory(corrupted)


def test_trajectory_rejects_mismatched_return_lineage_and_dropped_labels():
    from agentsec.eval.contract_cases import ContractTarget, case_scenario
    from agentsec.eval.ports import EvaluationContext
    from agentsec.eval.trajectory import EvaluationError, validate_evaluation_trajectory

    c = contract({"rule_id": "flow", "label": "SECRET", "denied_destinations": ["external"]})
    plan = compile_contract(c)
    probe = next(
        p
        for p in generate_probes(plan)
        if p.obligation_kind == "preserve" and p.expected == PolicyOutcome.ALLOW
    )
    observation = ContractTarget(plan, probe).run(
        contract=c,
        scenario=case_scenario(plan, probe),
        context=EvaluationContext(run_id="lineage-run", trace_id="lineage-trace"),
    )
    events = list(observation.events)
    returned_index = next(
        i for i, event in enumerate(events) if isinstance(event.payload, ToolReturnedPayload)
    )
    returned_event = events[returned_index]
    returned = returned_event.payload
    malformed = returned.artifacts[0].model_copy(
        update={"parent_artifact_ids": frozenset({"never-exposed"})}
    )
    events[returned_index] = returned_event.model_copy(
        update={"payload": returned.model_copy(update={"artifacts": (malformed,)})}
    )
    with pytest.raises(EvaluationError, match="INVALID_TRAJECTORY"):
        validate_evaluation_trajectory(observation.model_copy(update={"events": tuple(events)}))


def test_trajectory_frontier_siblings_and_label_monotonicity():
    from agentsec.domain.events import (
        DataExposedPayload,
        PolicyEvaluatedPayload,
        ToolDispatchedPayload,
        ToolRequestedPayload,
    )
    from agentsec.eval.contract_cases import ContractTarget, case_scenario
    from agentsec.eval.ports import EvaluationContext
    from agentsec.eval.trajectory import EvaluationError, validate_evaluation_trajectory

    c = contract({"rule_id": "flow", "label": "SECRET", "denied_destinations": ["external"]})
    plan = compile_contract(c)
    probe = next(
        p
        for p in generate_probes(plan)
        if p.obligation_kind == "preserve" and p.expected == PolicyOutcome.ALLOW
    )
    observation = ContractTarget(plan, probe).run(
        contract=c,
        scenario=case_scenario(plan, probe),
        context=EvaluationContext(run_id="siblings-run", trace_id="siblings-trace"),
    )
    events = list(observation.events)
    root = next(
        event.payload.artifacts[0]
        for event in events
        if isinstance(event.payload, ToolReturnedPayload) and event.payload.artifacts
    )
    sink_request_index = next(
        i
        for i, event in enumerate(events)
        if isinstance(event.payload, ToolRequestedPayload)
        and event.payload.request.tool_id == "conformance-tool"
    )
    sink_request_event = events[sink_request_index]
    original_request = sink_request_event.payload
    original_decision = next(
        event.payload
        for event in events[sink_request_index + 1 :]
        if isinstance(event.payload, PolicyEvaluatedPayload)
    )
    original_dispatch = next(
        event.payload
        for event in events[sink_request_index + 1 :]
        if isinstance(event.payload, ToolDispatchedPayload)
    )
    original_return = next(
        event.payload
        for event in events[sink_request_index + 1 :]
        if isinstance(event.payload, ToolReturnedPayload)
    )
    branch_events = []
    branch_returns = []
    children = []
    for suffix in ("branch-a", "branch-b"):
        request_id = f"{suffix}-request"
        decision_id = f"{suffix}-decision"
        dispatch_id = f"{suffix}-dispatch"
        digest = content_digest((original_request.action_digest, suffix))
        request = original_request.request.model_copy(
            update={"request_id": request_id, "data_artifact_refs": (root,)}
        )
        requested = original_request.model_copy(
            update={"request": request, "action_digest": digest}
        )
        decision = original_decision.decision.model_copy(
            update={"request_id": request_id, "decision_id": decision_id}
        )
        evaluated = original_decision.model_copy(update={"decision": decision})
        dispatch = original_dispatch.model_copy(
            update={
                "request_id": request_id,
                "decision_id": decision_id,
                "dispatch_id": dispatch_id,
                "action_digest": digest,
            }
        )
        child = DataArtifactRef(
            schema_version="0.1",
            artifact_id=f"{suffix}-artifact",
            labels=root.labels,
            origin=root.origin,
            parent_artifact_ids=frozenset({root.artifact_id}),
            created_at=NOW,
        )
        returned = original_return.model_copy(
            update={
                "request_id": request_id,
                "dispatch_id": dispatch_id,
                "artifacts": (child,),
            }
        )
        exposed = DataExposedPayload(
            kind=EventType.DATA_EXPOSED,
            request_id=request_id,
            dispatch_id=dispatch_id,
            tool_id=dispatch.tool_id,
            artifact=child,
        )
        children.append(child)
        branch_events.extend(
            [
                (f"{suffix}-request-event", requested),
                (f"{suffix}-decision-event", evaluated),
                (f"{suffix}-dispatch-event", dispatch),
            ]
        )
        branch_returns.extend(
            [
                (f"{suffix}-return-event", returned),
                (f"{suffix}-exposure-event", exposed),
            ]
        )
    branch_events.extend(branch_returns)

    final_request = original_request.request.model_copy(
        update={"data_artifact_refs": tuple(sorted(children, key=lambda ref: ref.artifact_id))}
    )
    events[sink_request_index] = sink_request_event.model_copy(
        update={"payload": original_request.model_copy(update={"request": final_request})}
    )
    prefix = events[:sink_request_index]
    suffix_events = events[sink_request_index:]
    added = [
        observation.events[0].model_copy(
            update={
                "event_id": event_id,
                "sequence": len(prefix) + index,
                "event_type": payload.kind,
                "payload": payload,
            }
        )
        for index, (event_id, payload) in enumerate(branch_events)
    ]
    complete_events = tuple(
        event.model_copy(update={"sequence": i})
        for i, event in enumerate(prefix + added + suffix_events)
    )
    coverage = observation.coverage.model_copy(update={"tool_arguments_complete": False})
    validate_evaluation_trajectory(
        observation.model_copy(update={"events": complete_events, "coverage": coverage})
    )

    # A successful sink response must retain labels from its exposed request snapshot.
    sink_return_index = max(
        i
        for i, event in enumerate(observation.events)
        if isinstance(event.payload, ToolReturnedPayload)
    )
    sink_return_event = observation.events[sink_return_index]
    sink_return = sink_return_event.payload
    exposed = next(
        event.payload.artifact
        for event in observation.events
        if isinstance(event.payload, DataExposedPayload)
    )
    child = DataArtifactRef(
        schema_version="0.1",
        artifact_id="bad-child",
        labels=frozenset({DataLabel.TOOL_OUTPUT}),
        origin=DataOrigin(origin_type="synthetic", trust_class=TrustClass.TOOL_OUTPUT),
        parent_artifact_ids=frozenset({exposed.artifact_id}),
        created_at=NOW,
    )
    events = list(observation.events)
    events[sink_return_index] = sink_return_event.model_copy(
        update={"payload": sink_return.model_copy(update={"artifacts": (child,)})}
    )
    with pytest.raises(EvaluationError, match="INVALID_TRAJECTORY"):
        validate_evaluation_trajectory(observation.model_copy(update={"events": tuple(events)}))


def test_diff_synthetic_grant_rule_id_cannot_hide_data_explanation():
    old = compile_contract(contract())
    new = compile_contract(contract({"rule_id": "diff-base", "label": "SECRET"}))
    changes = semantic_diff(old, new).changes
    assert "data_policy_explanation_change" in {c.kind for c in changes}
    assert all(
        c.old_outcome == c.new_outcome
        for c in changes
        if c.kind == "data_policy_explanation_change"
    )


def test_authored_data_diff_paths_use_rule_ids():
    before = compile_contract(
        contract(
            {
                "rule_id": "secret-egress",
                "label": "SECRET",
                "denied_destinations": ["external"],
            }
        )
    )
    after = compile_contract(
        contract(
            {
                "rule_id": "secret-egress",
                "label": "SECRET",
                "denied_destinations": ["external", "partner"],
            }
        )
    )
    changes = semantic_diff(before, after).changes
    authored = [change for change in changes if change.kind.startswith("data_denied_")]
    assert authored and {change.source_ref for change in authored} == {"data.rules/secret-egress"}
    added = compile_contract(
        contract({"rule_id": "pii-egress", "label": "PII", "denied_destinations": ["external"]})
    )
    additions = semantic_diff(compile_contract(contract()), added).changes
    assert any(
        change.kind == "data_rule_added" and change.source_ref == "data.rules/pii-egress"
        for change in additions
    )
    removals = semantic_diff(added, compile_contract(contract())).changes
    assert any(
        change.kind == "data_rule_removed" and change.source_ref == "data.rules/pii-egress"
        for change in removals
    )
