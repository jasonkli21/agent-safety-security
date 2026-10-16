"""Falsification tests across the offline incident lifecycle and real runtime evidence."""

import asyncio
import json
from datetime import timedelta

import pytest
from pydantic import ValidationError
from test_provenance_flow import contract
from test_runtime_state import NOW, Broker, tool
from typer.testing import CliRunner

from agentsec.cli.main import app
from agentsec.compiler import compile_contract
from agentsec.contracts.loader import load_artifact
from agentsec.domain.events import (
    ApprovalRequestedPayload,
    DataExposedPayload,
    PolicyEvaluatedPayload,
    ToolDispatchedPayload,
    ToolRequestedPayload,
    ToolReturnedPayload,
)
from agentsec.domain.replay import (
    Fidelity,
    RegressionState,
    ReplayBundle,
    ReplayError,
    SourceBinding,
)
from agentsec.domain.scenarios import MaxToolCalls, ToolNotCalled
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.domain.taxonomy import (
    ApprovalOutcome,
    DataLabel,
    EnforcementMode,
    EventType,
    SecurityCategory,
)
from agentsec.evidence.jsonl import JsonlEventSink
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.incident.classify import classify
from agentsec.incident.promote import promote
from agentsec.regression.runner import run_case, validate_case
from agentsec.replay.bundle import create_bundle, validate_bundle, validate_program
from agentsec.replay.engine import replay
from agentsec.replay.projection import project, semantic_diff
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure, ToolResponse


def source(c=None, *, count=1, broker=None, labels=frozenset(), transport=False, withheld=False):
    c = c or contract()
    sink = InMemoryEventSink()
    gateway = RuntimeGateway(
        c, EnforcementMode.ENFORCE, RuntimeEvents(sink, lambda: NOW), broker or Broker()
    )

    async def response(_):
        if transport:
            raise RuntimeError("synthetic transport failure")
        return ToolResponse(body={"content": []}, success=True)

    descriptor = tool()
    if withheld:
        descriptor = descriptor.model_copy(update={"output_schema": {"type": "string"}})

    async def run():
        for _ in range(count):
            try:
                await gateway.call(
                    descriptor,
                    {},
                    None,
                    response,
                    bound=True,
                    output_data_labels=labels,
                    data_destination="external",
                )
            except RuntimeFailure:
                pass
        gateway.finish()

    asyncio.run(run())
    return c, tuple(sink.events), descriptor


def bundle(c=None, **kwargs):
    c, events, descriptor = source(c, **kwargs)
    return create_bundle(events, c, tools=(descriptor,))


def test_exact_identity_and_stable_offline_replay(monkeypatch):
    b = bundle()
    assert b.assessment.source_binding == SourceBinding.EXACT
    assert b.assessment.fidelity == Fidelity.SECURITY_RUNTIME
    # A real gateway produces the source; replay must never instantiate one or import MCP.
    monkeypatch.setattr(RuntimeGateway, "__init__", lambda *a, **k: pytest.fail("live gateway"))
    result = replay(b)
    assert result == replay(b)
    assert result.diff.status == "UNCHANGED"
    assert result.external_effects_performed is False
    assert len(result.substituted_dispatch_ids) == 1
    assert result.events[0].run_id != b.source_run_id
    assert result.events[0].event_id != b.program.events[0].event_id
    assert validate_bundle(b) == b


@pytest.mark.parametrize("field", ["bundle_digest", "source_evidence_digest", "program"])
def test_tamper_rejected(field):
    data = json.loads(bundle().model_dump_json(round_trip=True))
    if field == "program":
        data[field]["events"][1]["payload"]["request"]["capability"] = "email.send"
    else:
        data[field] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError):
        ReplayBundle.model_validate_json(json.dumps(data))


def test_recomputed_digest_cannot_hide_forged_identity_or_assessment():
    b = bundle()
    for patch in (
        {"source_run_id": "other"},
        {
            "assessment": b.assessment.model_copy(
                update={"source_binding": SourceBinding.LEGACY_INFERRED}
            )
        },
        {"source_plan": compile_contract(contract(base="DENY"))},
    ):
        changed = b.model_copy(update=patch)
        changed = changed.model_copy(
            update={
                "bundle_digest": content_digest(
                    changed.model_dump(exclude={"bundle_digest"}, round_trip=True)
                )
            }
        )
        with pytest.raises(ReplayError, match="BUNDLE_BINDING_MISMATCH"):
            validate_bundle(changed)


@pytest.mark.parametrize("mutation", ["mixed", "order", "duplicate", "hash", "plan", "input"])
def test_bad_source_rejected(mutation):
    c, events, t = source()
    events = list(events)
    if mutation == "mixed":
        events[1] = events[1].model_copy(update={"run_id": "other-run"})
    elif mutation == "order":
        events[1], events[2] = events[2], events[1]
    elif mutation == "duplicate":
        events[1] = events[1].model_copy(update={"event_id": events[0].event_id})
    elif mutation in {"hash", "plan"}:
        p = events[0].payload
        patch = (
            {"effective_policy_hash": "sha256:" + "0" * 64}
            if mutation == "hash"
            else {"plan_identity": compile_contract(contract(base="DENY")).identity}
        )
        events[0] = events[0].model_copy(update={"payload": p.model_copy(update=patch)})
    else:
        events[1] = events[1].model_copy(
            update={
                "payload": events[1].payload.model_copy(
                    update={"policy_input_digest": "sha256:" + "0" * 64}
                )
            }
        )
    with pytest.raises(ReplayError):
        create_bundle(tuple(events), c, tools=(t,))


def test_legacy_binding_and_incomplete_prefix():
    c, events, t = source()
    start = events[0].payload.model_copy(update={"plan_identity": None})
    legacy = (events[0].model_copy(update={"payload": start}), *events[1:])
    b = create_bundle(legacy, c, tools=(t,))
    assert b.assessment.source_binding == SourceBinding.LEGACY_INFERRED
    assert "LEGACY_SOURCE_PLAN" in b.assessment.limitations
    assert replay(b).diff.status == "UNCHANGED"
    prefix = create_bundle(legacy[:-1], c, tools=(t,))
    assert replay(prefix).diff.status == "INCOMPLETE"


def test_material_redaction_never_guessed():
    c, events, t = source()
    p = events[1].payload
    p = p.model_copy(
        update={
            "redacted_fields": frozenset({"resource"}),
            "resource_digest": content_digest("secret-resource"),
        }
    )
    redacted = (events[0], events[1].model_copy(update={"payload": p}), *events[2:])
    b = create_bundle(redacted, c, tools=(t,))
    assert b.assessment.blockers == {"MATERIAL_REDACTION"}
    r = replay(b)
    assert r.events == () and r.diff.status == "INCOMPLETE"


@pytest.mark.parametrize("before,after", [("ALLOW", "DENY"), ("DENY", "ALLOW")])
def test_candidate_authority_changes(before, after):
    b = bundle(contract(base=before))
    r = replay(b, contract(base=after))
    decisions = [
        e.payload.decision for e in r.events if isinstance(e.payload, PolicyEvaluatedPayload)
    ]
    assert decisions[0].outcome.value == after
    assert r.diff.differences
    if after == "DENY":
        assert r.substituted_dispatch_ids == ()
    else:
        assert "MISSING_SUBSTITUTE_RESULT" in r.assessment.limitations
        assert r.diff.status == "INCOMPLETE"


@pytest.mark.parametrize("outcome", [ApprovalOutcome.APPROVE, ApprovalOutcome.DENY])
def test_approval_script_and_changed_policy_binding(outcome):
    class DecisionBroker(Broker):
        async def decide(self, request, presentation):
            d = await super().decide(request, presentation)
            return d.model_copy(update={"outcome": outcome})

    b = bundle(contract(base="REQUIRE_APPROVAL"), broker=DecisionBroker())
    r = replay(b)
    assert not r.diff.differences
    assert len(r.substituted_dispatch_ids) == int(outcome == ApprovalOutcome.APPROVE)
    changed = contract(base="REQUIRE_APPROVAL", budgets={"max_tool_calls": 2})
    r = replay(b, changed)
    assert "APPROVAL_BINDING_UNAVAILABLE" in r.assessment.blockers
    assert not r.substituted_dispatch_ids


def test_approval_forged_action_rejected_before_replay():
    c, events, t = source(contract(base="REQUIRE_APPROVAL"))
    altered = tuple(
        e.model_copy(
            update={
                "payload": e.payload.model_copy(
                    update={
                        "approval": e.payload.approval.model_copy(
                            update={"action_digest": "sha256:" + "0" * 64}
                        )
                    }
                )
            }
        )
        if isinstance(e.payload, ApprovalRequestedPayload)
        else e
        for e in events
    )
    with pytest.raises(ReplayError, match="INVALID_TRAJECTORY"):
        create_bundle(altered, c, tools=(t,))


def test_budgets_persist_and_runtime_duration_is_not_invented():
    b = bundle(count=3)
    r = replay(b, contract(budgets={"max_tool_calls": 1}))
    assert len(r.substituted_dispatch_ids) == 1
    assert any(e.event_type == EventType.SECURITY_SIGNAL for e in r.events)
    r = replay(b, contract(budgets={"max_runtime_seconds": 10}))
    assert r.events == () and "MISSING_MONOTONIC_DURATION" in r.assessment.blockers


def test_returned_withheld_and_transport_do_not_expose():
    for options in ({"withheld": True}, {"transport": True}):
        b = bundle(**options)
        r = replay(b)
        assert not any(isinstance(e.payload, DataExposedPayload) for e in r.events)
        assert sum(isinstance(e.payload, ToolReturnedPayload) for e in r.events) == int(
            not options.get("transport")
        )
        assert len(r.substituted_dispatch_ids) == 1


def test_provenance_inheritance_and_flow_denial():
    c = contract({"rule_id": "secret", "label": "SECRET", "denied_destinations": ["external"]})
    b = bundle(c, count=2, labels=frozenset({DataLabel.SECRET}))
    r = replay(b)
    requests = [e.payload.request for e in r.events if isinstance(e.payload, ToolRequestedPayload)]
    assert not requests[0].data_artifact_refs
    assert DataLabel.SECRET in requests[1].data_artifact_refs[0].labels
    assert len(r.substituted_dispatch_ids) == 1
    validate_program(b.program.model_copy(update={"events": r.events}))


def test_concurrent_source_ordering_preserved():
    c = contract()
    sink = InMemoryEventSink()
    gateway = RuntimeGateway(c, EnforcementMode.ENFORCE, RuntimeEvents(sink, lambda: NOW), Broker())

    async def run():
        waiting = asyncio.Event()
        release = asyncio.Event()

        async def first(_):
            waiting.set()
            await release.wait()
            return ToolResponse(body={"content": []}, success=True)

        async def second(_):
            release.set()
            return ToolResponse(body={"content": []}, success=True)

        a = asyncio.create_task(gateway.call(tool(), {}, None, first, bound=True))
        await waiting.wait()
        await gateway.call(tool(), {}, None, second, bound=True)
        await a
        await gateway.call(tool(), {}, None, second, bound=True)
        gateway.finish()

    asyncio.run(run())
    b = create_bundle(tuple(sink.events), c, tools=(tool(),))
    r = replay(b)
    assert r.diff.status == "UNCHANGED"
    reqs = [e.payload.request for e in r.events if isinstance(e.payload, ToolRequestedPayload)]
    assert not reqs[0].data_artifact_refs and not reqs[1].data_artifact_refs
    assert len(reqs[2].data_artifact_refs) == 2


def test_semantic_projection_volatility_and_meaningful_changes():
    b = bundle()
    shifted = tuple(
        e.model_copy(
            update={
                "event_id": "new-" + e.event_id,
                "run_id": "new-run",
                "trace_id": "new-trace",
                "occurred_at": NOW + timedelta(days=1),
            }
        )
        for e in b.program.events
    )
    assert project(shifted) == project(b.program.events)
    for cls in (ToolDispatchedPayload, ToolReturnedPayload, DataExposedPayload):
        removed = tuple(e for e in shifted if not isinstance(e.payload, cls))
        assert semantic_diff(b.program.events, removed).differences
    changed = tuple(
        e.model_copy(
            update={
                "payload": e.payload.model_copy(
                    update={
                        "decision": e.payload.decision.model_copy(
                            update={"matched_rule_ids": frozenset({"other"})}
                        )
                    }
                )
            }
        )
        if isinstance(e.payload, PolicyEvaluatedPayload)
        else e
        for e in shifted
    )
    assert semantic_diff(b.program.events, changed).differences
    assert semantic_diff((), (), limitations=frozenset({"MISSING"})).status == "INCOMPLETE"


def test_classification_ambiguity_and_operator_basis():
    b = bundle(
        contract({"rule_id": "s", "label": "SECRET", "denied_destinations": ["external"]}),
        count=2,
        labels=frozenset({DataLabel.SECRET}),
    )
    i = classify(b, SecurityCategory.SECRET_EXFILTRATION)
    assert i == classify(b, SecurityCategory.SECRET_EXFILTRATION)
    assert i.categories == {SecurityCategory.POLICY_BYPASS, SecurityCategory.SECRET_EXFILTRATION}
    assert any(basis.rule == "OPERATOR_SUPPLIED" for basis in i.classification_basis)
    assert all(
        basis.event_refs for basis in i.classification_basis if basis.rule != "OPERATOR_SUPPLIED"
    )


def test_promotion_safe_active_draft_stability_and_no_secret_copy():
    c, events, t = source()
    original = canonical_json(c)
    p = events[1].payload
    secret = "CANARY-DO-NOT-EXPORT-123"
    r = p.request.model_copy(update={"arguments_summary": {"value": secret}})
    changed = (
        events[0],
        events[1].model_copy(
            update={
                "payload": p.model_copy(
                    update={"request": r, "policy_input_digest": content_digest(r)}
                )
            }
        ),
        *events[2:],
    )
    b = create_bundle(
        changed, c, tools=(t,), expectations=(MaxToolCalls(type="MAX_TOOL_CALLS", maximum=1),)
    )
    i = classify(b)
    case = promote(b, i)
    assert case == promote(b, i) and case.state == RegressionState.ACTIVE
    assert secret not in canonical_json(case)
    assert run_case(case) == "PASS"
    assert canonical_json(c) == original
    plain = bundle()
    draft = promote(plain, classify(plain))
    assert draft.state == RegressionState.DRAFT and run_case(draft) == "DRAFT"
    with pytest.raises(ReplayError, match="INCIDENT_BINDING_MISMATCH"):
        promote(b, i.model_copy(update={"categories": frozenset({SecurityCategory.POLICY_BYPASS})}))


def test_full_chain_regression_fails_before_fix_and_passes_after(tmp_path):
    c, events, t = source()
    b = create_bundle(
        events,
        c,
        tools=(t,),
        expectations=(ToolNotCalled(type="TOOL_NOT_CALLED", tool_id=t.tool_id),),
    )
    i = classify(b, SecurityCategory.UNAUTHORIZED_TOOL_USE)
    assert replay(b).assertions[0].status.value == "FAIL"
    case = promote(b, i)
    validate_case(case)
    assert run_case(case) == "FAIL"
    assert run_case(case, compile_contract(contract(base="DENY"))) == "PASS"
    assert replay(b, contract(base="DENY")).diff.status == "CHANGED"
    runner = CliRunner()
    evidence = tmp_path / "source.jsonl"
    with JsonlEventSink(evidence) as sink:
        for e in events:
            sink.append(e)
    cp = tmp_path / "contract.json"
    cp.write_text(canonical_json(c))
    bp = tmp_path / "bundle.json"
    # API-built bundle includes the reviewed expectations and tool descriptors.
    bp.write_text(canonical_json(b))
    ip = tmp_path / "incident.json"
    assert (
        runner.invoke(
            app, ["incident", "classify", "--bundle", str(bp), "--out", str(ip)]
        ).exit_code
        == 0
    )
    root = tmp_path / "regressions"
    root.mkdir()
    rp = root / "case.json"
    assert (
        runner.invoke(
            app,
            ["incident", "promote", "--bundle", str(bp), "--incident", str(ip), "--out", str(rp)],
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["regression", "run", "--root", str(root)]).exit_code == 1
    cp.write_text(canonical_json(contract(base="DENY")))
    assert (
        runner.invoke(
            app, ["regression", "run", "--root", str(root), "--contract", str(cp)]
        ).exit_code
        == 0
    )
    assert load_artifact(bp, ReplayBundle) == b
    collision = runner.invoke(app, ["incident", "classify", "--bundle", str(bp), "--out", str(ip)])
    assert collision.exit_code == 4
    assert "OUTPUT_COLLISION" in collision.output


@pytest.mark.parametrize("bad", [{"schema_version": "9"}, {"extra": "secret"}])
def test_strict_bundle_fields(bad):
    data = json.loads(bundle().model_dump_json(round_trip=True))
    data.update(bad)
    with pytest.raises(ValidationError):
        ReplayBundle.model_validate_json(json.dumps(data))


def test_retry_attempts_each_charge_budget():
    c, events, t = source()
    # Two no-response attempts of one request; transport failure does not refund a dispatch.
    start, request, decision, dispatch = events[:4]
    assert isinstance(dispatch.payload, ToolDispatchedPayload)
    retry = dispatch.model_copy(
        update={
            "event_id": "retry-event",
            "sequence": 4,
            "payload": dispatch.payload.model_copy(update={"dispatch_id": "retry-dispatch"}),
        }
    )
    terminal = events[-1].model_copy(update={"sequence": 5})
    b = create_bundle((start, request, decision, dispatch, retry, terminal), c, tools=(t,))
    assert len(replay(b).substituted_dispatch_ids) == 2
    assert len(replay(b, contract(budgets={"max_tool_calls": 1})).substituted_dispatch_ids) == 1


def test_canonical_findings_and_assertion_failure_classification():
    from agentsec.domain.findings import Finding
    from agentsec.domain.taxonomy import Severity

    c, events, t = source()
    secret = "SOURCE-FINDING-SECRET"
    finding = Finding(
        schema_version="0.1",
        finding_id="f",
        category=SecurityCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title=secret,
        description=secret,
        run_id=events[0].run_id,
        event_refs=frozenset({events[1].event_id}),
    )
    b = create_bundle(
        events,
        c,
        tools=(t,),
        findings=(finding,),
        expectations=(ToolNotCalled(type="TOOL_NOT_CALLED", tool_id=t.tool_id),),
    )
    i = classify(b)
    assert i.categories == {
        SecurityCategory.PROMPT_INJECTION,
        SecurityCategory.UNAUTHORIZED_TOOL_USE,
    }
    assert {basis.rule for basis in i.classification_basis} == {
        "CANONICAL_FINDING",
        "ASSERTION_FAILURE",
    }
    assert secret not in canonical_json(b)
    assert secret not in canonical_json(promote(b, i))
    assert any(d.source and d.source.kind == "FINDING" for d in replay(b).diff.differences)
    with pytest.raises(ReplayError, match="INVALID_OBSERVATION"):
        create_bundle(
            events, c, tools=(t,), findings=(finding.model_copy(update={"run_id": "other"}),)
        )


def test_regression_corpus_drafts_invalid_active_and_cli_privacy(tmp_path):
    from agentsec.regression.runner import load_corpus

    plain = bundle()
    draft = promote(plain, classify(plain))
    path = tmp_path / "draft.json"
    path.write_text(canonical_json(draft))
    runner = CliRunner()
    result = runner.invoke(app, ["regression", "run", "--root", str(tmp_path)])
    assert result.exit_code == 3 and "DRAFT" in result.output
    data = json.loads(canonical_json(draft))
    data.update(state="ACTIVE", unexpected_secret="DO-NOT-ECHO")
    path.write_text(json.dumps(data))
    result = runner.invoke(app, ["regression", "run", "--root", str(tmp_path)])
    assert result.exit_code == 4 and "DO-NOT-ECHO" not in result.output
    assert "INVALID_ARTIFACT" in result.output
    path.unlink()
    with pytest.raises(ReplayError, match="REGRESSION_CORPUS_EMPTY"):
        load_corpus(tmp_path)


def test_new_public_artifacts_reject_unknown_fields_and_versions():
    from agentsec.domain.replay import Incident, RegressionCase, ReplayResult, TraceDiff

    b = bundle()
    i = classify(b)
    values = (b, i, replay(b), replay(b).diff, promote(b, i))
    models = (ReplayBundle, Incident, ReplayResult, TraceDiff, RegressionCase)
    for model, value in zip(models, values, strict=True):
        data = json.loads(value.model_dump_json(round_trip=True))
        for patch in ({"schema_version": "2.0"}, {"unexpected": True}):
            with pytest.raises(ValidationError):
                model.model_validate_json(json.dumps(data | patch))


def test_approval_timeout_is_semantic_but_absolute_time_is_not():
    b = bundle(contract(base="REQUIRE_APPROVAL"))
    changed = tuple(
        e.model_copy(
            update={
                "payload": e.payload.model_copy(
                    update={
                        "approval": e.payload.approval.model_copy(
                            update={
                                "expires_at": e.payload.approval.expires_at + timedelta(seconds=1)
                            }
                        )
                    }
                )
            }
        )
        if isinstance(e.payload, ApprovalRequestedPayload)
        else e
        for e in b.program.events
    )
    assert semantic_diff(b.program.events, changed).differences


def test_missing_tool_metadata_and_material_canary_assertions_are_explicit():
    from agentsec.domain.scenarios import OutputNotContainsCanary

    c, events, _ = source()
    b = create_bundle(events, c)
    assert b.assessment.fidelity == Fidelity.POLICY
    assert replay(b).diff.status == "INCOMPLETE"
    b = create_bundle(
        events,
        c,
        expectations=(
            OutputNotContainsCanary(type="OUTPUT_NOT_CONTAINS_CANARY", canary_id="private"),
        ),
    )
    assert "MISSING_RAW_ASSERTION_SURFACES" in b.assessment.blockers
    assert not replay(b).events
    assert promote(b, classify(b)).state == RegressionState.DRAFT


def test_cli_bundle_create_and_run_public_workflow(tmp_path, root):
    runner = CliRunner()
    b = tmp_path / "bundle.json"
    result = runner.invoke(
        app,
        [
            "replay",
            "bundle",
            "create",
            "--evidence",
            str(root / "examples/replay/source.jsonl"),
            "--contract",
            str(root / "examples/replay/source-contract.json"),
            "--scenario",
            str(root / "examples/replay/scenario.json"),
            "--out",
            str(b),
        ],
    )
    assert result.exit_code == 0, result.output
    i = tmp_path / "incident.json"
    assert (
        runner.invoke(app, ["incident", "classify", "--bundle", str(b), "--out", str(i)]).exit_code
        == 0
    )
    regression = tmp_path / "case.json"
    result = runner.invoke(
        app,
        [
            "incident",
            "promote",
            "--bundle",
            str(b),
            "--incident",
            str(i),
            "--contract",
            str(root / "examples/replay/current-contract.json"),
            "--out",
            str(regression),
        ],
    )
    assert result.exit_code == 0, result.output
    from agentsec.domain.replay import RegressionCase

    assert run_case(load_artifact(regression, RegressionCase)) == "PASS"
    replayed = runner.invoke(app, ["replay", "run", "--bundle", str(b)])
    assert replayed.exit_code == 0
    assert json.loads(replayed.stdout)["diff"]["status"] == "UNCHANGED"


def test_changed_causal_context_cannot_reuse_action_commitment():
    from agentsec.contracts.loader import validate_data
    from agentsec.contracts.models import AgentSecurityContract

    c = contract(
        tools={
            "rules": [
                {"rule_id": "source", "capability": "web.search", "decision": "ALLOW"},
                {"rule_id": "sink", "capability": "email.send", "decision": "ALLOW"},
            ]
        }
    )
    sink = InMemoryEventSink()
    gateway = RuntimeGateway(c, EnforcementMode.ENFORCE, RuntimeEvents(sink, lambda: NOW), Broker())
    second_tool = tool().model_copy(
        update={"tool_id": "second", "capabilities": frozenset({"email.send"})}
    )

    async def response(_):
        return ToolResponse(body={"content": []}, success=True)

    async def run():
        await gateway.call(tool(), {}, None, response, bound=True)
        await gateway.call(second_tool, {}, None, response, bound=True)
        gateway.finish()

    asyncio.run(run())
    b = create_bundle(tuple(sink.events), c, tools=(tool(), second_tool))
    data = c.model_dump(mode="json")
    for rule in data["tools"]["rules"]:
        if rule["rule_id"] == "source":
            rule["decision"] = "DENY"
    changed = validate_data(AgentSecurityContract, data)
    result = replay(b, changed)
    assert result.diff.status == "INCOMPLETE"
    assert result.assessment.blockers == {"ACTION_CONTEXT_BINDING_UNAVAILABLE"}
    assert not result.substituted_dispatch_ids


def test_lower_replay_entry_also_refuses_redaction():
    from agentsec.domain.replay import ReplayAssessment
    from agentsec.replay.engine import run_program

    c, events, t = source()
    p = events[1].payload.model_copy(
        update={
            "redacted_fields": frozenset({"resource"}),
            "resource_digest": content_digest("secret"),
        }
    )
    b = create_bundle(
        (events[0], events[1].model_copy(update={"payload": p}), *events[2:]), c, tools=(t,)
    )
    result = run_program(
        b.program,
        b.source_plan,
        b.source_plan,
        source_digest=b.bundle_digest,
        assessment=ReplayAssessment(
            fidelity=Fidelity.SECURITY_RUNTIME, source_binding=SourceBinding.EXACT
        ),
    )
    assert result.assessment.blockers == {"MATERIAL_REDACTION"} and not result.events


def test_replay_input_size_and_duplicate_metadata_rejected(tmp_path):
    from agentsec.contracts.loader import MAX_BYTES
    from agentsec.domain.replay import RegressionCase, ReplayProgram
    from agentsec.evidence.jsonl import EvidenceError, read_jsonl

    c, events, t = source()
    path = tmp_path / "events.jsonl"
    path.write_text(canonical_json(events[0]) + "\n")
    with pytest.raises(EvidenceError, match="SOURCE_EVIDENCE_TOO_LARGE"):
        read_jsonl(path, max_bytes=1)
    with pytest.raises(ValidationError, match="DUPLICATE_TOOL_ID"):
        ReplayProgram(schema_version="0.1", events=events, tools=(t, t))
    with pytest.raises(ReplayError, match="BUNDLE_TOO_LARGE"):
        create_bundle(events, c, tools=(t.model_copy(update={"description": "x" * MAX_BYTES}),))
    with pytest.raises(ValidationError, match="INVALID_ACTIVE_REGRESSION"):
        RegressionCase(
            schema_version="0.1",
            regression_id="r",
            source_incident_id="i",
            source_bundle_digest=content_digest("bundle"),
            source_evidence_digest=content_digest(events),
            state=RegressionState.ACTIVE,
            reason="TEST",
        )
