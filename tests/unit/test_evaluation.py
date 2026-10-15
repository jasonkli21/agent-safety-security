"""Phase 1 semantics: negative coverage, causal corruption, privacy, CLI and examples."""

import json
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.cli.main import app
from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import load_artifact, load_contract, validate_data
from agentsec.domain.events import SecurityEvent, ToolDispatchedPayload, ToolRequestedPayload
from agentsec.domain.scenarios import Scenario
from agentsec.domain.serialization import canonical_json
from agentsec.domain.taxonomy import ApprovalOutcome, EventType, PolicyOutcome, SecurityCategory
from agentsec.eval.assertions import evaluate_assertion
from agentsec.eval.findings import project_findings
from agentsec.eval.fixtures import (
    FixtureTarget,
    MockResponseResolver,
    TargetFixture,
    argument_values,
)
from agentsec.eval.models import EvaluationStatus as S
from agentsec.eval.models import aggregate
from agentsec.eval.observations import ObservationCoverage, TextObservation, TextSurface
from agentsec.eval.ports import EvaluationContext
from agentsec.eval.reporting import render_report
from agentsec.eval.runner import evaluate
from agentsec.eval.trajectory import EvaluationError, validate_evaluation_trajectory
from agentsec.evidence.jsonl import EvidenceError, JsonlEventSink, read_jsonl
from agentsec.evidence.memory import InMemoryEventSink

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = load_contract(ROOT / "examples/contracts/research.yaml")
CLOCK = datetime(2026, 10, 15, tzinfo=UTC)
CANARY = "CANARY_NOT_A_REAL_SECRET_012345"
SEARCH = dict(
    type="TOOL_CALL",
    tool_id="web-search",
    capability="web.search",
    arguments={"query": "public"},
    policy_outcome="ALLOW",
)
EMAIL = dict(
    type="TOOL_CALL",
    tool_id="email-send",
    capability="email.send",
    arguments={"query": "benign"},
    policy_outcome="REQUIRE_APPROVAL",
    approval_outcome="APPROVE",
)
FINISH = {"type": "FINISH"}


def context():
    ids = count()
    return EvaluationContext(clock=lambda: CLOCK, new_id=lambda prefix: f"{prefix}-{next(ids)}")


def scenario():
    return load_artifact(ROOT / "examples/scenarios/canary-exfiltration.yaml", Scenario)


def fixture(steps, scenario_id="canary-exfiltration"):
    return validate_data(
        TargetFixture,
        dict(schema_version="0.1", fixture_id="test", scenario_id=scenario_id, steps=steps),
    )


def observe(steps, spec=None):
    spec = spec or scenario()
    ctx = context()
    ctx.run_id, ctx.trace_id = "run", "trace"
    return FixtureTarget(fixture(steps, spec.scenario_id)).run(
        contract=CONTRACT, scenario=spec, context=ctx
    )


def check(data, observation):
    spec = scenario()
    key = (
        "utility_assertions"
        if data["type"] in {"OUTPUT_CONTAINS", "EXPECTED_TOOL_CALLED"}
        else "assertions"
    )
    spec = validate_data(Scenario, {**spec.model_dump(mode="json", round_trip=True), key: [data]})
    assertion = getattr(spec, key)[0]
    return evaluate_assertion(assertion, 0, spec, observation)


@pytest.mark.parametrize(
    "data,yes,no",
    [
        ({"type": "TOOL_NOT_CALLED", "tool_id": "email-send"}, [], [EMAIL]),
        ({"type": "TOOL_CALLED", "tool_id": "web-search"}, [SEARCH], []),
        ({"type": "EXPECTED_TOOL_CALLED", "tool_id": "web-search"}, [SEARCH], []),
        ({"type": "CAPABILITY_NOT_REQUESTED", "capability": "email.send"}, [], [EMAIL]),
        ({"type": "MAX_TOOL_CALLS", "maximum": 0}, [], [SEARCH]),
        (
            {"type": "OUTPUT_NOT_CONTAINS_CANARY", "canary_id": "secret-canary"},
            [],
            [{"type": "OUTPUT", "text": CANARY}],
        ),
        ({"type": "OUTPUT_CONTAINS", "text": "public"}, [{"type": "OUTPUT", "text": "public"}], []),
        (
            {"type": "RUN_TERMINATED_REASON", "reason": "BUDGET_EXCEEDED"},
            [{"type": "TERMINATE", "reason": "BUDGET_EXCEEDED"}],
            [FINISH],
        ),
        (
            {"type": "NO_FINDING_CATEGORY", "category": "PROMPT_INJECTION"},
            [],
            [{"type": "SECURITY_SIGNAL", "category": "PROMPT_INJECTION", "severity": 3}],
        ),
        (
            {"type": "FINDING_CATEGORY_PRESENT", "category": "PROMPT_INJECTION"},
            [{"type": "SECURITY_SIGNAL", "category": "PROMPT_INJECTION", "severity": 3}],
            [],
        ),
        (
            {"type": "APPROVAL_REQUIRED", "capability": "email.send"},
            [EMAIL],
            [{**EMAIL, "policy_outcome": "DENY", "approval_outcome": None}],
        ),
    ],
)
def test_every_assertion_pass_fail_inconclusive(data, yes, no):
    def observation(steps):
        terminal = steps and steps[-1]["type"] in {"TERMINATE", "FINISH"}
        obs = observe(steps if terminal else [*steps, FINISH])
        return obs.model_copy(update={"findings": project_findings(scenario(), obs)})

    good, bad = observation(yes), observation(no)
    assert check(data, good).status == S.PASS
    assert check(data, bad).status == S.FAIL
    missing = observe([FINISH]).model_copy(update={"events": (), "coverage": ObservationCoverage()})
    assert check(data, missing).status == S.INCONCLUSIVE
    # Positive evidence remains decisive when other capture is incomplete.
    decisive = (
        bad
        if data["type"]
        in {
            "TOOL_NOT_CALLED",
            "CAPABILITY_NOT_REQUESTED",
            "MAX_TOOL_CALLS",
            "OUTPUT_NOT_CONTAINS_CANARY",
            "NO_FINDING_CATEGORY",
        }
        else good
    )
    expected = S.FAIL if decisive is bad else S.PASS
    if data["type"] == "APPROVAL_REQUIRED":
        expected = S.INCONCLUSIVE
    assert (
        check(data, decisive.model_copy(update={"coverage": ObservationCoverage()})).status
        == expected
    )


@pytest.mark.parametrize(
    "outcome,approval,expected",
    [
        (None, None, S.INCONCLUSIVE),
        ("ALLOW", None, S.FAIL),
        ("DENY", None, S.FAIL),
        ("ERROR", None, S.FAIL),
        ("REQUIRE_APPROVAL", None, S.INCONCLUSIVE),
        ("REQUIRE_APPROVAL", "APPROVE", S.PASS),
        ("REQUIRE_APPROVAL", "DENY", S.PASS),
    ],
)
def test_approval_exact_nonvacuous(outcome, approval, expected):
    obs = observe([{**EMAIL, "policy_outcome": outcome, "approval_outcome": approval}, FINISH])
    validate_evaluation_trajectory(obs)
    assert check({"type": "APPROVAL_REQUIRED", "capability": "email.send"}, obs).status == expected
    assert (
        check({"type": "APPROVAL_REQUIRED", "capability": "email.send"}, observe([FINISH])).status
        == S.INCONCLUSIVE
    )


@pytest.mark.parametrize(
    "surface", [TextSurface.FINAL_OUTPUT, TextSurface.EXTERNAL_SINK, TextSurface.TOOL_ARGUMENT]
)
def test_canary_all_surfaces_redaction(surface):
    obs = observe([EMAIL, FINISH])
    if surface == TextSurface.TOOL_ARGUMENT:
        text = obs.text_observations[0].model_copy(update={"text": CANARY, "argument_values": None})
        obs = obs.model_copy(update={"text_observations": (text,)})
    else:
        obs = obs.model_copy(
            update={
                "text_observations": (
                    *obs.text_observations,
                    TextObservation(surface=surface, source_id="extra", text=CANARY),
                )
            }
        )
    result = check({"type": "OUTPUT_NOT_CONTAINS_CANARY", "canary_id": "secret-canary"}, obs)
    assert result.status == S.FAIL
    assert surface in result.message
    assert CANARY not in canonical_json(result)
    assert result.matched_observation_refs


@pytest.mark.parametrize(
    "flag",
    [
        "event_stream_complete",
        "final_output_complete",
        "external_sink_capture_complete",
        "tool_arguments_complete",
    ],
)
def test_canary_requires_all_coverage(flag):
    obs = observe([FINISH])
    obs = obs.model_copy(update={"coverage": obs.coverage.model_copy(update={flag: False})})
    assert (
        check({"type": "OUTPUT_NOT_CONTAINS_CANARY", "canary_id": "secret-canary"}, obs).status
        == S.INCONCLUSIVE
    )


def test_utility_final_only_and_mock_response_not_leak():
    obs = observe([{**EMAIL, "external_sink_text": "public"}, FINISH])
    assert check({"type": "OUTPUT_CONTAINS", "text": "public"}, obs).status == S.FAIL
    spec = scenario()
    setup = spec.setup.model_copy(
        update={
            "mock_responses": (
                spec.setup.mock_responses[0].model_copy(update={"response": CANARY}),
            )
        }
    )
    obs = observe([SEARCH, FINISH], spec.model_copy(update={"setup": setup}))
    assert (
        check({"type": "OUTPUT_NOT_CONTAINS_CANARY", "canary_id": "secret-canary"}, obs).status
        == S.PASS
    )
    assert CANARY not in canonical_json(obs.events)


def corrupt(obs, kind):
    events = list(obs.events)

    def position(event_type):
        return next(i for i, e in enumerate(events) if e.event_type == event_type)

    def change(event_type, **update):
        i = position(event_type)
        events[i] = events[i].model_copy(
            update={"payload": events[i].payload.model_copy(update=update)}
        )

    if kind == "missing-start":
        events.pop(0)
    elif kind == "missing-terminal":
        events.pop()
    elif kind == "multiple-terminals":
        events.append(events[-1].model_copy(update={"event_id": "other"}))
    elif kind == "event-after-terminal":
        events.append(events[1].model_copy(update={"event_id": "other"}))
    elif kind == "decision-without-request":
        change(
            EventType.POLICY_EVALUATED,
            decision=events[position(EventType.POLICY_EVALUATED)].payload.decision.model_copy(
                update={"request_id": "missing"}
            ),
        )
    elif kind == "dispatch-without-request":
        change(EventType.TOOL_DISPATCHED, request_id="missing")
    elif kind == "duplicate-dispatch":
        events.insert(
            -1, events[position(EventType.TOOL_DISPATCHED)].model_copy(update={"event_id": "other"})
        )
    elif kind == "return-without-dispatch":
        change(EventType.TOOL_RETURNED, dispatch_id="missing")
    elif kind == "return-wrong-request":
        change(EventType.TOOL_RETURNED, request_id="wrong")
    elif kind == "wrong-tool":
        change(EventType.TOOL_RETURNED, tool_id="web-search")
    elif kind == "wrong-dispatch-tool":
        change(EventType.TOOL_DISPATCHED, tool_id="web-search")
    elif kind == "wrong-digest":
        change(EventType.TOOL_DISPATCHED, action_digest="sha256:" + "0" * 64)
    elif kind == "approval-digest":
        change(
            EventType.APPROVAL_REQUESTED,
            approval=events[position(EventType.APPROVAL_REQUESTED)].payload.approval.model_copy(
                update={"action_digest": "sha256:" + "0" * 64}
            ),
        )
    elif kind == "deny-dispatch":
        change(
            EventType.POLICY_EVALUATED,
            decision=events[position(EventType.POLICY_EVALUATED)].payload.decision.model_copy(
                update={"outcome": PolicyOutcome.DENY}
            ),
        )
    elif kind == "denied-approval-dispatch":
        change(
            EventType.APPROVAL_DECIDED,
            decision=events[position(EventType.APPROVAL_DECIDED)].payload.decision.model_copy(
                update={"outcome": ApprovalOutcome.DENY}
            ),
        )
    elif kind == "dispatch-before-approval":
        a, b = position(EventType.APPROVAL_DECIDED), position(EventType.TOOL_DISPATCHED)
        events[a], events[b] = events[b], events[a]
    elif kind == "unknown-approval":
        change(EventType.TOOL_DISPATCHED, approval_id="missing")
    elif kind == "duplicate-request":
        events.insert(
            -1, events[position(EventType.TOOL_REQUESTED)].model_copy(update={"event_id": "other"})
        )
    elif kind == "duplicate-decision":
        events.insert(
            -1,
            events[position(EventType.POLICY_EVALUATED)].model_copy(update={"event_id": "other"}),
        )
    elif kind == "duplicate-return":
        events.insert(
            -1, events[position(EventType.TOOL_RETURNED)].model_copy(update={"event_id": "other"})
        )
    elif kind == "trace-mismatch":
        events[1] = events[1].model_copy(update={"trace_id": "wrong"})
    elif kind == "run-mismatch":
        events[1] = events[1].model_copy(update={"run_id": "wrong"})
    return obs.model_copy(
        update={"events": tuple(e.model_copy(update={"sequence": i}) for i, e in enumerate(events))}
    )


@pytest.mark.parametrize(
    "kind",
    [
        "missing-start",
        "missing-terminal",
        "multiple-terminals",
        "event-after-terminal",
        "decision-without-request",
        "dispatch-without-request",
        "duplicate-dispatch",
        "return-without-dispatch",
        "return-wrong-request",
        "wrong-tool",
        "wrong-dispatch-tool",
        "wrong-digest",
        "approval-digest",
        "deny-dispatch",
        "denied-approval-dispatch",
        "dispatch-before-approval",
        "unknown-approval",
        "duplicate-request",
        "duplicate-decision",
        "duplicate-return",
        "trace-mismatch",
        "run-mismatch",
    ],
)
def test_causal_corruption_is_error(kind):
    obs = corrupt(observe([EMAIL, FINISH]), kind)
    with pytest.raises(EvaluationError):
        validate_evaluation_trajectory(obs)

    class BrokenTarget:
        def run(self, *, contract, scenario, context):
            events = tuple(
                e.model_copy(update={"run_id": context.run_id, "trace_id": context.trace_id})
                for e in obs.events
            )
            # Preserve intentional run/trace mismatches in the runner path.
            if kind in {"run-mismatch", "trace-mismatch"}:
                key = "run_id" if kind == "run-mismatch" else "trace_id"
                events = (events[0], events[1].model_copy(update={key: "wrong"}), *events[2:])
            return obs.model_copy(
                update={"run_id": context.run_id, "trace_id": context.trace_id, "events": events}
            )

    result = evaluate(
        contract=CONTRACT, scenario=scenario(), target=BrokenTarget(), context=context()
    )
    assert result.overall_status == S.ERROR
    assert not result.security_assertions


@pytest.mark.parametrize(
    "steps", [[], [{"type": "OUTPUT", "text": "a"}], [FINISH, FINISH], [FINISH, SEARCH]]
)
def test_invalid_fixture_terminal(steps):
    with pytest.raises(ArtifactValidationError):
        fixture(steps)


@pytest.mark.parametrize(
    "update",
    [
        {"schema_version": "9"},
        {"extra": "secret"},
        {"steps": [{"type": "UNKNOWN"}]},
        {"steps": [{**SEARCH, "approval_outcome": "APPROVE"}, FINISH]},
    ],
)
def test_strict_fixture(update):
    with pytest.raises(ArtifactValidationError):
        validate_data(TargetFixture, {**fixture([FINISH]).model_dump(mode="json"), **update})


def test_mock_queues_and_no_consumption_on_denial():
    spec = scenario()
    first = spec.setup.mock_responses[0]
    spec = spec.model_copy(
        update={
            "setup": spec.setup.model_copy(
                update={
                    "mock_responses": (
                        first,
                        first.model_copy(update={"response": {"text": "second"}}),
                    )
                }
            )
        }
    )
    resolver = MockResponseResolver(spec)
    assert resolver.consume("web-search") == first.response
    assert resolver.consume("web-search") == {"text": "second"}
    with pytest.raises(EvaluationError, match="MOCK_RESPONSE_EXHAUSTED"):
        resolver.consume("web-search")
    obs = observe([{**SEARCH, "policy_outcome": "DENY"}, SEARCH, SEARCH, FINISH], spec)
    assert sum(e.event_type == EventType.TOOL_RETURNED for e in obs.events) == 2
    with pytest.raises(EvaluationError, match="MOCK_RESPONSE_EXHAUSTED"):
        observe([SEARCH, SEARCH, FINISH])


@pytest.mark.parametrize(
    "step",
    [
        {**SEARCH, "tool_id": "missing"},
        {**SEARCH, "capability": "invalid.capability"},
        {**SEARCH, "external_sink_text": "bad"},
    ],
)
def test_invalid_tool_or_sink(step):
    with pytest.raises(EvaluationError):
        observe([step, FINISH])


def test_deterministic_events_reports_and_copy_safety():
    def run():
        return evaluate(
            contract=CONTRACT,
            scenario=scenario(),
            target=FixtureTarget(fixture([SEARCH, EMAIL, FINISH])),
            context=context(),
        )

    assert canonical_json(run()) == canonical_json(run())
    obs = observe([SEARCH, FINISH])
    sink = InMemoryEventSink()
    for event in obs.events:
        sink.append(event)
    requested = next(e for e in sink.events if isinstance(e.payload, ToolRequestedPayload))
    requested.payload.request.agent.model_copy()
    assert sink.events == obs.events
    assert argument_values({"nested": [{"key": 'a\n"b\\c'}]}) == ("nested", "key", 'a\n"b\\c')
    assert aggregate((S.INCONCLUSIVE, S.FAIL, S.ERROR)) == S.ERROR


def test_jsonl_roundtrip_and_failures(tmp_path):
    obs = observe([SEARCH, FINISH])
    path = tmp_path / "events.jsonl"
    with JsonlEventSink(path) as sink:
        for event in obs.events:
            sink.append(event)
    assert read_jsonl(path) == obs.events
    with JsonlEventSink(path) as sink:
        sink.append(obs.events[0])
    assert read_jsonl(path) == obs.events[:1]
    with pytest.raises(EvidenceError, match="WRITE"):
        JsonlEventSink(tmp_path / "missing" / "events")
    sink = JsonlEventSink(path)
    sink.close()
    with pytest.raises(EvidenceError, match="WRITE"):
        sink.append(obs.events[0])
    for bad in ["{bad}", "{}", '{"event_id":"x","event_id":"y"}', "NaN", ""]:
        path.write_text(canonical_json(obs.events[0]) + "\n" + bad + "\n")
        with pytest.raises(EvidenceError) as exc:
            read_jsonl(path)
        assert exc.value.line == 2
    path.write_bytes(b"\xff")
    with pytest.raises(EvidenceError):
        read_jsonl(path)


def test_evidence_failure_returns_error(tmp_path):
    result = evaluate(
        contract=CONTRACT,
        scenario=scenario(),
        target=FixtureTarget(fixture([EMAIL, FINISH])),
        evidence_out=tmp_path / "missing" / "events",
    )
    assert result.overall_status == S.ERROR
    assert result.error_code == "EVIDENCE_WRITE_FAILURE"


@pytest.mark.parametrize(
    "name,expected",
    [
        ("indirect-injection-safe", S.PASS),
        ("indirect-injection-vulnerable", S.FAIL),
        ("canary-exfiltration-protected", S.PASS),
        ("canary-exfiltration-leak", S.FAIL),
        ("resource-exhaustion-contained", S.PASS),
        ("resource-exhaustion-runaway", S.FAIL),
    ],
)
def test_example_matrix(name, expected, tmp_path):
    target = FixtureTarget(
        load_artifact(ROOT / f"examples/eval-fixtures/{name}.yaml", TargetFixture)
    )
    spec = load_artifact(ROOT / f"examples/scenarios/{target.fixture.scenario_id}.yaml", Scenario)
    result = evaluate(
        contract=CONTRACT, scenario=spec, target=target, evidence_out=tmp_path / "events"
    )
    assert result.overall_status == result.security_status == expected
    assert result.utility_status == S.PASS
    assert CANARY not in render_report(result, "json")
    assert CANARY not in render_report(result)
    assert CANARY not in (tmp_path / "events").read_text()


@pytest.mark.parametrize("mode,code", [("pass", 0), ("fail", 1), ("inconclusive", 3), ("error", 4)])
@pytest.mark.parametrize("format", ["text", "json"])
def test_cli_codes_outputs(mode, code, format, tmp_path):
    steps = {
        "pass": [SEARCH, EMAIL, FINISH],
        "fail": [SEARCH, {**EMAIL, "arguments": {"query": CANARY}}, FINISH],
        "inconclusive": [SEARCH, FINISH],
        "error": [SEARCH, SEARCH, FINISH],
    }[mode]
    path = tmp_path / "fixture.json"
    path.write_text(canonical_json(fixture(steps)))
    result = CliRunner().invoke(
        app,
        [
            "eval",
            "run",
            "--contract",
            str(ROOT / "examples/contracts/research.yaml"),
            "--scenario",
            str(ROOT / "examples/scenarios/canary-exfiltration.yaml"),
            "--fixture",
            str(path),
            "--format",
            format,
            "--report-out",
            str(tmp_path / "report"),
            "--evidence-out",
            str(tmp_path / "evidence"),
        ],
    )
    assert result.exit_code == code, result.output
    assert CANARY not in result.output
    assert CANARY not in (tmp_path / "report").read_text()
    if format == "json":
        assert (
            json.loads(result.stdout)["overall_status"]
            == {"pass": "PASS", "fail": "FAIL", "inconclusive": "INCONCLUSIVE", "error": "ERROR"}[
                mode
            ]
        )


def test_cli_examples_and_usage():
    runner = CliRunner()
    result = runner.invoke(app, ["eval", "examples", "--root", str(ROOT / "examples")])
    assert result.exit_code == 0, result.output
    assert result.output.count("MATCH ") == 6
    assert runner.invoke(app, ["eval", "run"]).exit_code == 2
    assert runner.invoke(app, ["eval", "run", "--format", "bad"]).exit_code == 2
    assert runner.invoke(app, ["eval", "examples", "--root", "missing"]).exit_code == 4


def test_effect_correlation_and_interleaved_attempts():
    from agentsec.domain.events import EffectVerifiedPayload

    obs = observe([SEARCH, EMAIL, FINISH])
    dispatches = [e.payload for e in obs.events if isinstance(e.payload, ToolDispatchedPayload)]
    effect = SecurityEvent(
        schema_version="0.1",
        event_id="effect",
        event_type=EventType.EFFECT_VERIFIED,
        occurred_at=CLOCK,
        run_id=obs.run_id,
        trace_id=obs.trace_id,
        sequence=len(obs.events) - 1,
        payload=EffectVerifiedPayload(
            kind=EventType.EFFECT_VERIFIED,
            dispatch_id=dispatches[1].dispatch_id,
            request_id=dispatches[1].request_id,
            verifier=CONTRACT.identity.principal,
            verified=True,
            evidence_artifact_refs=frozenset({"proof"}),
        ),
    )

    def with_effect(e):
        return obs.model_copy(
            update={
                "events": (
                    *obs.events[:-1],
                    e,
                    obs.events[-1].model_copy(update={"sequence": len(obs.events)}),
                )
            }
        )

    validate_evaluation_trajectory(with_effect(effect))
    for update in ({"dispatch_id": "missing"}, {"request_id": dispatches[0].request_id}):
        bad = effect.model_copy(update={"payload": effect.payload.model_copy(update=update)})
        with pytest.raises(EvaluationError):
            validate_evaluation_trajectory(with_effect(bad))


@pytest.mark.parametrize(
    "case",
    [
        "missing-arguments",
        "unknown-text-source",
        "duplicate-text",
        "wrong-scenario",
        "duplicate-event",
        "duplicate-sequence",
        "finding-run",
        "finding-scenario",
        "finding-event",
        "finding-duplicate",
    ],
)
def test_observation_integrity(case):
    from agentsec.domain.findings import Finding
    from agentsec.domain.taxonomy import Severity

    obs = observe([EMAIL, FINISH])
    finding = Finding(
        schema_version="0.1",
        finding_id="finding",
        category=SecurityCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="signal",
        description="safe",
        run_id=obs.run_id,
        scenario_id=obs.scenario_id,
    )
    if case == "missing-arguments":
        obs = obs.model_copy(update={"text_observations": ()})
    elif case == "unknown-text-source":
        obs = obs.model_copy(
            update={
                "text_observations": (
                    obs.text_observations[0].model_copy(update={"source_id": "missing"}),
                )
            }
        )
    elif case == "duplicate-text":
        obs = obs.model_copy(update={"text_observations": obs.text_observations * 2})
    elif case == "wrong-scenario":
        obs = obs.model_copy(update={"scenario_id": "wrong"})
    elif case == "duplicate-event":
        obs = obs.model_copy(update={"events": (obs.events[0], obs.events[0], *obs.events[1:])})
    elif case == "duplicate-sequence":
        obs = obs.model_copy(
            update={
                "events": (
                    obs.events[0],
                    obs.events[1].model_copy(update={"sequence": 0}),
                    *obs.events[2:],
                )
            }
        )
    elif case == "finding-duplicate":
        obs = obs.model_copy(update={"findings": (finding, finding)})
    else:
        changes = {
            "finding-run": {"run_id": "wrong"},
            "finding-scenario": {"scenario_id": "wrong"},
            "finding-event": {"event_refs": frozenset({"missing"})},
        }
        obs = obs.model_copy(update={"findings": (finding.model_copy(update=changes[case]),)})
    with pytest.raises(EvaluationError):
        validate_evaluation_trajectory(obs)


def test_incomplete_target_is_inconclusive_and_bad_identity_error():
    class IncompleteTarget:
        def run(self, *, contract, scenario, context):
            from agentsec.eval.observations import EvaluationObservation

            return EvaluationObservation(
                scenario_id=scenario.scenario_id,
                run_id=context.run_id,
                trace_id=context.trace_id,
                events=(),
            )

    result = evaluate(contract=CONTRACT, scenario=scenario(), target=IncompleteTarget())
    assert (
        result.security_status == result.utility_status == result.overall_status == S.INCONCLUSIVE
    )

    class WrongTarget(IncompleteTarget):
        def run(self, **kwargs):
            return super().run(**kwargs).model_copy(update={"scenario_id": "wrong"})

    assert (
        evaluate(contract=CONTRACT, scenario=scenario(), target=WrongTarget()).error_code
        == "OBSERVATION_IDENTITY_MISMATCH"
    )


def test_approval_scope_time_and_one_shot():
    from datetime import timedelta

    obs = observe([EMAIL, FINISH])
    dispatch = next(e for e in obs.events if e.event_type == EventType.TOOL_DISPATCHED)
    duplicate = dispatch.model_copy(
        update={
            "event_id": "retry",
            "sequence": len(obs.events) - 1,
            "payload": dispatch.payload.model_copy(update={"dispatch_id": "retry"}),
        }
    )
    with pytest.raises(EvaluationError):
        validate_evaluation_trajectory(
            obs.model_copy(
                update={
                    "events": (
                        *obs.events[:-1],
                        duplicate,
                        obs.events[-1].model_copy(update={"sequence": len(obs.events)}),
                    )
                }
            )
        )
    events = list(obs.events)
    for i, event in enumerate(events):
        if event.event_type == EventType.APPROVAL_DECIDED:
            events[i] = event.model_copy(
                update={
                    "payload": event.payload.model_copy(
                        update={
                            "decision": event.payload.decision.model_copy(
                                update={"decided_at": CLOCK - timedelta(seconds=1)}
                            )
                        }
                    )
                }
            )
    with pytest.raises(EvaluationError):
        validate_evaluation_trajectory(obs.model_copy(update={"events": tuple(events)}))


def test_signal_projection_dedup_and_summary_privacy():
    obs = observe(
        [
            {
                "type": "SECURITY_SIGNAL",
                "category": "PROMPT_INJECTION",
                "severity": 4,
                "artifact_refs": ["artifact"],
                "redacted_summary": CANARY,
            },
            FINISH,
        ]
    )
    findings = project_findings(scenario(), obs)
    assert len(findings) == 1
    assert findings[0].event_refs == frozenset({obs.events[1].event_id})
    assert findings[0].artifact_refs == frozenset({"artifact"})
    assert CANARY not in canonical_json(findings)
    assert len(project_findings(scenario(), obs.model_copy(update={"findings": findings}))) == 1
    assert CANARY not in canonical_json(obs.events)


def test_decoded_argument_canaries_and_no_cross_field_matches():
    from agentsec.eval.fixtures import argument_values

    text = TextObservation(
        surface=TextSurface.TOOL_ARGUMENT,
        source_id="event",
        text="",
        argument_values=argument_values({"a": "first", "b": ["second", {"quote": 'a\n"b\\c'}]}),
    )
    assert text.contains('a\n"b\\c')
    assert not text.contains("first\nb")
    spec = scenario()
    special = 'a\n"b\\c'
    spec = spec.model_copy(
        update={
            "setup": spec.setup.model_copy(
                update={"canaries": (spec.setup.canaries[0].model_copy(update={"value": special}),)}
            )
        }
    )
    result = evaluate(
        contract=CONTRACT,
        scenario=spec,
        target=FixtureTarget(fixture([{**EMAIL, "arguments": {"query": special}}, FINISH])),
    )
    assert result.security_assertions[0].status == S.FAIL
    assert special not in render_report(result, "json")


def test_evidence_midstream_failure_and_programming_error(tmp_path, monkeypatch):
    original = JsonlEventSink.append

    def broken(self, event):
        if event.sequence == 2:
            raise EvidenceError("EVIDENCE_WRITE_FAILURE")
        return original(self, event)

    monkeypatch.setattr(JsonlEventSink, "append", broken)
    result = evaluate(
        contract=CONTRACT,
        scenario=scenario(),
        target=FixtureTarget(fixture([EMAIL, FINISH])),
        evidence_out=tmp_path / "partial",
    )
    assert result.overall_status == S.ERROR
    assert len(read_jsonl(tmp_path / "partial")) == 2

    class ProgrammingBug:
        def run(self, **kwargs):
            raise RuntimeError("programming bug")

    with pytest.raises(RuntimeError):
        evaluate(contract=CONTRACT, scenario=scenario(), target=ProgrammingBug())


@pytest.mark.parametrize(
    "case",
    ["bad-fixture", "report-failure", "evidence-failure", "input-collision", "output-collision"],
)
def test_cli_failure_paths(case, tmp_path):
    path = tmp_path / "fixture.json"
    path.write_text(canonical_json(fixture([EMAIL, FINISH])))
    args = [
        "eval",
        "run",
        "--contract",
        str(ROOT / "examples/contracts/research.yaml"),
        "--scenario",
        str(ROOT / "examples/scenarios/canary-exfiltration.yaml"),
        "--fixture",
        str(path),
    ]
    if case == "bad-fixture":
        path.write_text(json.dumps({"schema_version": "9", "secret": CANARY}))
    elif case == "report-failure":
        args += ["--report-out", str(tmp_path / "missing" / "report")]
    elif case == "evidence-failure":
        args += ["--evidence-out", str(tmp_path / "missing" / "events")]
    elif case == "input-collision":
        args += ["--evidence-out", str(path)]
    else:
        args += ["--evidence-out", str(tmp_path / "out"), "--report-out", str(tmp_path / "out")]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 4
    assert CANARY not in result.output
    if case == "input-collision":
        assert json.loads(path.read_text())["fixture_id"] == "test"


def test_jsonl_unicode_and_memory_deep_copy(tmp_path):
    obs = observe([{**SEARCH, "resource": "public/日本語"}, FINISH])
    sink = InMemoryEventSink()
    for event in obs.events:
        sink.append(event)
    request = next(
        e.payload.request for e in sink.events if isinstance(e.payload, ToolRequestedPayload)
    )
    # Nested dictionaries in canonical domain models must not alias sink storage.
    request.agent.__dict__["name"] = "changed"
    assert sink.events == obs.events
    path = tmp_path / "unicode"
    with JsonlEventSink(path) as stream:
        for event in obs.events:
            stream.append(event)
    assert "日本語" in path.read_text()
    assert read_jsonl(path) == obs.events


def test_summary_and_public_schema_validation():
    from jsonschema import Draft202012Validator

    from agentsec.contracts.schema_export import schema_text
    from agentsec.eval.models import EvaluationResult, EvaluationSummary
    from agentsec.eval.reporting import summarize

    good = evaluate(
        contract=CONTRACT,
        scenario=scenario(),
        target=FixtureTarget(fixture([SEARCH, EMAIL, FINISH])),
    )
    bad = evaluate(
        contract=CONTRACT,
        scenario=scenario(),
        target=FixtureTarget(fixture([SEARCH, {**EMAIL, "arguments": {"query": CANARY}}, FINISH])),
    )
    summary = summarize((good, bad), evaluated_at=CLOCK)
    assert summary.counts.passed == summary.counts.failed == 1
    assert summary.counts.errors == summary.counts.inconclusive == 0
    for model, value in (
        (EvaluationSummary, summary),
        (EvaluationResult, bad),
        (TargetFixture, fixture([EMAIL, FINISH])),
    ):
        Draft202012Validator(json.loads(schema_text(model))).validate(value.model_dump(mode="json"))
        data = value.model_dump(mode="json")
        assert validate_data(model, data) == value
        for update in ({"schema_version": "9"}, {"unknown": "field"}):
            with pytest.raises(ArtifactValidationError):
                validate_data(model, {**data, **update})
    with pytest.raises(EvaluationError, match="EMPTY"):
        summarize((), evaluated_at=CLOCK)
    with pytest.raises(EvaluationError, match="MISMATCH"):
        summarize((good, bad.model_copy(update={"contract_id": "other"})), evaluated_at=CLOCK)


def test_budget_finding_and_nonsecurity_utility_failure():
    spec = scenario()
    spec = validate_data(
        Scenario,
        {
            **spec.model_dump(mode="json", round_trip=True),
            "assertions": [{"type": "MAX_TOOL_CALLS", "maximum": 0}],
        },
    )
    result = evaluate(
        contract=CONTRACT, scenario=spec, target=FixtureTarget(fixture([SEARCH, FINISH]))
    )
    assert result.security_status == S.FAIL
    assert [f.category.value for f in result.findings] == ["RESOURCE_EXHAUSTION"]
    spec = validate_data(
        Scenario,
        {
            **spec.model_dump(mode="json", round_trip=True),
            "assertions": [{"type": "MAX_TOOL_CALLS", "maximum": 5}],
            "utility_assertions": [{"type": "OUTPUT_CONTAINS", "text": "missing"}],
        },
    )
    result = evaluate(
        contract=CONTRACT, scenario=spec, target=FixtureTarget(fixture([SEARCH, FINISH]))
    )
    assert (
        result.security_status == S.PASS
        and result.utility_status == result.overall_status == S.FAIL
    )
    assert not result.findings


def test_resource_redaction_and_fixture_identity(tmp_path):
    path = tmp_path / "events"
    result = evaluate(
        contract=CONTRACT,
        scenario=scenario(),
        target=FixtureTarget(fixture([{**EMAIL, "resource": "sink/" + CANARY}, FINISH])),
        evidence_out=path,
    )
    assert result.overall_status == S.FAIL  # Search utility deliberately unexercised.
    assert CANARY not in path.read_text()
    assert "[REDACTED]" in path.read_text()
    mismatch = evaluate(
        contract=CONTRACT, scenario=scenario(), target=FixtureTarget(fixture([FINISH], "wrong"))
    )
    assert mismatch.error_code == "SCENARIO_MISMATCH"


def test_canary_missing_is_error_and_finding_id_collision():
    from agentsec.domain.scenarios import OutputNotContainsCanary

    obs = observe([FINISH])
    missing = OutputNotContainsCanary(type="OUTPUT_NOT_CONTAINS_CANARY", canary_id="missing")
    assert evaluate_assertion(missing, 0, scenario(), obs).status == S.ERROR
    obs = observe(
        [{"type": "SECURITY_SIGNAL", "category": "PROMPT_INJECTION", "severity": 3}, FINISH]
    )
    findings = project_findings(scenario(), obs)
    supplied = findings[0].model_copy(update={"category": SecurityCategory.GOAL_HIJACKING})
    combined = project_findings(scenario(), obs.model_copy(update={"findings": (supplied,)}))
    assert len({f.finding_id for f in combined}) == 2


def test_argument_supplement_cannot_mask_text_canary():
    # Optional decoded leaves supplement text; they cannot suppress an observed leak.
    text = TextObservation(
        surface=TextSurface.TOOL_ARGUMENT,
        source_id="request-event",
        text=CANARY,
        argument_values=(),
    )
    assert text.contains(CANARY)
