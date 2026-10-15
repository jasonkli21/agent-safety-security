import json
from copy import deepcopy
from pathlib import Path

import pytest

from agentsec.contracts.errors import ArtifactValidationError, ErrorCode
from agentsec.contracts.loader import load_artifact, validate_data
from agentsec.domain.events import SecurityEvent, validate_event_sequence
from agentsec.domain.scenarios import Scenario
from agentsec.domain.serialization import canonical_json
from agentsec.domain.taxonomy import EventType

ROOT = Path(__file__).resolve().parents[2]
EVENTS = json.loads((ROOT / "tests/fixtures/events/approval-run.json").read_text())
SCENARIO = json.loads(
    canonical_json(load_artifact(ROOT / "examples/scenarios/indirect-injection.yaml", Scenario))
)


@pytest.mark.parametrize("name", ["approval-run", "denied-run"])
def test_evidence_run_roundtrip(name):
    raw = json.loads((ROOT / f"tests/fixtures/events/{name}.json").read_text())
    events = [validate_data(SecurityEvent, d) for d in raw]
    validate_event_sequence(events)
    for event in events:
        assert event == validate_data(SecurityEvent, json.loads(canonical_json(event)))
    assert "secret" not in canonical_json(events)


@pytest.mark.parametrize("event_type", list(EventType))
def test_all_event_payloads(event_type):
    existing = {e["event_type"]: e for e in EVENTS}
    extra = {
        "SECURITY_SIGNAL": {
            "category": "PROMPT_INJECTION",
            "severity": 2,
            "artifact_refs": ["artifact-1"],
        },
        "RUN_TERMINATED": {"reason": "BUDGET_EXCEEDED"},
    }
    if event_type in existing:
        data = deepcopy(existing[event_type])
    else:
        data = {
            **EVENTS[0],
            "event_type": event_type.value,
            "payload": {"kind": event_type.value, **extra[event_type]},
        }
    event = validate_data(SecurityEvent, data)
    assert event.payload.kind == event.event_type
    with pytest.raises(ArtifactValidationError):
        validate_data(
            SecurityEvent,
            {
                **data,
                "event_type": "TOOL_RETURNED"
                if event_type != EventType.TOOL_RETURNED
                else "RUN_STARTED",
            },
        )
    with pytest.raises(ArtifactValidationError):
        validate_data(SecurityEvent, {**data, "payload": {**data["payload"], "unknown": True}})


@pytest.mark.parametrize(
    "changes",
    [
        {"sequence": -1},
        {"sequence": True},
        {"sequence": "1"},
        {"occurred_at": "2026-01-01T00:00:00"},
        {"event_type": "UNKNOWN"},
        {"payload": {"kind": "UNKNOWN"}},
        {"schema_version": "2.0"},
    ],
)
def test_event_invalid_envelope(changes):
    with pytest.raises(ArtifactValidationError):
        validate_data(SecurityEvent, {**EVENTS[0], **changes})


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e[1].update(sequence=0),
        lambda e: e[2].update(sequence=0),
        lambda e: e[1].update(event_id=e[0]["event_id"]),
        lambda e: e[1].update(trace_id="different-trace"),
    ],
)
def test_invalid_ordering(change):
    data = deepcopy(EVENTS)
    change(data)
    with pytest.raises(ArtifactValidationError) as caught:
        validate_event_sequence([validate_data(SecurityEvent, d) for d in data])
    assert caught.value.issues[0].code == ErrorCode.INVALID_EVENT_SEQUENCE


def test_interleaved_runs_and_sequence_gaps():
    other = {**EVENTS[0], "run_id": "run-other", "trace_id": "trace-other", "event_id": "other"}
    data = [EVENTS[0], other, EVENTS[3]]
    validate_event_sequence([validate_data(SecurityEvent, d) for d in data])


@pytest.mark.parametrize("path", sorted((ROOT / "examples/scenarios").glob("*.yaml")))
def test_scenario_roundtrip(path):
    scenario = load_artifact(path, Scenario)
    assert scenario == validate_data(Scenario, json.loads(canonical_json(scenario)))
    assert scenario.utility_assertions


@pytest.mark.parametrize("path", sorted((ROOT / "tests/fixtures/scenarios").glob("*.yaml")))
def test_invalid_scenarios(path):
    with pytest.raises(ArtifactValidationError) as caught:
        load_artifact(path, Scenario)
    if path.stem == "unknown-assertion":
        assert caught.value.issues[0].code == ErrorCode.UNKNOWN_ASSERTION_TYPE


@pytest.mark.parametrize(
    "assertion",
    [
        {"type": "TOOL_NOT_CALLED", "tool_id": "email-send"},
        {"type": "TOOL_CALLED", "tool_id": "web-search"},
        {"type": "CAPABILITY_NOT_REQUESTED", "capability": "email.send"},
        {"type": "OUTPUT_NOT_CONTAINS_CANARY", "canary_id": "canary"},
        {"type": "APPROVAL_REQUIRED", "capability": "email.send"},
        {"type": "MAX_TOOL_CALLS", "maximum": 0},
        {"type": "RUN_TERMINATED_REASON", "reason": "BUDGET_EXCEEDED"},
        {"type": "NO_FINDING_CATEGORY", "category": "SECRET_EXFILTRATION"},
        {"type": "FINDING_CATEGORY_PRESENT", "category": "RESOURCE_EXHAUSTION"},
    ],
)
def test_all_assertion_discriminators(assertion):
    data = deepcopy(SCENARIO)
    data["setup"]["canaries"] = [{"canary_id": "canary", "value": "CANARY_SYNTHETIC"}]
    data["assertions"] = [assertion]
    assert validate_data(Scenario, data).assertions[0].type == assertion["type"]
    data["assertions"][0]["unknown"] = True
    with pytest.raises(ArtifactValidationError):
        validate_data(Scenario, data)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["setup"].update(mock_responses=[{"tool_id": "missing", "response": None}]),
        lambda d: d["setup"].update(initial_memory=["missing"]),
        lambda d: d["setup"]["data_artifacts"].append(deepcopy(d["setup"]["data_artifacts"][0])),
        lambda d: d["setup"].update(
            canaries=[{"canary_id": "c", "value": "X"}, {"canary_id": "c", "value": "Y"}]
        ),
        lambda d: d.update(
            utility_assertions=[{"type": "EXPECTED_TOOL_CALLED", "tool_id": "missing"}]
        ),
        lambda d: d.update(utility_assertions=[{"type": "LLM_JUDGE"}]),
        lambda d: d.update(assertions=[]),
    ],
)
def test_scenario_references_and_required_assertions(mutate):
    data = deepcopy(SCENARIO)
    mutate(data)
    with pytest.raises(ArtifactValidationError):
        validate_data(Scenario, data)


def test_utility_output_assertion_and_fixture_reference():
    data = deepcopy(SCENARIO)
    data["utility_assertions"] = [{"type": "OUTPUT_CONTAINS", "text": "research"}]
    data["injections"][0]["fixture_ref"] = "static-fixture"
    del data["injections"][0]["content"]
    assert validate_data(Scenario, data).injections[0].fixture_ref == "static-fixture"


@pytest.mark.parametrize(
    "name,code",
    [
        ("invalid-payload", ErrorCode.INVALID_SCHEMA),
        ("invalid-order", ErrorCode.INVALID_EVENT_SEQUENCE),
        ("invalid-approval-expiry", ErrorCode.INVALID_TIMESTAMP_RANGE),
    ],
)
def test_invalid_event_fixtures(name, code):
    data = json.loads((ROOT / f"tests/fixtures/events/{name}.json").read_text())
    with pytest.raises(ArtifactValidationError) as caught:
        if isinstance(data, list):
            validate_event_sequence([validate_data(SecurityEvent, event) for event in data])
        else:
            validate_data(SecurityEvent, data)
    assert caught.value.issues[0].code == code
