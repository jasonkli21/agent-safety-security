import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import get_type_hints

import pytest
from pydantic import ValidationError

from agentsec.contracts.errors import ArtifactValidationError, ErrorCode
from agentsec.contracts.loader import load_artifact, validate_data
from agentsec.domain.approvals import (
    ApprovalDecision,
    ApprovalRequest,
    NormalizedAction,
    action_digest,
)
from agentsec.domain.base import VersionedModel
from agentsec.domain.findings import Finding
from agentsec.domain.identity import AgentIdentity, Delegation, PrincipalRef, TaskScope
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.provenance import DataArtifactRef
from agentsec.domain.scenarios import Scenario
from agentsec.domain.serialization import canonical_json
from agentsec.domain.taxonomy import PrincipalType, Severity, TrustClass
from agentsec.domain.tools import ToolDescriptor, description_digest, schema_digest
from agentsec.policy.ports import PolicyEngine

ROOT = Path(__file__).resolve().parents[2]
STAMP = "2026-10-15T12:00:00Z"
HASH = "sha256:" + "a" * 64
PRINCIPAL = {"principal_id": "agent:local", "principal_type": "AGENT"}
TOOL = (
    load_artifact(ROOT / "examples/scenarios/indirect-injection.yaml", Scenario)
    .setup.tools[0]
    .model_dump(mode="json", round_trip=True)
)
REQUEST = json.loads((ROOT / "tests/fixtures/events/approval-run.json").read_text())[1]["payload"][
    "request"
]
DECISION = json.loads((ROOT / "tests/fixtures/events/approval-run.json").read_text())[2]["payload"][
    "decision"
]
APPROVAL = json.loads((ROOT / "tests/fixtures/events/approval-run.json").read_text())[3]["payload"][
    "approval"
]
APPROVED = json.loads((ROOT / "tests/fixtures/events/approval-run.json").read_text())[4]["payload"][
    "decision"
]
DELEGATION = {
    "schema_version": "0.1",
    "delegation_id": "delegation-1",
    "delegator": PRINCIPAL,
    "delegate": {"principal_id": "agent:child", "principal_type": "AGENT"},
    "task_scope": {"task_id": "task-1", "description": "Read public data"},
    "capability_scope": ["web.search"],
    "issued_at": STAMP,
    "expires_at": "2026-10-15T12:01:00Z",
}
ACTION = {
    "schema_version": "0.1",
    "principal": PRINCIPAL,
    "agent_id": "local",
    "environment": "development",
    "capability": "email.send",
    "tool_id": "email-send",
    "arguments": {"to": "synthetic@example.invalid", "body": "hello"},
    "tool_schema_hash": HASH,
    "tool_description_hash": HASH,
    "effective_policy_hash": HASH,
}
ARTIFACT = {
    "schema_version": "0.1",
    "artifact_id": "artifact-1",
    "labels": ["SECRET"],
    "origin": {"origin_type": "fixture", "trust_class": "UNTRUSTED_EXTERNAL"},
    "parent_artifact_ids": ["parent-1"],
    "content_hash": HASH,
}
FINDING = {
    "schema_version": "0.1",
    "finding_id": "finding-1",
    "category": "SECRET_EXFILTRATION",
    "severity": 3,
    "title": "Canary exposed",
    "description": "Synthetic finding",
    "event_refs": ["event-1"],
    "artifact_refs": ["artifact-1"],
}


@pytest.mark.parametrize(
    "model,data",
    [
        (ToolDescriptor, TOOL),
        (PolicyRequest, REQUEST),
        (PolicyDecision, DECISION),
        (ApprovalRequest, APPROVAL),
        (ApprovalDecision, APPROVED),
        (NormalizedAction, ACTION),
        (Delegation, DELEGATION),
        (DataArtifactRef, ARTIFACT),
        (Finding, FINDING),
    ],
)
def test_domain_roundtrip_and_unknown_fields(model, data):
    instance = validate_data(model, data)
    assert validate_data(model, json.loads(canonical_json(instance))) == instance
    with pytest.raises(ArtifactValidationError) as caught:
        validate_data(model, {**data, "unknown": True})
    assert caught.value.issues[0].code == ErrorCode.UNKNOWN_FIELD
    if issubclass(model, VersionedModel):
        with pytest.raises(ArtifactValidationError) as caught:
            validate_data(model, {**data, "schema_version": "2.0"})
        assert caught.value.issues[0].code == ErrorCode.UNSUPPORTED_SCHEMA_VERSION


@pytest.mark.parametrize("identifier", ["", " space", "hidden\n", "x" * 129, "a b", "a\u200bb"])
def test_invalid_principal_id(identifier):
    with pytest.raises(ArtifactValidationError):
        validate_data(PrincipalRef, {**PRINCIPAL, "principal_id": identifier})


def test_principal_enum_and_scope_semantics():
    ref = validate_data(PrincipalRef, PRINCIPAL)
    assert ref.principal_type is PrincipalType.AGENT
    assert ref.model_dump(mode="json")["principal_type"] == "AGENT"
    scope = validate_data(TaskScope, {"task_id": "t", "description": "A requested task"})
    assert scope.requested_capabilities is None
    assert "permissions" not in PrincipalRef.model_fields
    assert "grant" not in TaskScope.model_fields
    assert get_type_hints(PolicyEngine.decide)["request"] is PolicyRequest


def test_policy_request_environment_matches_agent_and_roundtrips():
    matching = deepcopy(REQUEST)
    matching["agent"]["environment"] = matching["environment"] = "development"
    request = validate_data(PolicyRequest, matching)
    assert request == validate_data(PolicyRequest, json.loads(canonical_json(request)))

    mismatched = {**matching, "environment": "production"}
    with pytest.raises(ArtifactValidationError) as caught:
        validate_data(PolicyRequest, mismatched)
    assert caught.value.issues[0].code == ErrorCode.INVALID_SCHEMA
    assert caught.value.issues[0].path == "environment"


@pytest.mark.parametrize("value", ["agent", False, 1])
def test_enum_not_coerced(value):
    with pytest.raises(ArtifactValidationError):
        validate_data(PrincipalRef, {**PRINCIPAL, "principal_type": value})


def test_frozen_models():
    principal = validate_data(PrincipalRef, PRINCIPAL)
    with pytest.raises(ValidationError):
        principal.principal_id = "changed"


@pytest.mark.parametrize(
    "model,data,start,end",
    [
        (Delegation, DELEGATION, "issued_at", "expires_at"),
        (ApprovalRequest, APPROVAL, "created_at", "expires_at"),
    ],
)
@pytest.mark.parametrize("expiry", [STAMP, "2026-10-15T11:59:59Z"])
def test_timestamp_ranges(model, data, start, end, expiry):
    with pytest.raises(ArtifactValidationError) as caught:
        validate_data(model, {**data, start: STAMP, end: expiry})
    assert caught.value.issues[0].code == ErrorCode.INVALID_TIMESTAMP_RANGE


@pytest.mark.parametrize("value", ["2026-10-15T12:00:00", 0, "not-a-date"])
def test_timezone_required(value):
    with pytest.raises(ArtifactValidationError):
        validate_data(Delegation, {**DELEGATION, "issued_at": value})


def test_timezone_normalization():
    a = validate_data(Delegation, DELEGATION)
    b = validate_data(Delegation, {**DELEGATION, "issued_at": "2026-10-15T05:00:00-07:00"})
    assert canonical_json(a) == canonical_json(b)
    assert a.issued_at == datetime(2026, 10, 15, 12, tzinfo=UTC)


@pytest.mark.parametrize(
    "changes",
    [
        {"capabilities": []},
        {"destructive": True},
        {"destructive": "false"},
        {"idempotent": "false"},
        {"input_schema": {"type": "bogus"}},
        {"input_schema": {"required": "name"}},
        {"output_schema": {"properties": False}},
        {"input_schema": []},
        {"capabilities": ["bad capability"]},
        {"input_schema": {"minimum": float("inf")}},
    ],
)
def test_tool_rejections(changes):
    with pytest.raises(ArtifactValidationError):
        validate_data(ToolDescriptor, {**TOOL, **changes})


def test_tool_destructive_and_hash_semantics():
    a = validate_data(ToolDescriptor, TOOL)
    b = validate_data(ToolDescriptor, {**TOOL, "description": "Changed description"})
    assert a.tool_id == b.tool_id
    assert a.description_hash != b.description_hash
    assert a.schema_hash == b.schema_hash
    changed = validate_data(ToolDescriptor, {**TOOL, "input_schema": {"type": "string"}})
    assert a.schema_hash != changed.schema_hash
    assert schema_digest({"type": "object", "required": ["a"]}) == schema_digest(
        {"required": ["a"], "type": "object"}
    )
    assert description_digest("a") != description_digest("b")
    assert validate_data(
        ToolDescriptor, {**TOOL, "side_effect_class": "DESTRUCTIVE", "destructive": True}
    ).destructive
    for side_effect_class in ("CODE_EXECUTION", "INFRASTRUCTURE"):
        assert not validate_data(
            ToolDescriptor,
            {**TOOL, "side_effect_class": side_effect_class, "destructive": False},
        ).destructive
        assert validate_data(
            ToolDescriptor,
            {**TOOL, "side_effect_class": side_effect_class, "destructive": True},
        ).destructive
    with pytest.raises(ArtifactValidationError) as caught:
        validate_data(
            ToolDescriptor,
            {**TOOL, "side_effect_class": "DESTRUCTIVE", "destructive": False},
        )
    assert caught.value.issues[0].code == ErrorCode.INVALID_TOOL_SCHEMA
    assert caught.value.issues[0].path == "destructive"
    with pytest.raises(ArtifactValidationError):
        validate_data(ToolDescriptor, {**TOOL, "side_effect_class": "DESTRUCTIVE"})
    with pytest.raises(ArtifactValidationError):
        validate_data(ToolDescriptor, {**TOOL, "description_hash": HASH})


@pytest.mark.parametrize(
    "field,value",
    [
        ("principal", {"principal_id": "user:other", "principal_type": "USER"}),
        ("agent_id", "other"),
        ("environment", "production"),
        ("delegation_id", "delegation-other"),
        ("task_id", "task-other"),
        ("tool_id", "other-tool"),
        ("capability", "ticket.update"),
        ("resource", "other-resource"),
        ("arguments", {"to": "other@example.invalid", "body": "hello"}),
        ("tool_schema_hash", "sha256:" + "b" * 64),
        ("tool_description_hash", "sha256:" + "c" * 64),
        ("effective_policy_hash", "sha256:" + "d" * 64),
    ],
)
def test_approval_binds_every_action_component(field, value):
    a = validate_data(NormalizedAction, ACTION)
    b = validate_data(NormalizedAction, {**ACTION, field: value})
    assert action_digest(a) != action_digest(b)


def test_approval_argument_order_and_array_semantics():
    a = validate_data(NormalizedAction, ACTION)
    b = validate_data(
        NormalizedAction, {**ACTION, "arguments": dict(reversed(list(ACTION["arguments"].items())))}
    )
    assert action_digest(a) == action_digest(b)
    c = validate_data(NormalizedAction, {**ACTION, "arguments": {"values": [1, 2]}})
    d = validate_data(NormalizedAction, {**ACTION, "arguments": {"values": [2, 1]}})
    assert action_digest(c) != action_digest(d)


def test_approval_requires_request_reference_and_complete_arguments():
    data = deepcopy(APPROVAL)
    del data["policy_request_id"]
    with pytest.raises(ArtifactValidationError):
        validate_data(ApprovalRequest, data)
    data = deepcopy(ACTION)
    del data["arguments"]
    with pytest.raises(ArtifactValidationError):
        validate_data(NormalizedAction, data)
    with pytest.raises(ArtifactValidationError):
        validate_data(ApprovalDecision, {**APPROVED, "scope": "SESSION"})


def test_policy_decision_requires_explanation():
    with pytest.raises(ArtifactValidationError):
        validate_data(PolicyDecision, {**DECISION, "reason_codes": []})
    with pytest.raises(ArtifactValidationError):
        validate_data(PolicyDecision, {**DECISION, "outcome": "maybe"})


def test_severity_ordering_and_content_free_evidence():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    finding = validate_data(Finding, FINDING)
    assert finding.severity == Severity.HIGH
    assert finding.model_dump(mode="json")["severity"] == 3
    artifact = validate_data(DataArtifactRef, ARTIFACT)
    assert artifact.parent_artifact_ids == frozenset({"parent-1"})
    assert "content" not in DataArtifactRef.model_fields
    assert artifact.artifact_id != artifact.content_hash


def test_agent_context_not_credentials():
    assert "api_key" not in AgentIdentity.model_fields
    assert get_type_hints(AgentIdentity)["trust_level"] == str | None
    assert get_type_hints(AgentIdentity)["trust_level"] != TrustClass | None
    assert (
        AgentIdentity(
            agent_id="agent-1",
            name="Agent",
            environment="development",
            trust_level="tier:reviewed",
        ).trust_level
        == "tier:reviewed"
    )


def test_evidence_port_uses_canonical_event():
    from agentsec.domain.events import SecurityEvent
    from agentsec.evidence.ports import EventSink

    assert get_type_hints(EventSink.append)["event"] is SecurityEvent


@pytest.mark.parametrize(
    "enum_name",
    [
        "PrincipalType",
        "PolicyOutcome",
        "RuleDecision",
        "EnforcementMode",
        "SideEffectClass",
        "TrustClass",
        "DataLabel",
        "SecurityCategory",
        "EventType",
        "ReasonCode",
        "ApprovalOutcome",
        "ApprovalScope",
        "Severity",
    ],
)
def test_taxonomy_wire_values(enum_name):
    from pydantic import TypeAdapter

    from agentsec.domain import taxonomy

    enum_type = getattr(taxonomy, enum_name)
    adapter = TypeAdapter(enum_type)
    for member in enum_type:
        assert adapter.validate_json(json.dumps(member.value), strict=True) is member
        assert adapter.dump_json(member) == json.dumps(member.value).encode()
    with pytest.raises(ValidationError):
        adapter.validate_json('"UNKNOWN_VALUE"', strict=True)
