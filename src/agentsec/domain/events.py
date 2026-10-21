"""Typed factual evidence; per-run ordering does not establish authorization correctness."""

from typing import Annotated, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)
from pydantic_core import PydanticCustomError

from agentsec.compiler.models import PlanIdentity
from agentsec.contracts.errors import ErrorCode, fail
from agentsec.domain.approvals import ApprovalDecision, ApprovalRequest
from agentsec.domain.authority import AuthoritySummary
from agentsec.domain.base import (
    Count,
    Digest,
    Identifier,
    NonEmpty,
    SecurityModel,
    Timestamp,
    VersionedModel,
)
from agentsec.domain.execution import ExecutionBinding
from agentsec.domain.identity import PrincipalRef
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.provenance import DataArtifactRef
from agentsec.domain.taxonomy import (
    DataLabel,
    EnforcementMode,
    EventType,
    ReasonCode,
    SecurityCategory,
    Severity,
)
from agentsec.supply_chain.models import TrustAssessment


class RunStartedPayload(SecurityModel):
    authority_summary: AuthoritySummary | None = None
    kind: Literal[EventType.RUN_STARTED]
    contract_id: Identifier
    effective_policy_hash: Digest
    scenario_id: Identifier | None = None
    plan_identity: PlanIdentity | None = None

    @model_serializer(mode="wrap")
    def compatible_wire(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        data: dict[str, object] = handler(self)
        if self.authority_summary is None:
            data.pop("authority_summary", None)
        return data


class RunFinishedPayload(SecurityModel):
    kind: Literal[EventType.RUN_FINISHED]
    output_artifact_refs: frozenset[Identifier] = frozenset()


class ToolRequestedPayload(SecurityModel):
    kind: Literal[EventType.TOOL_REQUESTED]
    request: PolicyRequest
    trust_assessment: TrustAssessment | None = None
    trust_snapshot_digest: Digest | None = None
    action_digest: Digest
    policy_input_digest: Digest | None = None
    redacted_fields: frozenset[Literal["resource", "task_scope", "authority"]] = frozenset()
    resource_digest: Digest | None = None
    task_scope_digest: Digest | None = None
    authority_digest: Digest | None = None

    @model_serializer(mode="wrap")
    def compatible_wire(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        data: dict[str, object] = handler(self)
        if self.trust_assessment is None:
            data.pop("trust_assessment", None)
        if self.trust_snapshot_digest is None:
            data.pop("trust_snapshot_digest", None)
        if self.authority_digest is None:
            data.pop("authority_digest", None)
        return data

    @model_validator(mode="after")
    def truthful_redaction(self) -> Self:
        if (self.trust_assessment is None) != (self.trust_snapshot_digest is None):
            raise ValueError("TRUST_EVIDENCE_INCOMPLETE")
        if self.redacted_fields and self.policy_input_digest is None:
            raise PydanticCustomError(
                "INVALID_SCHEMA", "Redacted policy inputs must carry a full-input digest"
            )
        if ("resource" in self.redacted_fields) != (self.resource_digest is not None):
            raise PydanticCustomError(
                "INVALID_SCHEMA", "Resource redaction must carry its field digest"
            )
        if ("task_scope" in self.redacted_fields) != (self.task_scope_digest is not None):
            raise PydanticCustomError(
                "INVALID_SCHEMA", "Task-scope redaction must carry its field digest"
            )
        if ("authority" in self.redacted_fields) != (self.authority_digest is not None):
            raise ValueError("AUTHORITY_REDACTION_DIGEST_REQUIRED")
        return self


class PolicyEvaluatedPayload(SecurityModel):
    kind: Literal[EventType.POLICY_EVALUATED]
    decision: PolicyDecision


class ApprovalRequestedPayload(SecurityModel):
    kind: Literal[EventType.APPROVAL_REQUESTED]
    approval: ApprovalRequest


class ApprovalDecidedPayload(SecurityModel):
    kind: Literal[EventType.APPROVAL_DECIDED]
    decision: ApprovalDecision


class ToolDispatchedPayload(SecurityModel):
    trust_assessment: TrustAssessment | None = None
    trust_snapshot_digest: Digest | None = None
    execution_binding: ExecutionBinding | None = None

    @model_serializer(mode="wrap")
    def compatible_wire(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        data: dict[str, object] = handler(self)
        if self.trust_assessment is None:
            data.pop("trust_assessment", None)
        if self.trust_snapshot_digest is None:
            data.pop("trust_snapshot_digest", None)
        if self.execution_binding is None:
            data.pop("execution_binding", None)
        return data

    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"enforcement_mode": {"enum": ["ENFORCE", "SHADOW"]}}},
                    "then": {
                        "required": ["decision_id"],
                        "properties": {"decision_id": {"type": "string"}},
                    },
                    "else": {
                        "properties": {
                            "decision_id": {"type": "null"},
                            "approval_id": {"type": "null"},
                        }
                    },
                }
            ]
        }
    )
    kind: Literal[EventType.TOOL_DISPATCHED]
    dispatch_id: Identifier
    request_id: Identifier
    tool_id: Identifier
    action_digest: Digest
    decision_id: Identifier | None = None
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE
    approval_id: Identifier | None = None

    @model_validator(mode="after")
    def truthful_mode(self) -> Self:
        if (self.trust_assessment is None) != (self.trust_snapshot_digest is None):
            raise ValueError("TRUST_EVIDENCE_INCOMPLETE")
        if (
            self.enforcement_mode == EnforcementMode.ENFORCE
            and self.trust_assessment
            and not self.trust_assessment.admitted
        ):
            raise ValueError("TRUST_EVIDENCE_NOT_ADMITTED")
        if self.enforcement_mode != EnforcementMode.DISABLED and self.decision_id is None:
            raise PydanticCustomError("INVALID_SCHEMA", "Protected dispatch requires decision")
        if self.enforcement_mode == EnforcementMode.DISABLED and (
            self.decision_id is not None or self.approval_id is not None
        ):
            raise PydanticCustomError("INVALID_SCHEMA", "Disabled dispatch has no policy authority")
        return self


class ToolReturnedPayload(SecurityModel):
    kind: Literal[EventType.TOOL_RETURNED]
    dispatch_id: Identifier
    request_id: Identifier
    tool_id: Identifier
    success: bool
    artifacts: tuple[DataArtifactRef, ...] = ()
    response_hash: Digest | None = None


class DataExposedPayload(SecurityModel):
    """A guarded response is committed to release into the protected context."""

    kind: Literal[EventType.DATA_EXPOSED]
    dispatch_id: Identifier
    request_id: Identifier
    tool_id: Identifier
    artifact: DataArtifactRef


class SecuritySignalPayload(SecurityModel):
    kind: Literal[EventType.SECURITY_SIGNAL]
    category: SecurityCategory
    severity: Severity
    artifact_refs: frozenset[Identifier] = frozenset()
    redacted_summary: NonEmpty | None = None


class RunTerminatedPayload(SecurityModel):
    kind: Literal[EventType.RUN_TERMINATED]
    reason: ReasonCode


class EffectVerifiedPayload(SecurityModel):
    kind: Literal[EventType.EFFECT_VERIFIED]
    dispatch_id: Identifier
    request_id: Identifier
    verifier: PrincipalRef
    verified: bool
    evidence_artifact_refs: Annotated[frozenset[Identifier], Field(min_length=1)]


EventPayload = Annotated[
    RunStartedPayload
    | RunFinishedPayload
    | ToolRequestedPayload
    | PolicyEvaluatedPayload
    | ApprovalRequestedPayload
    | ApprovalDecidedPayload
    | ToolDispatchedPayload
    | ToolReturnedPayload
    | DataExposedPayload
    | SecuritySignalPayload
    | RunTerminatedPayload
    | EffectVerifiedPayload,
    Field(discriminator="kind"),
]


class SecurityEvent(VersionedModel):
    model_config = ConfigDict(
        **{
            "json_schema_extra": {
                "allOf": [
                    {
                        "if": {"properties": {"event_type": {"const": event.value}}},
                        "then": {
                            "properties": {
                                "payload": {"properties": {"kind": {"const": event.value}}}
                            }
                        },
                    }
                    for event in EventType
                ]
            }
        }
    )

    event_id: Identifier
    event_type: EventType
    occurred_at: Timestamp
    run_id: Identifier
    trace_id: Identifier
    sequence: Count
    actor: PrincipalRef | None = None
    subject: Identifier | None = None
    payload: EventPayload
    labels: frozenset[DataLabel] = frozenset()

    @model_validator(mode="after")
    def matches_payload(self) -> Self:
        if self.event_type != self.payload.kind:
            raise PydanticCustomError("INVALID_SCHEMA", "Event type and payload kind differ")
        return self


def validate_event_sequence(events: list[SecurityEvent]) -> None:
    """Validate uniqueness and increasing sequences per run, allowing interleaved runs/gaps."""
    last: dict[str, int] = {}
    traces: dict[str, str] = {}
    ids: set[str] = set()
    for index, event in enumerate(events):
        if (
            event.event_id in ids
            or event.sequence <= last.get(event.run_id, -1)
            or (event.run_id in traces and traces[event.run_id] != event.trace_id)
        ):
            fail(
                ErrorCode.INVALID_EVENT_SEQUENCE,
                "Duplicate ID, non-increasing sequence, or changed trace",
                f"events[{index}]",
            )
        ids.add(event.event_id)
        last[event.run_id] = event.sequence
        traces[event.run_id] = event.trace_id
