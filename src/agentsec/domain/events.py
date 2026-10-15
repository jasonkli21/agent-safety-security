"""Typed factual evidence; per-run ordering does not establish authorization correctness."""

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, model_validator
from pydantic_core import PydanticCustomError

from agentsec.contracts.errors import ErrorCode, fail
from agentsec.domain.approvals import ApprovalDecision, ApprovalRequest
from agentsec.domain.base import (
    Count,
    Digest,
    Identifier,
    NonEmpty,
    SecurityModel,
    Timestamp,
    VersionedModel,
)
from agentsec.domain.identity import PrincipalRef
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.provenance import DataArtifactRef
from agentsec.domain.taxonomy import DataLabel, EventType, ReasonCode, SecurityCategory, Severity


class RunStartedPayload(SecurityModel):
    kind: Literal[EventType.RUN_STARTED]
    contract_id: Identifier
    effective_policy_hash: Digest
    scenario_id: Identifier | None = None


class RunFinishedPayload(SecurityModel):
    kind: Literal[EventType.RUN_FINISHED]
    output_artifact_refs: frozenset[Identifier] = frozenset()


class ToolRequestedPayload(SecurityModel):
    kind: Literal[EventType.TOOL_REQUESTED]
    request: PolicyRequest
    action_digest: Digest


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
    kind: Literal[EventType.TOOL_DISPATCHED]
    dispatch_id: Identifier
    request_id: Identifier
    tool_id: Identifier
    action_digest: Digest
    decision_id: Identifier
    approval_id: Identifier | None = None


class ToolReturnedPayload(SecurityModel):
    kind: Literal[EventType.TOOL_RETURNED]
    dispatch_id: Identifier
    request_id: Identifier
    tool_id: Identifier
    success: bool
    artifacts: tuple[DataArtifactRef, ...] = ()
    response_hash: Digest | None = None


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
