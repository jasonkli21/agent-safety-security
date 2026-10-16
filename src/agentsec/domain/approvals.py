"""Exact, complete action binding; approval is neither authorization nor dispatch."""

from typing import Self

from pydantic import JsonValue, field_validator, model_validator
from pydantic_core import PydanticCustomError

from agentsec.domain.base import (
    CapabilityId,
    Digest,
    Identifier,
    NonEmpty,
    Timestamp,
    VersionedModel,
)
from agentsec.domain.identity import PrincipalRef
from agentsec.domain.provenance import DataArtifactRef, canonical_artifacts
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import ApprovalOutcome, ApprovalScope, ReasonCode


class NormalizedAction(VersionedModel):
    """Use complete arguments, never a lossy/redacted PolicyRequest summary."""

    principal: PrincipalRef
    agent_id: Identifier
    environment: Identifier
    delegation_id: Identifier | None = None
    task_id: Identifier | None = None
    capability: CapabilityId
    tool_id: Identifier
    resource: NonEmpty | None = None
    data_destination: Identifier | None = None
    data_artifact_refs: tuple[DataArtifactRef, ...] = ()

    _canonical_artifacts = field_validator("data_artifact_refs")(canonical_artifacts)

    arguments: dict[str, JsonValue]
    tool_schema_hash: Digest
    tool_description_hash: Digest
    effective_policy_hash: Digest


def action_digest(action: NormalizedAction) -> str:
    return content_digest(action)


class ApprovalRequest(VersionedModel):
    approval_id: Identifier
    policy_request_id: Identifier
    action_digest: Digest
    summary: NonEmpty
    reason_codes: frozenset[ReasonCode]
    created_at: Timestamp
    expires_at: Timestamp | None = None

    @model_validator(mode="after")
    def valid_window(self) -> Self:
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise PydanticCustomError("INVALID_TIMESTAMP_RANGE", "Expiry must follow creation")
        return self


class ApprovalDecision(VersionedModel):
    approval_id: Identifier
    approver: PrincipalRef
    outcome: ApprovalOutcome
    scope: ApprovalScope = ApprovalScope.ONE_SHOT
    decided_at: Timestamp
