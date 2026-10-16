"""Protocol-independent authorization inputs and explainable decisions."""

from typing import Annotated

from pydantic import (
    Field,
    JsonValue,
    SerializerFunctionWrapHandler,
    ValidationInfo,
    field_validator,
    model_serializer,
)
from pydantic_core import PydanticCustomError

from agentsec.domain.authority import AuthorityContext
from agentsec.domain.base import (
    CapabilityId,
    Digest,
    Identifier,
    NonEmpty,
    Timestamp,
    VersionedModel,
)
from agentsec.domain.identity import AgentIdentity, PrincipalRef, TaskScope
from agentsec.domain.provenance import DataArtifactRef, canonical_artifacts
from agentsec.domain.taxonomy import PolicyOutcome, ReasonCode


class PolicyRequest(VersionedModel):
    authority: AuthorityContext | None = None
    request_id: Identifier
    principal: PrincipalRef
    agent: AgentIdentity
    task_scope: TaskScope | None = None
    delegation_id: Identifier | None = None
    capability: CapabilityId
    tool_id: Identifier | None = None
    resource: NonEmpty | None = None
    arguments_summary: dict[str, JsonValue] | None = None
    data_artifact_refs: tuple[DataArtifactRef, ...] = ()
    data_destination: Identifier | None = None

    _canonical_artifacts = field_validator("data_artifact_refs")(canonical_artifacts)

    trajectory_ref: Identifier | None = None
    environment: Identifier
    requested_at: Timestamp

    @field_validator("environment")
    @classmethod
    def environment_matches_agent(cls, value: str, info: ValidationInfo) -> str:
        agent = info.data.get("agent")
        if isinstance(agent, AgentIdentity) and value != agent.environment:
            raise PydanticCustomError("INVALID_SCHEMA", "Request and agent environments differ")
        return value

    @model_serializer(mode="wrap")
    def compatible_wire(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        data: dict[str, object] = handler(self)
        if self.authority is None:
            data.pop("authority", None)
        return data


class PolicyDecision(VersionedModel):
    decision_id: Identifier
    request_id: Identifier
    outcome: PolicyOutcome
    matched_rule_ids: frozenset[Identifier] = frozenset()
    reason_codes: Annotated[frozenset[ReasonCode], Field(min_length=1)]
    human_reason: NonEmpty | None = None
    contract_id: Identifier
    effective_policy_hash: Digest
    decided_at: Timestamp
