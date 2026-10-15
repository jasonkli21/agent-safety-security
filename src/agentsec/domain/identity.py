"""Identity and requested scope never grant authority by themselves."""

from typing import Self

from pydantic import model_validator
from pydantic_core import PydanticCustomError

from agentsec.domain.base import (
    CapabilityId,
    Identifier,
    NonEmpty,
    SecurityModel,
    Timestamp,
    VersionedModel,
)
from agentsec.domain.taxonomy import PrincipalType


class PrincipalRef(SecurityModel):
    principal_id: Identifier
    principal_type: PrincipalType


class AgentIdentity(SecurityModel):
    agent_id: Identifier
    name: NonEmpty
    environment: Identifier
    owner: PrincipalRef | None = None
    trust_level: Identifier | None = None
    framework: Identifier | None = None
    model_provider: Identifier | None = None
    model_name: Identifier | None = None


class TaskScope(SecurityModel):
    task_id: Identifier
    description: NonEmpty
    requested_capabilities: frozenset[CapabilityId] | None = None
    resource_scopes: dict[CapabilityId, frozenset[NonEmpty]] | None = None


class Delegation(VersionedModel):
    delegation_id: Identifier
    delegator: PrincipalRef
    delegate: PrincipalRef
    task_scope: TaskScope
    capability_scope: frozenset[CapabilityId]
    issued_at: Timestamp
    expires_at: Timestamp | None = None
    parent_delegation_id: Identifier | None = None

    @model_validator(mode="after")
    def valid_window(self) -> Self:
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise PydanticCustomError("INVALID_TIMESTAMP_RANGE", "Expiry must follow issue time")
        return self
