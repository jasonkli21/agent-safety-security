"""Replay-safe verified facts. No bearer tokens or arbitrary external claims."""

from typing import Literal, Self

from pydantic import model_validator

from agentsec.domain.base import (
    CapabilityId,
    Digest,
    Identifier,
    NonEmpty,
    Timestamp,
    VersionedModel,
)
from agentsec.domain.identity import Delegation, PrincipalRef
from agentsec.domain.serialization import content_digest


class VerifiedCredential(VersionedModel):
    principal: PrincipalRef
    assurance: Literal["STATIC_TRUSTED_CONFIG", "SIGNED_JWT"]
    capability_ceiling: frozenset[CapabilityId] | None = None
    valid_from: Timestamp
    expires_at: Timestamp | None = None

    @model_validator(mode="after")
    def window(self) -> Self:
        if self.expires_at is not None and self.expires_at <= self.valid_from:
            raise ValueError("INVALID_CREDENTIAL_WINDOW")
        if self.assurance == "SIGNED_JWT" and self.expires_at is None:
            raise ValueError("FINITE_CREDENTIAL_EXPIRY_REQUIRED")
        return self


class AuthorityContext(VersionedModel):
    credential: VerifiedCredential
    # Canonical JSON freezes Delegation's mutable resource map without parallel semantics.
    delegation_json: NonEmpty | None = None

    @model_validator(mode="after")
    def canonical_grant(self) -> Self:
        if self.delegation_json is not None:
            from agentsec.domain.serialization import canonical_json

            grant = Delegation.model_validate_json(self.delegation_json)
            if canonical_json(grant) != self.delegation_json:
                raise ValueError("NONCANONICAL_DELEGATION")
        return self

    @property
    def delegation(self) -> Delegation | None:
        return (
            Delegation.model_validate_json(self.delegation_json) if self.delegation_json else None
        )

    @property
    def authority_digest(self) -> str:
        return content_digest(self)

    @property
    def expires_at(self) -> Timestamp | None:
        grant = self.delegation
        dates = [d for d in (self.credential.expires_at, grant.expires_at if grant else None) if d]
        return min(dates) if dates else None


class AuthoritySummary(VersionedModel):
    actor: PrincipalRef | None = None
    assurance: Literal["STATIC_TRUSTED_CONFIG", "SIGNED_JWT"] | None = None
    acts_on_behalf_of: PrincipalRef | None = None
    delegation_id: Identifier | None = None
    delegation_digest: Digest | None = None
    authority_digest: Digest | None = None
    expires_at: Timestamp | None = None
    error: Identifier | None = None
    enforcement_enabled: bool
