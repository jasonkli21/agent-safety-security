"""Protected operational mappings. No credentials belong in this configuration."""

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from agentsec.domain.base import CapabilityId, Identifier, NonEmpty, SecurityModel
from agentsec.domain.identity import PrincipalRef


class StaticIdentityConfig(SecurityModel):
    provider: Literal["static"]
    principal: PrincipalRef
    capability_ceiling: frozenset[CapabilityId] | None = None


class SubjectMapping(SecurityModel):
    subject: NonEmpty
    principal: PrincipalRef


class JwtKey(SecurityModel):
    kid: Identifier
    algorithm: Literal["RS256", "ES256", "EdDSA"]
    public_key_pem: NonEmpty


class JwtIdentityConfig(SecurityModel):
    provider: Literal["signed_jwt"]
    issuer: NonEmpty
    audience: NonEmpty
    keys: Annotated[tuple[JwtKey, ...], Field(min_length=1)]
    subjects: Annotated[tuple[SubjectMapping, ...], Field(min_length=1)]
    scope_mapping: dict[NonEmpty, CapabilityId] | None = None
    clock_skew_seconds: Annotated[int, Field(ge=0, le=60)] = 0

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len({k.kid for k in self.keys}) != len(self.keys):
            raise ValueError("DUPLICATE_KEY_ID")
        if len({s.subject for s in self.subjects}) != len(self.subjects):
            raise ValueError("DUPLICATE_SUBJECT_MAPPING")
        if any("PRIVATE" in k.public_key_pem for k in self.keys):
            raise ValueError("PUBLIC_KEYS_ONLY")
        return self


IdentityConfig = Annotated[
    StaticIdentityConfig | JwtIdentityConfig, Field(discriminator="provider")
]
