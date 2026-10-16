"""Strict operational wiring; bindings classify tools and never grant authority."""

from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from agentsec.domain.base import (
    CapabilityId,
    Digest,
    Identifier,
    NonEmpty,
    SecurityModel,
    VersionedModel,
)
from agentsec.domain.identity import Delegation
from agentsec.domain.taxonomy import DataLabel, EnforcementMode, SecurityCategory, SideEffectClass
from agentsec.identity.config import IdentityConfig


class StdioUpstream(SecurityModel):
    transport: Literal["stdio"]
    command: NonEmpty
    args: tuple[str, ...] = ()
    cwd: NonEmpty | None = None
    env: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def safe_argv(self) -> Self:
        values = [self.command, *self.args, *(self.env.keys()), *(self.env.values())]
        if self.cwd is not None:
            values.append(self.cwd)
        if any("\x00" in v for v in values) or any(not k or "=" in k for k in self.env):
            raise ValueError("Invalid process configuration")
        return self


class HttpUpstream(SecurityModel):
    transport: Literal["streamable_http"]
    url: NonEmpty

    @field_validator("url")
    @classmethod
    def http_url(cls, value: str) -> str:
        url = urlsplit(value)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.fragment
            or any(ord(c) < 33 for c in value)
        ):
            raise ValueError("Expected HTTP(S) endpoint without embedded credentials or fragment")
        return value


class ToolBinding(SecurityModel):
    upstream_name: NonEmpty
    capability: CapabilityId
    side_effect_class: SideEffectClass
    destructive: bool = False
    data_access_labels: frozenset[DataLabel] = frozenset()
    output_data_labels: frozenset[DataLabel] | None = None
    data_sink_destination: Identifier | None = None
    risk_tags: frozenset[SecurityCategory] = frozenset()
    resource_argument_path: tuple[NonEmpty, ...] | None = None
    resource_semantics: Literal["opaque_exact"] | None = None
    approval_display_paths: tuple[tuple[NonEmpty, ...], ...] = ()
    expected_schema_hash: Digest | None = None
    expected_description_hash: Digest | None = None

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.resource_argument_path == ():
            raise ValueError("Resource path must contain a key")
        if self.resource_semantics is not None and self.resource_argument_path is None:
            raise ValueError("Resource semantics require a resource argument path")
        if any(not path for path in self.approval_display_paths):
            raise ValueError("Approval display paths must contain a key")
        if len(set(self.approval_display_paths)) != len(self.approval_display_paths):
            raise ValueError("Duplicate approval display path")
        if self.side_effect_class == SideEffectClass.DESTRUCTIVE and not self.destructive:
            raise ValueError("Destructive class requires flag")
        if self.destructive and self.side_effect_class not in {
            SideEffectClass.DESTRUCTIVE,
            SideEffectClass.CODE_EXECUTION,
            SideEffectClass.INFRASTRUCTURE,
        }:
            raise ValueError("Incompatible destructive classification")
        return self


class McpGatewayConfig(VersionedModel):
    gateway_id: Identifier
    server_id: Identifier
    mode: EnforcementMode = EnforcementMode.ENFORCE
    upstream: Annotated[StdioUpstream | HttpUpstream, Field(discriminator="transport")]
    tool_bindings: tuple[ToolBinding, ...] = ()
    identity: IdentityConfig | None = None
    delegation: Delegation | None = None

    @model_validator(mode="after")
    def unique_bindings(self) -> Self:
        names = [b.upstream_name for b in self.tool_bindings]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate tool binding")
        return self
