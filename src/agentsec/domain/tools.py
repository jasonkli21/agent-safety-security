"""Stable tool identity with separately derived metadata fingerprints."""

from typing import Self

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import (
    ConfigDict,
    JsonValue,
    ValidationInfo,
    computed_field,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from agentsec.domain.base import CapabilityId, Identifier, NonEmpty, VersionedModel
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import DataLabel, SecurityCategory, SideEffectClass


def schema_digest(
    input_schema: dict[str, JsonValue], output_schema: dict[str, JsonValue] | None = None
) -> str:
    return content_digest({"input_schema": input_schema, "output_schema": output_schema})


def description_digest(description: str) -> str:
    return content_digest(description)


class ToolDescriptor(VersionedModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "side_effect_class": {"const": SideEffectClass.DESTRUCTIVE.value}
                        },
                        "required": ["side_effect_class"],
                    },
                    "then": {
                        "properties": {"destructive": {"const": True}},
                        "required": ["destructive"],
                    },
                }
            ]
        }
    )

    tool_id: Identifier
    namespace: Identifier
    name: NonEmpty
    protocol: Identifier
    server_id: Identifier | None = None
    version: Identifier | None = None
    description: str
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue] | None = None
    side_effect_class: SideEffectClass
    risk_tags: frozenset[SecurityCategory] = frozenset()
    data_access_labels: frozenset[DataLabel] = frozenset()
    destructive: bool = False
    idempotent: bool | None = None
    capabilities: frozenset[CapabilityId]

    @field_validator("destructive")
    @classmethod
    def destructive_class_requires_flag(cls, value: bool, info: ValidationInfo) -> bool:
        side_effect_class = info.data.get("side_effect_class")
        if side_effect_class is SideEffectClass.DESTRUCTIVE and not value:
            raise PydanticCustomError(
                "INVALID_TOOL_SCHEMA", "DESTRUCTIVE side-effect class requires destructive=true"
            )
        return value

    @model_validator(mode="after")
    def valid_metadata(self) -> Self:
        if not self.capabilities:
            raise PydanticCustomError("INVALID_CAPABILITY", "Tool requires a capability")
        if self.destructive and self.side_effect_class not in {
            SideEffectClass.DESTRUCTIVE,
            SideEffectClass.CODE_EXECUTION,
            SideEffectClass.INFRASTRUCTURE,
        }:
            raise PydanticCustomError("INVALID_TOOL_SCHEMA", "Incompatible destructive class")
        for schema in (self.input_schema, self.output_schema):
            if schema is not None:
                try:
                    Draft202012Validator.check_schema(schema)
                except SchemaError as exc:
                    raise PydanticCustomError("INVALID_TOOL_SCHEMA", "Invalid JSON Schema") from exc
        return self

    # Derived values cannot be supplied by authors; round trips omit computed fields.
    @computed_field  # type: ignore[prop-decorator]
    @property
    def description_hash(self) -> str:
        return description_digest(self.description)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def schema_hash(self) -> str:
        return schema_digest(self.input_schema, self.output_schema)
