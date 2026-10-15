"""Strict wire primitives. JSON parsing accepts wire enums, arrays, and ISO dates only."""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints

Identifier = Annotated[
    str, StringConstraints(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.:/-]*$")
]
CapabilityId = Annotated[
    str,
    StringConstraints(
        min_length=3, max_length=128, pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
    ),
]
Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
NonEmpty = Annotated[str, StringConstraints(min_length=1, max_length=8192)]
Count = Annotated[int, Field(ge=0)]
Timeout = Annotated[int, Field(gt=0)]
Timestamp = AwareDatetime


class SecurityModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False, validate_default=True
    )


class VersionedModel(SecurityModel):
    schema_version: Literal["0.1"]
