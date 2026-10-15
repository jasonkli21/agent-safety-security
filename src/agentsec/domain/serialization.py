"""Project canonical JSON: ordered maps/sets, ordered arrays, explicit nulls/defaults."""

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import cast

from pydantic import BaseModel, JsonValue


def normalize(value: object) -> JsonValue:
    if isinstance(value, BaseModel):
        return normalize(value.model_dump(mode="python", round_trip=True))
    if isinstance(value, Enum):
        return normalize(value.value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, (set, frozenset)):
        return sorted((normalize(v) for v in value), key=canonical_json)
    if isinstance(value, (list, tuple)):
        return [normalize(v) for v in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return cast(JsonValue, value)
    raise TypeError(f"Unsupported canonical value: {type(value).__name__}")


def canonical_json(value: object) -> str:
    return json.dumps(
        normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def content_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
