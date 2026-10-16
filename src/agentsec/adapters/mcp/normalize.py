"""Strict input validation and exact opaque resource extraction."""

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as SchemaValidationError
from pydantic import JsonValue

from agentsec.domain.serialization import canonical_json
from agentsec.domain.tools import ToolDescriptor
from agentsec.runtime.models import RuntimeFailure


def validate_arguments(
    tool: ToolDescriptor, arguments: dict[str, JsonValue], path: tuple[str, ...] | None
) -> str | None:
    try:
        canonical_json(arguments)  # Reject NaN and non-JSON values before hashing/dispatch.
        Draft202012Validator(tool.input_schema).validate(arguments)
        resource: JsonValue = arguments
        if path is not None:
            for key in path:
                if not isinstance(resource, dict) or key not in resource:
                    raise RuntimeFailure("INVALID_RESOURCE")
                resource = resource[key]
            if not isinstance(resource, str) or not 0 < len(resource) <= 8192:
                raise RuntimeFailure("INVALID_RESOURCE")
            return resource
        return None
    except (SchemaValidationError, ValueError, TypeError, RecursionError) as exc:
        raise RuntimeFailure("INVALID_ARGUMENTS") from exc
