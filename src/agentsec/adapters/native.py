"""Async native callables, explicitly classified by protected configuration."""

from collections.abc import Awaitable, Callable

from pydantic import JsonValue, TypeAdapter, ValidationError

from agentsec.domain.execution import ExecutionBinding
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.runtime.bindings import ProtectedCall, ProtectedTool
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure, ToolResponse

_JSON = TypeAdapter(JsonValue)


def protect_native(
    gateway: RuntimeGateway,
    tool: ProtectedTool,
    function: Callable[[dict[str, JsonValue]], Awaitable[ToolResponse | JsonValue]],
) -> ProtectedCall:
    """The operator supplies a binding revision identifying the callable implementation."""

    async def dispatch(arguments: dict[str, JsonValue]) -> ToolResponse:
        value = await function(arguments)
        if isinstance(value, ToolResponse):
            return value
        try:
            value = _JSON.validate_python(value, strict=True)
            canonical_json(value)
        except (ValidationError, ValueError, TypeError, RecursionError) as exc:
            raise RuntimeFailure("UNSUPPORTED_NATIVE_RETURN") from exc
        return ToolResponse(body={"result": value}, structured=value, success=True)

    return ProtectedCall(gateway, tool, dispatch)


def native_binding(adapter_id: str, implementation_revision: str) -> ExecutionBinding:
    return ExecutionBinding(
        schema_version="0.1",
        adapter_kind="native",
        adapter_id=adapter_id,
        binding_digest=content_digest(implementation_revision),
    )
