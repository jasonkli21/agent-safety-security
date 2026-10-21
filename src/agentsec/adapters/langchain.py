"""Optional async StructuredTool boundary, also consumable by LangGraph ToolNode."""

from typing import TYPE_CHECKING

from pydantic import JsonValue

from agentsec.runtime.bindings import ProtectedCall

if TYPE_CHECKING:
    from langchain_core.tools import StructuredTool


def as_langchain_tool(call: ProtectedCall) -> "StructuredTool":
    """Wrap protected dispatch; framework callbacks and tracing remain separate effects.

    LangChain may notify configured callbacks before this coroutine reaches the gateway.
    Callers must apply a separate egress policy to callbacks and tracing that can see raw
    tool inputs, outputs, or errors.
    """
    from langchain_core.tools import StructuredTool

    call = call.for_adapter("langchain")
    descriptor = call.tool.descriptor

    async def invoke(**arguments: JsonValue) -> dict[str, JsonValue]:
        response = await call.invoke(arguments)
        return {"success": response.success, "result": response.body}

    return StructuredTool.from_function(
        coroutine=invoke,
        name=descriptor.name,
        description=descriptor.description,
        args_schema=descriptor.input_schema,
        infer_schema=False,
    )
