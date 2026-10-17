"""Optional async StructuredTool boundary, also consumable by LangGraph ToolNode."""

from typing import TYPE_CHECKING

from pydantic import JsonValue

from agentsec.runtime.bindings import ProtectedCall

if TYPE_CHECKING:
    from langchain_core.tools import StructuredTool


def as_langchain_tool(call: ProtectedCall) -> "StructuredTool":
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
