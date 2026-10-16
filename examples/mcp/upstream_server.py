"""Synthetic MCP tools: no actual search, email, or filesystem effects."""

import asyncio

from mcp import types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

TOOLS = [
    types.Tool(
        name="search",
        description="Return a synthetic search result.",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
        },
    ),
    types.Tool(
        name="send_email",
        description="Simulate an email without sending it.",
        input_schema={
            "type": "object",
            "properties": {"recipient": {"type": "string"}, "body": {"type": "string"}},
            "required": ["recipient", "body"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="write_file",
        description="Simulate writing a file without filesystem access.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    ),
]


async def list_tools(
    context: ServerRequestContext[None], params: types.PaginatedRequestParams | None
) -> types.ListToolsResult:
    return types.ListToolsResult(tools=TOOLS)


async def call_tool(
    context: ServerRequestContext[None], params: types.CallToolRequestParams
) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text="synthetic result")],
        structured_content={"ok": True},
    )


async def main() -> None:
    server: Server[None] = Server(
        "synthetic-tools", on_list_tools=list_tools, on_call_tool=call_tool
    )
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
