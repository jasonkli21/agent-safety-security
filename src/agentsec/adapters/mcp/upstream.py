"""Official SDK connections and typed one-attempt forwarding; no framing code."""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp import Client, types
from mcp.client.stdio import DEFAULT_INHERITED_ENV_VARS, StdioServerParameters, stdio_client
from pydantic import JsonValue

from agentsec.adapters.mcp.config import HttpUpstream, StdioUpstream
from agentsec.contracts.loader import validate_data
from agentsec.runtime.models import RuntimeFailure, ToolResponse


def process_parameters(config: StdioUpstream) -> StdioServerParameters:
    # SDK always merges its safe default environment. Override every inherited value.
    env = {name: "" for name in DEFAULT_INHERITED_ENV_VARS}
    env.update(config.env)
    return StdioServerParameters(
        command=config.command, args=list(config.args), cwd=config.cwd, env=env
    )


@asynccontextmanager
async def connect(config: StdioUpstream | HttpUpstream) -> AsyncIterator[Client]:
    if isinstance(config, StdioUpstream):
        with open(os.devnull, "w") as errlog:
            async with Client(
                stdio_client(process_parameters(config), errlog=errlog), mode="legacy"
            ) as client:
                yield client
    else:
        async with Client(config.url, mode="legacy") as client:
            yield client


async def list_all_tools(client: Client, *, trust_limits: bool = False) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor: str | None = None
    seen: set[str] = set()
    total_bytes = 0
    max_pages = 128 if trust_limits else 1000
    max_tools = 2048
    max_bytes = 8 * 1024 * 1024
    for _ in range(max_pages):
        page = await client.list_tools(cursor=cursor, cache_mode="bypass")
        if trust_limits:
            # Apply cumulative ceilings before retaining the next page. The SDK has already
            # decoded this one page, so its transport-level body limit remains SDK-owned.
            page_bytes = sum(len(tool.model_dump_json().encode("utf-8")) for tool in page.tools)
            if len(tools) + len(page.tools) > max_tools or total_bytes + page_bytes > max_bytes:
                raise RuntimeFailure("TRUST_DISCOVERY_LIMIT_EXCEEDED")
            total_bytes += page_bytes
        tools.extend(page.tools)
        cursor = page.next_cursor
        if cursor is None:
            return tools
        if cursor in seen:
            break
        seen.add(cursor)
    raise RuntimeFailure(
        "TRUST_DISCOVERY_LIMIT_EXCEEDED" if trust_limits else "INVALID_TOOL_PAGINATION"
    )


async def dispatch(client: Client, name: str, arguments: dict[str, JsonValue]) -> ToolResponse:
    # Bypass Client.call_tool's retry/metadata refresh and output validation. Runtime owns
    # validation so it can hash invalid returns and truthfully forward them in SHADOW.
    result = await client.session.send_request(
        types.CallToolRequest(params=types.CallToolRequestParams(name=name, arguments=arguments)),
        types.CallToolResult,
    )
    return validate_data(
        ToolResponse,
        {
            "body": result.model_dump(mode="json", by_alias=True),
            "success": not result.is_error,
            "structured": result.structured_content,
        },
    )
