"""MCP ingress translation; all authority lives in the protocol-independent runtime."""

import asyncio
from types import MappingProxyType
from typing import cast

from mcp import Client, types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from pydantic import JsonValue

from agentsec.adapters.mcp.config import McpGatewayConfig
from agentsec.adapters.mcp.coverage import discovered_resource_coverage
from agentsec.adapters.mcp.discovery import DiscoveredTool, discover, trust_route
from agentsec.adapters.mcp.normalize import validate_arguments
from agentsec.adapters.mcp.upstream import dispatch, list_all_tools
from agentsec.domain.taxonomy import EnforcementMode, SecurityCategory
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure, ToolResponse


def safe_error(code: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=code)], is_error=True)


class McpRequestIdentityGuard:
    """Reject a second tools/call using the same JSON-RPC identity in one session."""

    def __init__(self) -> None:
        self._seen: set[tuple[str, str]] = set()
        self._lock = asyncio.Lock()

    async def claim(self, request_id: str | int | None) -> bool:
        if request_id is None:
            return False
        identity = (type(request_id).__name__, str(request_id))
        async with self._lock:
            if identity in self._seen:
                return False
            self._seen.add(identity)
            return True


async def create_server(
    client: Client, config: McpGatewayConfig, runtime: RuntimeGateway
) -> tuple[Server[None], tuple[str, ...]]:
    config = McpGatewayConfig.model_validate_json(config.model_dump_json())
    if config.mode != runtime.mode:
        raise RuntimeFailure("MODE_MISMATCH")
    discovered, gaps = discover(
        await list_all_tools(client, trust_limits=runtime.trust_enabled),
        config,
        trust_limits=runtime.trust_enabled,
    )
    if runtime.trust_enabled and runtime.mode == EnforcementMode.ENFORCE:
        required = set(runtime.trust_required_candidates)
        observed = {
            runtime.trust_candidate(
                entry.descriptor,
                trust_route(entry, config),
                entry.binding.data_sink_destination if entry.binding else None,
                entry.binding.output_data_labels if entry.binding else None,
            ).candidate_id
            for entry in discovered.values()
        }
        if required - observed:
            raise RuntimeFailure("TRUST_REQUIRED_CANDIDATE_MISSING")
    registry = MappingProxyType(discovered)
    request_ids = McpRequestIdentityGuard()
    enforce = config.mode == EnforcementMode.ENFORCE
    resource_coverage = discovered_resource_coverage(runtime.plan, discovered)
    resource_gaps = resource_coverage.gaps
    if enforce and resource_gaps:
        raise RuntimeFailure("UNSUPPORTED_RESOURCE_COVERAGE")
    if gaps:
        runtime.signal(SecurityCategory.SUPPLY_CHAIN_CHANGE, "DISCOVERY_COVERAGE_GAPS")
    for gap in resource_gaps:
        runtime.signal(SecurityCategory.POLICY_BYPASS, "COVERAGE_GAP:" + gap)

    def admitted(entry: DiscoveredTool) -> bool:
        if not runtime.trust_enabled:
            return True
        try:
            runtime.admit_trust(
                runtime.trust_candidate(
                    entry.descriptor,
                    trust_route(entry, config),
                    entry.binding.data_sink_destination if entry.binding else None,
                    entry.binding.output_data_labels if entry.binding else None,
                )
            )
            return True
        except RuntimeFailure:
            return False

    # Strict registration rejects a partial inventory rather than exposing unknown tools.
    if enforce and any(not admitted(entry) for entry in registry.values()):
        raise RuntimeFailure("TRUST_ADMISSION_REJECTED")

    async def list_tools(
        context: ServerRequestContext[None], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                entry.wire
                for entry in registry.values()
                if (entry.binding is not None or not enforce) and admitted(entry)
            ]
        )

    async def call_tool(
        context: ServerRequestContext[None], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        if context.request_id is not None and not await request_ids.claim(context.request_id):
            runtime.signal(SecurityCategory.TRACE_INTEGRITY_FAILURE, "DUPLICATE_REQUEST_ID")
            return safe_error("DUPLICATE_REQUEST_ID")
        entry = registry.get(params.name)
        if entry is None:
            runtime.signal(SecurityCategory.UNAUTHORIZED_TOOL_USE, "UNKNOWN_TOOL")
            return safe_error("UNKNOWN_TOOL")
        try:
            arguments = cast(dict[str, JsonValue], params.arguments or {})
            try:
                resource = validate_arguments(
                    entry.descriptor,
                    arguments,
                    entry.binding.resource_argument_path if entry.binding else None,
                )
            except RuntimeFailure:
                runtime.signal(SecurityCategory.ARGUMENT_VIOLATION, "INVALID_ARGUMENTS")
                raise

            async def forward(values: dict[str, JsonValue]) -> ToolResponse:
                return await dispatch(client, params.name, values)

            response = await runtime.call(
                entry.descriptor,
                arguments,
                resource,
                forward,
                bound=entry.binding is not None,
                execution_binding=trust_route(entry, config) if runtime.trust_enabled else None,
                approval_display_paths=(
                    entry.binding.approval_display_paths if entry.binding is not None else ()
                ),
                approval_display_resource=(
                    entry.binding.approval_display_resource if entry.binding is not None else False
                ),
                resource_coverage_gap=(
                    params.name in resource_coverage.uncovered_tool_names
                    and params.name not in resource_coverage.data_uncovered_tool_names
                ),
                data_coverage_gap=params.name in resource_coverage.data_uncovered_tool_names,
                data_destination=(entry.binding.data_sink_destination if entry.binding else None),
                output_data_labels=(entry.binding.output_data_labels if entry.binding else None),
            )
            return types.CallToolResult.model_validate(response.body)
        except RuntimeFailure as exc:
            return safe_error(exc.code)
        except Exception:
            # Never let an SDK exception dump raw arguments/response data to the host.
            return safe_error("GATEWAY_FAILURE")

    server: Server[None] = Server(
        config.gateway_id, on_list_tools=list_tools, on_call_tool=call_tool
    )
    return server, tuple(sorted((*gaps, *resource_gaps)))


async def serve_stdio(server: Server[None]) -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())
