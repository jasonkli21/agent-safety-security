"""Session metadata is stored as canonical JSON, never aliased mutable SDK objects."""

from dataclasses import dataclass

from mcp import types

from agentsec.adapters.mcp.config import McpGatewayConfig, ToolBinding
from agentsec.contracts.loader import validate_data
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.domain.taxonomy import EnforcementMode, SideEffectClass
from agentsec.domain.tools import ToolDescriptor
from agentsec.runtime.models import RuntimeFailure


def check_local_schema(value: object) -> None:
    """No implicit network/file resolution of upstream-controlled schemas."""
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                key in {"$ref", "$dynamicRef"}
                and isinstance(child, str)
                and not child.startswith("#")
            ):
                raise RuntimeFailure("UNSUPPORTED_SCHEMA_REFERENCE")
            check_local_schema(child)
    elif isinstance(value, list):
        for child in value:
            check_local_schema(child)


@dataclass(frozen=True)
class DiscoveredTool:
    wire_json: str
    descriptor_json: str
    binding: ToolBinding | None

    @property
    def descriptor(self) -> ToolDescriptor:
        return ToolDescriptor.model_validate_json(self.descriptor_json)

    @property
    def wire(self) -> types.Tool:
        return types.Tool.model_validate_json(self.wire_json)


def discover(
    tools: list[types.Tool], config: McpGatewayConfig
) -> tuple[dict[str, DiscoveredTool], tuple[str, ...]]:
    registry: dict[str, DiscoveredTool] = {}
    bindings = {b.upstream_name: b for b in config.tool_bindings}
    gaps = []
    for tool in tools:
        if tool.name in registry:
            raise RuntimeFailure("DUPLICATE_TOOL")
        check_local_schema(tool.input_schema)
        check_local_schema(tool.output_schema)
        binding = bindings.get(tool.name)
        descriptor = validate_data(
            ToolDescriptor,
            {
                "schema_version": "0.1",
                "tool_id": "mcp-" + content_digest([config.server_id, tool.name])[7:39],
                "namespace": config.gateway_id,
                "name": tool.name,
                "protocol": "mcp",
                "server_id": config.server_id,
                "description": tool.description or "",
                "input_schema": tool.input_schema,
                "output_schema": tool.output_schema,
                "capabilities": [binding.capability if binding else "mcp.unbound"],
                "side_effect_class": binding.side_effect_class if binding else SideEffectClass.NONE,
                "destructive": binding.destructive if binding else False,
                "risk_tags": sorted(binding.risk_tags) if binding else [],
                "data_access_labels": sorted(binding.data_access_labels) if binding else [],
            },
        )
        if binding is None:
            gaps.append("unbound_tool:" + descriptor.tool_id)
        elif (
            binding.expected_schema_hash is not None
            and binding.expected_schema_hash != descriptor.schema_hash
        ) or (
            binding.expected_description_hash is not None
            and binding.expected_description_hash != descriptor.description_hash
        ):
            gaps.append("metadata_pin:" + descriptor.tool_id)
            if config.mode == EnforcementMode.ENFORCE:
                raise RuntimeFailure("TOOL_METADATA_MISMATCH")
        registry[tool.name] = DiscoveredTool(
            tool.model_dump_json(by_alias=True), canonical_json(descriptor), binding
        )
    if bindings.keys() - registry.keys():
        if config.mode == EnforcementMode.ENFORCE:
            raise RuntimeFailure("STALE_TOOL_BINDING")
        gaps.append("stale_tool_binding")
    return registry, tuple(gaps)
