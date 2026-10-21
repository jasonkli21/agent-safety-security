"""Observation builders shared by offline inspection and protected runtime wiring."""

from typing import TYPE_CHECKING

from agentsec.domain.serialization import content_digest
from agentsec.supply_chain.inspection import observe
from agentsec.supply_chain.models import Candidate, Inventory

if TYPE_CHECKING:
    from mcp.types import ListToolsResult

    from agentsec.adapters.mcp.config import McpGatewayConfig
    from agentsec.runtime.bindings import ProtectedTool


def inspect_protected(tool: "ProtectedTool", *, finalized: bool = False) -> Candidate:
    route = tool.execution_binding
    if not finalized:
        route = route.model_copy(update={"binding_digest": content_digest(tool)})
    return observe(
        tool.descriptor,
        route,
        classification={
            "destination": tool.data_sink_destination,
            "labels": tool.output_data_labels,
        },
        labels_complete=tool.output_data_labels is not None
        and (
            tool.descriptor.side_effect_class.value not in {"EXTERNAL_WRITE", "NETWORK"}
            or tool.data_sink_destination is not None
        ),
    )


def inspect_mcp(config: "McpGatewayConfig", listing: "ListToolsResult") -> Inventory:
    from agentsec.adapters.mcp.discovery import discover, trust_route
    from agentsec.runtime.models import RuntimeFailure

    if listing.next_cursor is not None:
        raise RuntimeFailure("TRUST_DISCOVERY_INCOMPLETE")
    entries, _ = discover(listing.tools, config, trust_limits=True)
    return Inventory(
        schema_version="0.1",
        candidates=tuple(
            observe(
                entry.descriptor,
                trust_route(entry, config),
                classification={
                    "destination": entry.binding.data_sink_destination if entry.binding else None,
                    "labels": entry.binding.output_data_labels if entry.binding else None,
                },
                labels_complete=bool(
                    entry.binding
                    and entry.binding.output_data_labels is not None
                    and (
                        entry.binding.side_effect_class.value != "EXTERNAL_WRITE"
                        or entry.binding.data_sink_destination is not None
                    )
                ),
            )
            for entry in entries.values()
        ),
    )
