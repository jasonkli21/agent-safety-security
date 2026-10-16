"""MCP-aware checks for policy inputs that must come from tool arguments."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from agentsec.adapters.mcp.config import ToolBinding
from agentsec.adapters.mcp.discovery import DiscoveredTool
from agentsec.contracts.models import AgentSecurityContract


@dataclass(frozen=True)
class ResourceCoverage:
    gaps: tuple[str, ...]
    uncovered_tool_names: frozenset[str]


def configured_resource_coverage_gaps(
    contract: AgentSecurityContract, bindings: Iterable[ToolBinding]
) -> tuple[str, ...]:
    """Check configured bindings for resource-dependent policy, before discovery."""
    return _binding_coverage(
        contract,
        ((binding.upstream_name, binding.capability, binding) for binding in bindings),
    ).gaps


def discovered_resource_coverage_gaps(
    contract: AgentSecurityContract, registry: Mapping[str, DiscoveredTool]
) -> tuple[str, ...]:
    """Check active discovered tools after their immutable bindings are resolved."""
    return discovered_resource_coverage(contract, registry).gaps


def discovered_resource_coverage(
    contract: AgentSecurityContract, registry: Mapping[str, DiscoveredTool]
) -> ResourceCoverage:
    """Return exact gaps and the bound tools whose policy input is incomplete."""
    gaps: list[str] = []
    uncovered_names: set[str] = set()
    bindings: list[tuple[str, str, ToolBinding]] = []
    for name, entry in registry.items():
        binding = entry.binding
        if binding is None:
            continue
        if binding.capability not in entry.descriptor.capabilities:
            gaps.append(f"binding_capability:{name}")
            uncovered_names.add(name)
            continue
        bindings.append((name, binding.capability, binding))
    binding_coverage = _binding_coverage(contract, bindings)
    gaps.extend(binding_coverage.gaps)
    uncovered_names.update(binding_coverage.uncovered_tool_names)
    return ResourceCoverage(tuple(sorted(set(gaps))), frozenset(uncovered_names))


def _binding_coverage(
    contract: AgentSecurityContract,
    bindings: Iterable[tuple[str, str, ToolBinding]],
) -> ResourceCoverage:
    resource_rule_capabilities = {
        rule.capability
        for rule in (contract.tools.rules if contract.tools else ())
        if rule.resource is not None
    }
    task_resource_capabilities = (
        set(contract.task_scope.resource_scopes)
        if contract.task_scope is not None and contract.task_scope.resource_scopes is not None
        else set()
    )
    required_capabilities = resource_rule_capabilities | task_resource_capabilities

    canonical_resource_capabilities = _canonical_resource_capabilities(contract)

    gaps: list[str] = []
    uncovered_names: set[str] = set()
    for name, capability, binding in bindings:
        if capability not in required_capabilities:
            continue
        if binding.resource_argument_path is None:
            gaps.append(f"resource_extractor:{capability}:{name}")
            uncovered_names.add(name)
        elif (
            capability in canonical_resource_capabilities
            and binding.resource_semantics != "opaque_exact"
        ):
            gaps.append(f"resource_semantics:{capability}:{name}:opaque_exact_required")
            uncovered_names.add(name)
    return ResourceCoverage(tuple(sorted(set(gaps))), frozenset(uncovered_names))


def _canonical_resource_capabilities(contract: AgentSecurityContract) -> set[str]:
    general_allow = {
        rule.capability
        for rule in (contract.tools.rules if contract.tools else ())
        if rule.resource is None and rule.decision.value == "ALLOW"
    }
    stricter_resource_exceptions = {
        rule.capability
        for rule in (contract.tools.rules if contract.tools else ())
        if rule.resource is not None and rule.decision.value in {"DENY", "REQUIRE_APPROVAL"}
    }
    return general_allow & stricter_resource_exceptions
