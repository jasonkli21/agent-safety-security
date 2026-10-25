"""MCP-aware checks for policy inputs that must come from tool arguments."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING

from agentsec.adapters.mcp.config import ToolBinding
from agentsec.compiler import CompiledSecurityPlan
from agentsec.compiler.reporting import AdapterAtomProof, AdapterProof
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import DataLabel
from agentsec.runtime.coverage import ResourceCoverage
from agentsec.runtime.coverage import binding_coverage as _binding_coverage

if TYPE_CHECKING:
    from agentsec.adapters.mcp.discovery import DiscoveredTool


def configured_resource_coverage_gaps(
    contract: AgentSecurityContract | CompiledSecurityPlan, bindings: Iterable[ToolBinding]
) -> tuple[str, ...]:
    """Check configured bindings for resource-dependent policy, before discovery."""
    return _binding_coverage(
        contract,
        ((binding.upstream_name, binding.capability, binding) for binding in bindings),
    ).gaps


def discovered_resource_coverage_gaps(
    contract: AgentSecurityContract | CompiledSecurityPlan, registry: Mapping[str, DiscoveredTool]
) -> tuple[str, ...]:
    """Check active discovered tools after their immutable bindings are resolved."""
    return discovered_resource_coverage(contract, registry).gaps


def discovered_resource_coverage(
    contract: AgentSecurityContract | CompiledSecurityPlan, registry: Mapping[str, DiscoveredTool]
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
    return ResourceCoverage(
        tuple(sorted(set(gaps))),
        frozenset(uncovered_names),
        binding_coverage.data_uncovered_tool_names,
    )


def discovery_snapshot_digest(registry: Mapping[str, DiscoveredTool]) -> str:
    return content_digest(
        {
            name: (entry.wire_json, entry.descriptor_json, entry.binding)
            for name, entry in sorted(registry.items())
        }
    )


def semantic_adapter_proof(
    plan: CompiledSecurityPlan, registry: Mapping[str, DiscoveredTool]
) -> AdapterProof:
    """Project discovery/binding proof to atoms; absent applicable tools remain unproven."""
    coverage = discovered_resource_coverage(plan, registry)
    proof: dict[str, AdapterAtomProof] = {}
    for atom in plan.atoms:
        if not atom.adapter_required:
            continue
        if atom.source_ref.startswith("data.rules/"):
            # Classification completeness and exact per-rule runtime witnesses are separate.
            if registry:
                rule = next(
                    r for r in plan.data_rules if atom.source_ref == f"data.rules/{r.rule_id}"
                )
                bindings = [entry.binding for entry in registry.values()]
                source_ok = all(
                    b is not None
                    and (
                        rule.label in {DataLabel.TOOL_OUTPUT, DataLabel.UNTRUSTED_CONTENT}
                        or b.output_data_labels is not None
                    )
                    for b in bindings
                )
                sink_ok = all(
                    b is not None
                    and (
                        not (rule.allowed_destinations or rule.denied_destinations)
                        or b.data_sink_destination is not None
                    )
                    for b in bindings
                )
                source_reachable = any(
                    b is not None
                    and (
                        rule.label in {DataLabel.TOOL_OUTPUT, DataLabel.UNTRUSTED_CONTENT}
                        or rule.label in (b.output_data_labels or ())
                    )
                    for b in bindings
                )
                sink_reachable = not (rule.allowed_destinations or rule.denied_destinations) or any(
                    b is not None
                    and b.data_sink_destination
                    in (rule.allowed_destinations | rule.denied_destinations)
                    for b in bindings
                )
                proof[atom.atom_id] = AdapterAtomProof(
                    atom_id=atom.atom_id,
                    covered=source_ok
                    and sink_ok
                    and source_reachable
                    and sink_reachable
                    and all(
                        entry.binding is not None
                        and entry.binding.capability in entry.descriptor.capabilities
                        for entry in registry.values()
                    ),
                    source_classification_covered=source_ok,
                    sink_classification_covered=sink_ok,
                    source_runtime_reachable=source_reachable,
                    sink_runtime_reachable=sink_reachable,
                )
            continue
        if atom.source_ref == "task_scope":
            capabilities = (
                {r.capability for r in plan.scope.resources or ()} if plan.scope else set()
            )
        else:
            capabilities = {
                r.capability for r in plan.rules if atom.source_ref == f"tools.rules/{r.rule_id}"
            }
        applicable = {
            name for name, entry in registry.items() if entry.descriptor.capabilities & capabilities
        }
        if applicable:
            proof[atom.atom_id] = AdapterAtomProof(
                atom_id=atom.atom_id,
                covered=all(
                    registry[name].binding is not None and name not in coverage.uncovered_tool_names
                    for name in applicable
                ),
            )
    return AdapterProof(
        schema_version="0.1",
        plan_identity=plan.identity,
        discovery_snapshot_digest=discovery_snapshot_digest(registry),
        atoms=tuple(v for _, v in sorted(proof.items())),
    )
