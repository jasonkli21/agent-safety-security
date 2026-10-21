"""Shared adapter input coverage; no protocol discovery or policy engine."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from agentsec.compiler import CompiledSecurityPlan, compile_contract
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.taxonomy import DataLabel


class BindingMetadata(Protocol):
    @property
    def output_data_labels(self) -> frozenset[DataLabel] | None: ...
    @property
    def data_sink_destination(self) -> str | None: ...
    @property
    def resource_argument_path(self) -> tuple[str, ...] | None: ...
    @property
    def resource_semantics(self) -> str | None: ...


@dataclass(frozen=True)
class ResourceCoverage:
    gaps: tuple[str, ...]
    uncovered_tool_names: frozenset[str]
    data_uncovered_tool_names: frozenset[str] = frozenset()
    resource_scoped_capabilities: frozenset[str] = frozenset()


def binding_coverage(
    contract: AgentSecurityContract | CompiledSecurityPlan,
    bindings: Iterable[tuple[str, str, BindingMetadata]],
) -> ResourceCoverage:
    if isinstance(contract, AgentSecurityContract):
        contract = compile_contract(contract)
    resource_rule_capabilities = {
        rule.capability for rule in contract.rules if rule.resource is not None
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
    data_uncovered: set[str] = set()
    reviewed_sources = any(
        r.label not in {DataLabel.TOOL_OUTPUT, DataLabel.UNTRUSTED_CONTENT}
        for r in contract.data_rules
    )
    destinations = any(r.allowed_destinations or r.denied_destinations for r in contract.data_rules)
    for name, capability, binding in bindings:
        if reviewed_sources and binding.output_data_labels is None:
            gaps.append(f"data_source_classification:{name}")
            data_uncovered.add(name)
        if destinations and binding.data_sink_destination is None:
            gaps.append(f"data_sink_destination:{name}")
            data_uncovered.add(name)
        if capability not in required_capabilities:
            continue
        if (
            binding.resource_argument_path is None
            and getattr(binding, "trusted_effect_resource", None) is None
        ):
            gaps.append(f"resource_extractor:{capability}:{name}")
            uncovered_names.add(name)
        elif (
            binding.resource_argument_path is not None
            and capability in canonical_resource_capabilities
            and binding.resource_semantics != "opaque_exact"
        ):
            gaps.append(f"resource_semantics:{capability}:{name}:opaque_exact_required")
            uncovered_names.add(name)
    return ResourceCoverage(
        tuple(sorted(set(gaps))),
        frozenset(uncovered_names | data_uncovered),
        frozenset(data_uncovered),
        frozenset(required_capabilities),
    )


def _canonical_resource_capabilities(
    contract: AgentSecurityContract | CompiledSecurityPlan,
) -> set[str]:
    if isinstance(contract, AgentSecurityContract):
        contract = compile_contract(contract)
    general_allow = {
        rule.capability
        for rule in contract.rules
        if rule.resource is None and rule.decision.value == "ALLOW"
    }
    stricter_resource_exceptions = {
        rule.capability
        for rule in contract.rules
        if rule.resource is not None and rule.decision.value in {"DENY", "REQUIRE_APPROVAL"}
    }
    return general_allow & stricter_resource_exceptions
