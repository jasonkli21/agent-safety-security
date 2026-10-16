"""Configured unsupported intent cannot claim enforcement."""

from agentsec.contracts.models import AgentSecurityContract


def coverage_gaps(contract: AgentSecurityContract) -> tuple[str, ...]:
    gaps = []
    if contract.data.rules:
        gaps.append("data.rules")
    if contract.invariants:
        gaps.append("invariants")
    if contract.identity.acts_on_behalf_of is not None:
        gaps.append("identity.acts_on_behalf_of")
    for name in ("max_model_calls", "max_cost_usd", "max_delegated_agents"):
        if getattr(contract.budgets, name) is not None:
            gaps.append(f"budgets.{name}")
    return tuple(gaps)
