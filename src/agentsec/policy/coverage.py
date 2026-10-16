"""Compatibility projection of the compiler's explicit unsupported inventory."""

from agentsec.compiler import CompiledSecurityPlan, compile_contract
from agentsec.contracts.models import AgentSecurityContract


def coverage_gaps(contract: AgentSecurityContract | CompiledSecurityPlan) -> tuple[str, ...]:
    plan = compile_contract(contract) if isinstance(contract, AgentSecurityContract) else contract
    gaps = {g.split("/")[0] for g in plan.gaps}
    order = (
        "data.rules",
        "invariants",
        "identity.acts_on_behalf_of",
        "budgets.max_model_calls",
        "budgets.max_cost_usd",
        "budgets.max_delegated_agents",
    )
    return tuple(g for g in order if g in gaps)
