"""Explicit document and policy projections; rule ordering has no semantics in v0.1."""

from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.serialization import canonical_json, content_digest


def document_projection(contract: AgentSecurityContract) -> dict[str, object]:
    data = contract.model_dump(mode="python", round_trip=True)
    data["tools"]["rules"] = sorted(data["tools"]["rules"], key=lambda r: r["rule_id"])
    data["data"]["rules"] = sorted(data["data"]["rules"], key=lambda r: r["rule_id"])
    data["invariants"] = sorted(data["invariants"], key=lambda r: r["id"])
    return data


def policy_projection(contract: AgentSecurityContract) -> dict[str, object]:
    """Explicit security field allowlist. New fields need a deliberate projection decision."""
    return {
        "schema_version": contract.schema_version,
        "agent": {
            "agent_id": contract.agent.agent_id,
            "environment": contract.agent.environment,
            "owner": contract.agent.owner,
            "trust_level": contract.agent.trust_level,
        },
        "identity": contract.identity,
        "task_scope": None
        if contract.task_scope is None
        else {
            "task_id": contract.task_scope.task_id,
            "requested_capabilities": contract.task_scope.requested_capabilities,
            "resource_scopes": contract.task_scope.resource_scopes,
        },
        "tools": sorted(contract.tools.rules, key=lambda r: r.rule_id),
        "data": sorted(contract.data.rules, key=lambda r: r.rule_id),
        "budgets": contract.budgets,
        "approvals": contract.approvals,
        # Invariants are declarative intent; prose is preserved conservatively.
        "invariants": sorted(contract.invariants, key=lambda i: i.id),
        "environment": contract.environment,
    }


def canonical_contract(contract: AgentSecurityContract) -> str:
    return canonical_json(document_projection(contract))


def document_hash(contract: AgentSecurityContract) -> str:
    return content_digest(document_projection(contract))


def effective_policy_hash(contract: AgentSecurityContract) -> str:
    return content_digest(policy_projection(contract))
