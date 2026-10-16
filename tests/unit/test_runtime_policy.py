"""Decision table and unsupported enforcement coverage, independent of MCP SDK."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsec.contracts.loader import load_contract, validate_data
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.policy import PolicyRequest
from agentsec.domain.taxonomy import PolicyOutcome, ReasonCode
from agentsec.policy.coverage import coverage_gaps
from agentsec.policy.native import NativePolicyEngine

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 15, tzinfo=UTC)


def contract_with(**updates):
    data = load_contract(ROOT / "examples/mcp/contract.yaml").model_dump(mode="json")
    data.update(updates)
    return validate_data(AgentSecurityContract, data)


def request_for(contract, capability="web.search", resource=None):
    return PolicyRequest(
        schema_version="0.1",
        request_id="request",
        principal=contract.identity.principal,
        agent=contract.agent,
        task_scope=contract.task_scope,
        capability=capability,
        tool_id="tool",
        resource=resource,
        environment=contract.environment.mode,
        requested_at=NOW,
    )


@pytest.mark.parametrize(
    "rules,resource,outcome,reason",
    [
        ([], None, PolicyOutcome.DENY, ReasonCode.DEFAULT_DENY),
        ([("general", "ALLOW", None)], None, PolicyOutcome.ALLOW, ReasonCode.EXPLICIT_ALLOW),
        (
            [("general", "ALLOW", None), ("exact", "DENY", "x")],
            "x",
            PolicyOutcome.DENY,
            ReasonCode.EXPLICIT_DENY,
        ),
        (
            [("general", "REQUIRE_APPROVAL", None), ("exact", "ALLOW", "x")],
            "x",
            PolicyOutcome.REQUIRE_APPROVAL,
            ReasonCode.APPROVAL_REQUIRED,
        ),
        (
            [("general", "DENY", None), ("exact", "REQUIRE_APPROVAL", "x")],
            "x",
            PolicyOutcome.DENY,
            ReasonCode.EXPLICIT_DENY,
        ),
        ([("exact", "ALLOW", "x")], "other", PolicyOutcome.DENY, ReasonCode.DEFAULT_DENY),
    ],
)
def test_policy_table(rules, resource, outcome, reason):
    contract = contract_with(
        tools={
            "rules": [
                {
                    "rule_id": id,
                    "capability": "web.search",
                    "decision": decision,
                    "resource": selector,
                }
                for id, decision, selector in rules
            ]
        }
    )
    decision = NativePolicyEngine(lambda: NOW).decide(
        request_for(contract, resource=resource), contract
    )
    assert decision.outcome == outcome
    assert decision.reason_codes == {reason}
    assert decision.matched_rule_ids == {
        id for id, _, selector in rules if selector in {None, resource}
    }
    assert decision.decided_at == NOW


@pytest.mark.parametrize(
    "capability,resource,reason",
    [
        ("email.send", "demo@example.invalid", ReasonCode.APPROVAL_REQUIRED),
        ("email.send", None, ReasonCode.OUTSIDE_TASK_SCOPE),
        ("email.send", "outside", ReasonCode.OUTSIDE_TASK_SCOPE),
        ("unknown.tool", None, ReasonCode.OUTSIDE_TASK_SCOPE),
        ("filesystem.write", "/tmp/x", ReasonCode.EXPLICIT_DENY),
    ],
)
def test_scope_is_ceiling(capability, resource, reason):
    contract = contract_with()
    assert NativePolicyEngine().decide(
        request_for(contract, capability, resource), contract
    ).reason_codes == {reason}


@pytest.mark.parametrize("change", ["principal", "agent", "task_scope", "tool_id", "delegation_id"])
def test_runtime_consistency(change):
    contract = contract_with()
    request = request_for(contract)
    values = {
        "principal": request.principal.model_copy(update={"principal_id": "other"}),
        "agent": request.agent.model_copy(update={"agent_id": "other"}),
        "task_scope": None,
        "tool_id": None,
        "delegation_id": "unverified",
    }
    decision = NativePolicyEngine().decide(
        request.model_copy(update={change: values[change]}), contract
    )
    assert decision.outcome == PolicyOutcome.DENY
    assert decision.reason_codes == {ReasonCode.INVALID_REQUEST}


def test_coverage_conservative_including_zero():
    assert coverage_gaps(contract_with()) == ()
    contract = contract_with(
        data={"rules": [{"rule_id": "secret", "label": "SECRET"}]},
        invariants=[{"id": "i", "description": "Do not exfiltrate"}],
        budgets={"max_model_calls": 0, "max_cost_usd": 0, "max_delegated_agents": 0},
    )
    assert coverage_gaps(contract) == (
        "invariants",
        "budgets.max_model_calls",
        "budgets.max_cost_usd",
        "budgets.max_delegated_agents",
    )
