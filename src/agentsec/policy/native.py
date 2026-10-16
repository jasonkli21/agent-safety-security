"""Exact-match policy; runtime and protocols supply no implicit grants."""

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from agentsec.compiler import CompiledSecurityPlan, compile_contract
from agentsec.compiler.models import AgentBinding
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.taxonomy import PolicyOutcome, ReasonCode, RuleDecision


class NativePolicyEngine:
    def __init__(self, clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.clock = clock

    def decide(
        self, request: PolicyRequest, contract: CompiledSecurityPlan | AgentSecurityContract
    ) -> PolicyDecision:
        if isinstance(contract, AgentSecurityContract):
            contract = compile_contract(contract)
        outcome = PolicyOutcome.DENY
        reason = ReasonCode.DEFAULT_DENY
        matched: frozenset[str] = frozenset()
        scope = contract.task_scope
        if (
            request.principal != contract.principal
            or AgentBinding.from_identity(request.agent) != contract.agent
            or request.environment != contract.environment
            or not contract.matches_scope(request.task_scope)
            or request.delegation_id is not None
            or request.tool_id is None
        ):
            reason = ReasonCode.INVALID_REQUEST
        elif scope is not None and (
            (
                scope.requested_capabilities is not None
                and request.capability not in scope.requested_capabilities
            )
            or (
                scope.resource_scopes is not None
                and request.capability in scope.resource_scopes
                and request.resource not in scope.resource_scopes[request.capability]
            )
        ):
            reason = ReasonCode.OUTSIDE_TASK_SCOPE
        else:
            rules = tuple(
                r
                for r in contract.rules
                if r.capability == request.capability
                and (r.resource is None or r.resource == request.resource)
            )
            matched = frozenset(r.rule_id for r in rules)
            for decision, code in (
                (RuleDecision.DENY, ReasonCode.EXPLICIT_DENY),
                (RuleDecision.REQUIRE_APPROVAL, ReasonCode.APPROVAL_REQUIRED),
                (RuleDecision.ALLOW, ReasonCode.EXPLICIT_ALLOW),
            ):
                if any(r.decision == decision for r in rules):
                    outcome, reason = PolicyOutcome(decision.value), code
                    break
        return PolicyDecision(
            schema_version="0.1",
            decision_id=str(uuid4()),
            request_id=request.request_id,
            outcome=outcome,
            matched_rule_ids=matched,
            reason_codes=frozenset({reason}),
            contract_id=contract.contract_id,
            effective_policy_hash=contract.effective_policy_hash,
            decided_at=self.clock(),
        )
