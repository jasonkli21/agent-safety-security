"""Exact-match policy; runtime and protocols supply no implicit grants."""

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from agentsec.compiler import CompiledSecurityPlan, compile_contract
from agentsec.compiler.models import AgentBinding
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.taxonomy import PolicyOutcome, ReasonCode, RuleDecision
from agentsec.identity.authority import authority_failure


class NativePolicyEngine:
    def __init__(
        self,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        id_factory: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        self.clock = clock
        self.id_factory = id_factory

    def decide(
        self, request: PolicyRequest, contract: CompiledSecurityPlan | AgentSecurityContract
    ) -> PolicyDecision:
        if isinstance(contract, AgentSecurityContract):
            contract = compile_contract(contract)
        outcome = PolicyOutcome.DENY
        reason = ReasonCode.DEFAULT_DENY
        matched: frozenset[str] = frozenset()
        scope = contract.task_scope
        failure = None
        if contract.compiler_version == "phase6-v1":
            failure = authority_failure(
                request.authority,
                contract.principal,
                contract.acts_on_behalf_of,
                scope,
                self.clock(),
                capability=request.capability,
                resource=request.resource,
            )
        grant = request.authority.delegation if request.authority else None
        if (
            request.principal != contract.principal
            or AgentBinding.from_identity(request.agent) != contract.agent
            or request.environment != contract.environment
            or not contract.matches_scope(request.task_scope)
            or (request.delegation_id != (grant.delegation_id if grant else None))
            or (contract.compiler_version == "phase4-v1" and request.authority is not None)
            or request.tool_id is None
        ):
            reason = ReasonCode.INVALID_REQUEST
        elif failure is not None:
            reason = failure
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
        if outcome in {PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL}:
            labels = {label for ref in request.data_artifact_refs for label in ref.labels}
            applicable = tuple(r for r in contract.data_rules if r.label in labels)
            matched |= frozenset(r.rule_id for r in applicable)
            blocked = any(
                request.capability in r.denied_capabilities
                or (r.allowed_capabilities and request.capability not in r.allowed_capabilities)
                or (
                    request.data_destination is not None
                    and (
                        request.data_destination in r.denied_destinations
                        or (
                            r.allowed_destinations
                            and request.data_destination not in r.allowed_destinations
                        )
                    )
                )
                for r in applicable
            )
            missing = request.data_destination is None and any(
                r.allowed_destinations or r.denied_destinations for r in applicable
            )
            # Explicit denial wins over missing context, independent of rule ordering.
            if blocked:
                outcome, reason = PolicyOutcome.DENY, ReasonCode.DATA_FLOW_DENIED
            elif missing:
                outcome, reason = PolicyOutcome.ERROR, ReasonCode.DATA_FLOW_CONTEXT_MISSING
        return PolicyDecision(
            schema_version="0.1",
            decision_id=self.id_factory(),
            request_id=request.request_id,
            outcome=outcome,
            matched_rule_ids=matched,
            reason_codes=frozenset({reason}),
            contract_id=contract.contract_id,
            effective_policy_hash=contract.effective_policy_hash,
            decided_at=self.clock(),
        )
