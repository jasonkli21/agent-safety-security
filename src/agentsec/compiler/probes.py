"""Declarative obligations: this module never calls the native evaluator for expectations."""

from dataclasses import dataclass
from datetime import UTC, datetime

from agentsec.compiler.models import CompiledSecurityPlan
from agentsec.domain.policy import PolicyRequest
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import PolicyOutcome, ReasonCode


@dataclass(frozen=True)
class PolicyProbe:
    probe_id: str
    capability: str
    resource: str | None
    expected: PolicyOutcome
    reason: ReasonCode
    atom_ids: tuple[str, ...]

    def request(self, plan: CompiledSecurityPlan) -> PolicyRequest:
        return PolicyRequest(
            schema_version="0.1",
            request_id=self.probe_id,
            principal=plan.principal,
            agent=plan.agent,
            environment=plan.environment,
            task_scope=plan.task_scope,
            tool_id="conformance-tool",
            capability=self.capability,
            resource=self.resource,
            requested_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


def sentinel(values: set[str], prefix: str) -> str:
    candidate = prefix
    index = 0
    while candidate in values:
        index += 1
        candidate = f"{prefix}_{index}"
    return candidate


def partition(*plans: CompiledSecurityPlan) -> tuple[tuple[str, str | None], ...]:
    """Finite exact-match equivalence classes, including scope-only and unknown space."""
    capabilities = {r.capability for p in plans for r in p.rules}
    for plan in plans:
        if plan.scope:
            capabilities.update(plan.scope.requested_capabilities or ())
            capabilities.update(r.capability for r in plan.scope.resources or ())
    unknown = sentinel(capabilities, "conformance.unknown")
    rows: list[tuple[str, str | None]] = []
    for capability in sorted(capabilities | {unknown}):
        resources = {
            r.resource
            for p in plans
            for r in p.rules
            if r.capability == capability and r.resource is not None
        }
        for plan in plans:
            if plan.scope:
                for ceiling in plan.scope.resources or ():
                    if ceiling.capability == capability:
                        resources.update(ceiling.resources)
        rows.extend(
            (capability, resource)
            for resource in (None, *sorted(resources), sentinel(resources, "conformance-other"))
        )
    return tuple(rows)


def obligation(
    plan: CompiledSecurityPlan, capability: str, resource: str | None
) -> tuple[PolicyOutcome, ReasonCode]:
    """Small independent oracle: ceiling plus explicit deny/approval/allow obligations.

    No PolicyDecision or evaluator result is an input. Precedence is an explicit table.
    """
    scope = plan.scope
    if scope is not None:
        outside_capability = (
            scope.requested_capabilities is not None
            and capability not in scope.requested_capabilities
        )
        outside_resource = any(
            c.capability == capability and resource not in c.resources
            for c in scope.resources or ()
        )
        if outside_capability or outside_resource:
            return PolicyOutcome.DENY, ReasonCode.OUTSIDE_TASK_SCOPE
    decisions = {
        r.decision.value
        for r in plan.rules
        if r.capability == capability and (r.resource is None or r.resource == resource)
    }
    table = (
        ("DENY", PolicyOutcome.DENY, ReasonCode.EXPLICIT_DENY),
        ("REQUIRE_APPROVAL", PolicyOutcome.REQUIRE_APPROVAL, ReasonCode.APPROVAL_REQUIRED),
        ("ALLOW", PolicyOutcome.ALLOW, ReasonCode.EXPLICIT_ALLOW),
    )
    for name, outcome, reason in table:
        if name in decisions:
            return outcome, reason
    return PolicyOutcome.DENY, ReasonCode.DEFAULT_DENY


def generate_probes(plan: CompiledSecurityPlan) -> tuple[PolicyProbe, ...]:
    probes = []
    for capability, resource in partition(plan):
        outcome, reason = obligation(plan, capability, resource)
        atoms = ["identity"]
        if plan.scope:
            atoms.append("task_scope")
        if reason == ReasonCode.DEFAULT_DENY:
            atoms.append("tools.default_deny")
        if reason != ReasonCode.OUTSIDE_TASK_SCOPE:
            atoms.extend(
                f"tools.rules/{r.rule_id}"
                for r in plan.rules
                if r.capability == capability and (r.resource is None or r.resource == resource)
            )
        probes.append(
            PolicyProbe(
                probe_id="probe-" + content_digest((capability, resource)).split(":")[1][:24],
                capability=capability,
                resource=resource,
                expected=outcome,
                reason=reason,
                atom_ids=tuple(sorted(atoms)),
            )
        )
    return tuple(probes)
