"""Finite native-policy comparison, not general formal equivalence or activation."""

from agentsec.compiler.models import CompiledSecurityPlan
from agentsec.compiler.probes import PolicyProbe, partition
from agentsec.domain.base import VersionedModel
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import PolicyOutcome, ReasonCode
from agentsec.policy.native import NativePolicyEngine


class SemanticChange(VersionedModel):
    kind: str
    source_ref: str
    capability: str | None = None
    representative_digest: str | None = None
    old_outcome: PolicyOutcome | None = None
    new_outcome: PolicyOutcome | None = None


class SemanticDiff(VersionedModel):
    old_effective_policy_hash: str
    new_effective_policy_hash: str
    comparison: str = "finite exact-match policy partition; unsupported intent is not compared"
    representatives: int
    changes: tuple[SemanticChange, ...]


def semantic_diff(old: CompiledSecurityPlan, new: CompiledSecurityPlan) -> SemanticDiff:
    changes: list[SemanticChange] = []

    def change(kind: str, ref: str) -> None:
        changes.append(SemanticChange(schema_version="0.1", kind=kind, source_ref=ref))

    rank = {PolicyOutcome.DENY: 0, PolicyOutcome.REQUIRE_APPROVAL: 1, PolicyOutcome.ALLOW: 2}
    engine = NativePolicyEngine()
    rows = partition(old, new)
    for capability, resource in rows:
        probe = PolicyProbe(
            "diff-request", capability, resource, PolicyOutcome.DENY, ReasonCode.DEFAULT_DENY, ()
        )
        before = engine.decide(probe.request(old), old)
        after = engine.decide(probe.request(new), new)
        if before.outcome != after.outcome:
            kinds = [
                "authority_expansion"
                if rank[after.outcome] > rank[before.outcome]
                else "authority_reduction"
            ]
            if PolicyOutcome.REQUIRE_APPROVAL in (before.outcome, after.outcome):
                kinds.append("approval_boundary")
            for kind in kinds:
                changes.append(
                    SemanticChange(
                        schema_version="0.1",
                        kind=kind,
                        source_ref="tools/task_scope",
                        capability=capability,
                        representative_digest=content_digest((capability, resource)),
                        old_outcome=before.outcome,
                        new_outcome=after.outcome,
                    )
                )
        before_outside = ReasonCode.OUTSIDE_TASK_SCOPE in before.reason_codes
        after_outside = ReasonCode.OUTSIDE_TASK_SCOPE in after.reason_codes
        if before_outside != after_outside:
            changes.append(
                SemanticChange(
                    schema_version="0.1",
                    kind="task_scope_widening" if before_outside else "task_scope_narrowing",
                    source_ref="task_scope",
                    capability=capability,
                    representative_digest=content_digest((capability, resource)),
                )
            )
    for name in type(old.budgets).model_fields:
        a, b = getattr(old.budgets, name), getattr(new.budgets, name)
        if a != b:
            relaxed = b is None or (a is not None and b > a)
            change("budget_relaxation" if relaxed else "budget_tightening", f"budgets.{name}")
    if old.approvals != new.approvals:
        change("approval_timeout_change", "approvals.default_timeout_seconds")
    if (old.principal, old.agent, old.environment) != (new.principal, new.agent, new.environment):
        change("identity_environment_change", "identity/agent/environment")
    if old.scope != new.scope:
        change("task_scope_configuration_change", "task_scope")
    unsupported_old = {a.atom_id: a.intent_digest for a in old.atoms if not a.compiled}
    unsupported_new = {a.atom_id: a.intent_digest for a in new.atoms if not a.compiled}
    for ref in sorted(unsupported_old.keys() | unsupported_new.keys()):
        if unsupported_old.get(ref) != unsupported_new.get(ref):
            change("unsupported_change", ref)
    return SemanticDiff(
        schema_version="0.1",
        old_effective_policy_hash=old.effective_policy_hash,
        new_effective_policy_hash=new.effective_policy_hash,
        representatives=len(rows),
        changes=tuple(changes),
    )
