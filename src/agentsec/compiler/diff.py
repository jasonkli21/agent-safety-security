"""Finite native-policy comparison, not general formal equivalence or activation."""

from agentsec.compiler.models import CompiledSecurityPlan
from agentsec.compiler.probes import (
    PolicyProbe,
    flow_partition,
    partition,
    sentinel,
    synthetic_artifacts,
)
from agentsec.contracts.models import ToolRule
from agentsec.domain.base import VersionedModel
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import PolicyOutcome, ReasonCode, RuleDecision
from agentsec.policy.native import NativePolicyEngine


class SemanticChange(VersionedModel):
    kind: str
    source_ref: str
    capability: str | None = None
    representative_digest: str | None = None
    old_outcome: PolicyOutcome | None = None
    new_outcome: PolicyOutcome | None = None
    old_reason_codes: frozenset[ReasonCode] | None = None
    new_reason_codes: frozenset[ReasonCode] | None = None
    old_matched_rule_ids: frozenset[str] | None = None
    new_matched_rule_ids: frozenset[str] | None = None


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
        if (before.reason_codes, before.matched_rule_ids) != (
            after.reason_codes,
            after.matched_rule_ids,
        ):
            changes.append(
                SemanticChange(
                    schema_version="0.1",
                    kind="policy_explanation_change",
                    source_ref="tools/task_scope",
                    capability=capability,
                    representative_digest=content_digest((capability, resource)),
                    old_outcome=before.outcome,
                    new_outcome=after.outcome,
                    old_reason_codes=before.reason_codes,
                    new_reason_codes=after.reason_codes,
                    old_matched_rule_ids=before.matched_rule_ids,
                    new_matched_rule_ids=after.matched_rule_ids,
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
    old_data = {r.label: r for r in old.data_rules}
    new_data = {r.label: r for r in new.data_rules}
    for label in sorted(old_data.keys() | new_data.keys()):
        a, b = old_data.get(label), new_data.get(label)
        if a is None or b is None:
            rule = b if a is None else a
            assert rule is not None
            change(
                "data_rule_added" if a is None else "data_rule_removed",
                f"data.rules/{rule.rule_id}",
            )
        else:
            for field in (
                "allowed_capabilities",
                "denied_capabilities",
                "allowed_destinations",
                "denied_destinations",
            ):
                if getattr(a, field) != getattr(b, field):
                    change(f"data_{field}_change", f"data.rules/{b.rule_id}")
    base_rule_id = sentinel(
        {r.rule_id for p in (old, new) for r in p.rules}
        | {r.rule_id for p in (old, new) for r in p.data_rules},
        "diff-base",
    )
    flow_rows = flow_partition(old, new)
    for label, capability, destination in flow_rows:
        # Isolate the restrictive layer from ordinary authority. Both plans get the
        # same synthetic grant; real tool/scope changes are compared above.
        probe = PolicyProbe(
            "diff-flow",
            capability,
            None,
            PolicyOutcome.ALLOW,
            ReasonCode.EXPLICIT_ALLOW,
            (),
            data_artifact_refs=synthetic_artifacts(frozenset({label})),
            data_destination=destination,
        )
        decisions = []
        for plan in (old, new):
            flow_plan = plan.model_copy(
                update={
                    "scope": None,
                    "rules": (
                        ToolRule(
                            rule_id=base_rule_id, capability=capability, decision=RuleDecision.ALLOW
                        ),
                    ),
                }
            )
            decisions.append(engine.decide(probe.request(flow_plan), flow_plan))
        before, after = decisions
        state_before = (before.outcome, before.reason_codes, before.matched_rule_ids)
        state_after = (after.outcome, after.reason_codes, after.matched_rule_ids)
        if state_before != state_after:
            # Missing context and denial both prohibit the flow.
            allowed_before = before.outcome == PolicyOutcome.ALLOW
            allowed_after = after.outcome == PolicyOutcome.ALLOW
            kind = (
                ("data_policy_relaxation" if allowed_after else "data_policy_tightening")
                if allowed_before != allowed_after
                else "data_policy_explanation_change"
            )
            changes.append(
                SemanticChange(
                    schema_version="0.1",
                    kind=kind,
                    source_ref="data.rules",
                    capability=capability,
                    representative_digest=content_digest((label, capability, destination)),
                    old_outcome=before.outcome,
                    new_outcome=after.outcome,
                    old_reason_codes=before.reason_codes,
                    new_reason_codes=after.reason_codes,
                    old_matched_rule_ids=before.matched_rule_ids,
                    new_matched_rule_ids=after.matched_rule_ids,
                )
            )
            if kind != "data_policy_explanation_change" and (
                before.reason_codes != after.reason_codes
                or before.matched_rule_ids != after.matched_rule_ids
            ):
                changes.append(
                    changes[-1].model_copy(update={"kind": "data_policy_explanation_change"})
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
        representatives=len(rows) + len(flow_rows),
        changes=tuple(changes),
    )
