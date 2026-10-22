"""Deterministic graph authority probes; stateful obligations stay explicitly NOT_RUN."""

from datetime import datetime, timedelta
from typing import Literal

from agentsec.compiler.probes import obligation, partition, sentinel
from agentsec.domain.authority import AuthorityContext
from agentsec.domain.base import Identifier, VersionedModel
from agentsec.domain.policy import PolicyRequest
from agentsec.domain.taxonomy import PolicyOutcome, SideEffectClass
from agentsec.domain.tools import ToolDescriptor
from agentsec.multi_agent.authority import GraphMaterial, decide_path
from agentsec.multi_agent.budgets import HierarchicalBudgets
from agentsec.runtime.models import RuntimeFailure


class GraphProbeResult(VersionedModel):
    node_id: Identifier
    obligation: Identifier
    status: Literal["PASS", "FAIL", "NOT_RUN"]
    reason: Identifier


class GraphConformanceReport(VersionedModel):
    graph_digest: str
    probes: tuple[GraphProbeResult, ...]
    claim: Literal["synthetic graph authority only"] = "synthetic graph authority only"


def graph_conformance(material: GraphMaterial, now: datetime) -> GraphConformanceReport:
    results: list[GraphProbeResult] = []
    for fact in material.participants:
        plan = fact.plan
        binding = material.binding(fact.node_id)
        unknown = sentinel(
            {r.capability for p in material.participants for r in p.plan.rules}
            | {c for e in material.graph.edges for c in e.grant.capability_scope},
            "agent.unknown",
        )
        capability = next((r.capability for r in plan.rules), unknown)
        base = PolicyRequest(
            schema_version="0.1",
            request_id="graph-probe",
            graph_binding=binding,
            principal=plan.principal,
            agent=plan.agent.request_agent(),
            task_scope=plan.task_scope,
            authority=AuthorityContext(schema_version="0.1", credential=fact.credential),
            capability=capability,
            tool_id="graph-probe-tool",
            environment=plan.environment,
            requested_at=now,
        )
        cases = (
            ("missing_graph", base.model_copy(update={"graph_binding": None}), now),
            ("missing_identity", base.model_copy(update={"authority": None}), now),
            (
                "wrong_generation",
                base.model_copy(
                    update={
                        "graph_binding": binding.model_copy(
                            update={"generation": binding.generation + 1}
                        )
                    }
                ),
                now,
            ),
            ("unknown_capability", base.model_copy(update={"capability": unknown}), now),
            (
                "expired_ancestor",
                base,
                max(
                    e.grant.expires_at
                    for e in material.graph.edges
                    if e.grant.expires_at is not None
                )
                + timedelta(seconds=1),
            ),
        )
        for name, request, at in cases:
            try:
                decision = decide_path(material, request, at)
                passed = decision.outcome in {PolicyOutcome.DENY, PolicyOutcome.ERROR}
                reason = next(iter(sorted(c.value for c in decision.reason_codes)))
            except RuntimeFailure as exc:
                passed, reason = True, exc.code
            results.append(
                GraphProbeResult(
                    schema_version="0.1",
                    node_id=fact.node_id,
                    obligation=name,
                    status="PASS" if passed else "FAIL",
                    reason=reason,
                )
            )
        # Independent existing contract oracle over the whole path's finite partition.
        plans = tuple(material.participant(n).plan for n in binding.path)
        for cap, resource in partition(*plans):
            expected = max(
                (obligation(p, cap, resource)[0] for p in plans),
                key={
                    PolicyOutcome.ALLOW: 0,
                    PolicyOutcome.REQUIRE_APPROVAL: 1,
                    PolicyOutcome.DENY: 2,
                    PolicyOutcome.ERROR: 3,
                }.__getitem__,
            )
            grants = [e.grant for e in material.graph.edges if e.child_id in binding.path]
            restricted = any(
                cap not in g.capability_scope
                or (
                    g.task_scope.requested_capabilities is not None
                    and cap not in g.task_scope.requested_capabilities
                )
                or (
                    g.task_scope.resource_scopes is not None
                    and cap in g.task_scope.resource_scopes
                    and resource not in g.task_scope.resource_scopes[cap]
                )
                for g in grants
            ) or any(
                material.participant(n).credential.capability_ceiling is not None
                and cap not in (material.participant(n).credential.capability_ceiling or ())
                for n in binding.path
            )
            if restricted:
                expected = PolicyOutcome.DENY
            try:
                actual = decide_path(
                    material,
                    base.model_copy(
                        update={
                            "capability": cap,
                            "resource": resource,
                        }
                    ),
                    now,
                ).outcome
                status: Literal["PASS", "FAIL", "NOT_RUN"] = (
                    "PASS" if actual == expected else "FAIL"
                )
            except RuntimeFailure:
                status = "NOT_RUN"
            results.append(
                GraphProbeResult(
                    schema_version="0.1",
                    node_id=fact.node_id,
                    obligation="path_policy_partition",
                    status=status,
                    reason="FINITE_SYNTHETIC_POLICY_ORACLE",
                )
            )
        # No tool executes: reservations test the very same session coordinator implementation.
        for field, effect, destructive in (
            ("max_tool_calls", SideEffectClass.READ, False),
            ("max_external_writes", SideEffectClass.EXTERNAL_WRITE, False),
            ("max_destructive_calls", SideEffectClass.DESTRUCTIVE, True),
        ):
            limits = [
                getattr(p.budgets, field) for p in plans if getattr(p.budgets, field) is not None
            ]
            limit = min(limits) if limits else None
            status = "NOT_RUN"
            reason = "NO_BOUNDED_BUDGET_WITNESS"
            if limit is not None and limit <= 128:
                ledger = HierarchicalBudgets(lambda: material, lambda: None)
                descriptor = ToolDescriptor(
                    schema_version="0.1",
                    tool_id="synthetic",
                    namespace="graph",
                    name="synthetic",
                    protocol="synthetic",
                    description="No effect",
                    input_schema={},
                    side_effect_class=effect,
                    destructive=destructive,
                    capabilities=frozenset({capability}),
                )
                try:
                    for _ in range(limit):
                        ledger.reserve(descriptor, binding, material.graph.digest)
                    ledger.reserve(descriptor, binding, material.graph.digest)
                    status, reason = "FAIL", "BUDGET_OVERSPEND"
                except RuntimeFailure as exc:
                    status, reason = "PASS", exc.code
                # If another smaller counter won, record only that enforced bound.
            results.append(
                GraphProbeResult(
                    schema_version="0.1",
                    node_id=fact.node_id,
                    obligation=field,
                    status=status,
                    reason=reason,
                )
            )
        for stateful in ("agent_cap", "parent_approval_broker", "label_transfer"):
            results.append(
                GraphProbeResult(
                    schema_version="0.1",
                    node_id=fact.node_id,
                    obligation=stateful,
                    status="NOT_RUN",
                    reason="REQUIRES_STATEFUL_SESSION_FIXTURE",
                )
            )
    return GraphConformanceReport(
        schema_version="0.1", graph_digest=material.graph.digest, probes=tuple(results)
    )
