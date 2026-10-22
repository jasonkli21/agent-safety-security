"""Pure recorded-time graph ceilings, shared with local runtime and offline inspection."""

from datetime import datetime
from typing import Annotated, Self
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from agentsec.compiler.models import AgentBinding, CompiledSecurityPlan
from agentsec.domain.authority import VerifiedCredential
from agentsec.domain.base import Identifier, SecurityModel, VersionedModel
from agentsec.domain.graph import AncestorDecision, GraphBinding, GraphSnapshot
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import PolicyOutcome, ReasonCode
from agentsec.identity.authority import outside_scope
from agentsec.policy.native import compiled_ceiling
from agentsec.runtime.models import RuntimeFailure


class ParticipantFacts(SecurityModel):
    node_id: Identifier
    plan: CompiledSecurityPlan
    credential: VerifiedCredential


class GraphMaterial(VersionedModel):
    """Protected replay material; recorded credentials are facts, never fresh authentication."""

    graph: GraphSnapshot
    participants: Annotated[tuple[ParticipantFacts, ...], Field(min_length=1, max_length=32)]

    @field_validator("participants")
    @classmethod
    def ordered_participants(
        cls, value: tuple[ParticipantFacts, ...]
    ) -> tuple[ParticipantFacts, ...]:
        return tuple(sorted(value, key=lambda p: p.node_id))

    @model_validator(mode="after")
    def bindings(self) -> Self:
        facts = {p.node_id: p for p in self.participants}
        if len(facts) != len(self.participants) or facts.keys() != {
            n.node_id for n in self.graph.nodes
        }:
            raise ValueError("GRAPH_PARTICIPANTS_MISMATCH")
        if len({p.plan.agent.agent_id for p in self.participants}) != len(facts) or len(
            {p.plan.contract_id for p in self.participants}
        ) != len(facts):
            raise ValueError("GRAPH_DUPLICATE_AGENT_OR_CONTRACT")
        edges = {e.child_id: e for e in self.graph.edges}
        for node in self.graph.nodes:
            fact = facts[node.node_id]
            grant = edges[node.node_id].grant
            if (
                fact.plan.identity != node.plan_identity
                or fact.plan.principal != node.principal
                or fact.credential.principal != node.principal
                or fact.plan.acts_on_behalf_of != grant.delegator
                or fact.plan.task_scope is None
                or fact.plan.task_scope.task_id != grant.task_scope.task_id
                or fact.plan.gaps
            ):
                raise ValueError("GRAPH_PARTICIPANT_BINDING_INVALID")
        return self

    def participant(self, node_id: str) -> ParticipantFacts:
        return next(p for p in self.participants if p.node_id == node_id)

    def binding(self, node_id: str) -> GraphBinding:
        path = self.graph.path(node_id)
        edges = {e.child_id: e for e in self.graph.edges}
        return GraphBinding(
            schema_version="0.1",
            graph_digest=self.graph.digest,
            generation=self.graph.generation,
            node_id=node_id,
            path=path,
            authority_path_digest=content_digest(
                tuple((edges[n], self.participant(n)) for n in path)
            ),
        )


def check_path(
    material: GraphMaterial,
    binding: GraphBinding,
    now: datetime,
    capability: str | None = None,
    resource: str | None = None,
) -> None:
    if material.binding(binding.node_id) != binding:
        raise RuntimeFailure("GRAPH_BINDING_STALE")
    edges = {e.child_id: e for e in material.graph.edges}
    for node in binding.path:
        fact = material.participant(node)
        credential, grant = fact.credential, edges[node].grant
        if (
            now < credential.valid_from
            or (credential.expires_at is not None and now >= credential.expires_at)
            or now < grant.issued_at
            or grant.expires_at is None
            or now >= grant.expires_at
        ):
            raise RuntimeFailure("GRAPH_AUTHORITY_EXPIRED")
        if capability is not None and (
            capability not in grant.capability_scope
            or (
                credential.capability_ceiling is not None
                and capability not in credential.capability_ceiling
            )
            or outside_scope(grant.task_scope, capability, resource)
            or outside_scope(fact.plan.task_scope, capability, resource)
        ):
            raise RuntimeFailure("GRAPH_OUTSIDE_AUTHORITY_SCOPE")


def decide_path(material: GraphMaterial, request: PolicyRequest, now: datetime) -> PolicyDecision:
    binding = request.graph_binding
    if binding is None:
        raise RuntimeFailure("GRAPH_BINDING_REQUIRED")
    check_path(material, binding, now)
    own = material.participant(binding.node_id)
    if (
        request.principal != own.plan.principal
        or AgentBinding.from_identity(request.agent) != own.plan.agent
        or not own.plan.matches_scope(request.task_scope)
        or request.environment != own.plan.environment
        or request.authority is None
        or request.authority.credential != own.credential
        or request.authority.delegation_json is not None
        or request.delegation_id is not None
        or request.tool_id is None
    ):
        raise RuntimeFailure("GRAPH_REQUEST_BINDING_INVALID")
    authority_denied = False
    try:
        check_path(material, binding, now, request.capability, request.resource)
    except RuntimeFailure as exc:
        if exc.code != "GRAPH_OUTSIDE_AUTHORITY_SCOPE":
            raise
        authority_denied = True
    outcomes = [compiled_ceiling(request, material.participant(n).plan) for n in binding.path]
    if authority_denied:
        outcomes.append((PolicyOutcome.DENY, ReasonCode.OUTSIDE_AUTHORITY_SCOPE, frozenset()))
    priority = {
        PolicyOutcome.ALLOW: 0,
        PolicyOutcome.REQUIRE_APPROVAL: 1,
        PolicyOutcome.DENY: 2,
        PolicyOutcome.ERROR: 3,
    }
    outcome = max((o[0] for o in outcomes), key=priority.__getitem__)
    return PolicyDecision(
        schema_version="0.1",
        decision_id=str(uuid4()),
        request_id=request.request_id,
        outcome=outcome,
        # IDs belong to separate plans. Full path commitment identifies their namespaces.
        matched_rule_ids=frozenset(r for _, _, rules in outcomes for r in rules),
        reason_codes=frozenset(reason for result, reason, _ in outcomes if result == outcome),
        ancestor_decisions=tuple(
            AncestorDecision(
                node_id=n,
                plan_identity=material.participant(n).plan.identity,
                outcome=o,
                reason_code=r,
                matched_rule_ids=rules,
            )
            for n, (o, r, rules) in zip(binding.path, outcomes[: len(binding.path)], strict=True)
        ),
        human_reason="GRAPH_ANCESTOR_CEILING",
        contract_id=own.plan.contract_id,
        effective_policy_hash=own.plan.effective_policy_hash,
        decided_at=now,
    )
