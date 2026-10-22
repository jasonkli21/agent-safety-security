"""Versioned local graph commitments. Grants are canonical strings to prevent aliasing."""

from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from agentsec.compiler.models import PlanIdentity
from agentsec.domain.base import Digest, Identifier, SecurityModel, VersionedModel
from agentsec.domain.identity import Delegation, PrincipalRef
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.domain.taxonomy import PolicyOutcome, PrincipalType, ReasonCode


class AgentNode(SecurityModel):
    node_id: Identifier
    principal: PrincipalRef
    plan_identity: PlanIdentity

    @model_validator(mode="after")
    def agent(self) -> Self:
        if self.principal.principal_type != PrincipalType.AGENT:
            raise ValueError("GRAPH_AGENT_REQUIRED")
        if self.plan_identity.compiler_version != "phase9-v1":
            raise ValueError("GRAPH_PHASE9_PLAN_REQUIRED")
        return self


class DelegationEdge(SecurityModel):
    parent_id: Identifier | None
    child_id: Identifier
    delegation_json: Annotated[str, Field(min_length=1, max_length=8192)]

    @field_validator("delegation_json")
    @classmethod
    def canonical(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 8192:
            raise ValueError("GRAPH_GRANT_SIZE_LIMIT")
        grant = Delegation.model_validate_json(value)
        if canonical_json(grant) != value or grant.expires_at is None:
            raise ValueError("GRAPH_CANONICAL_FINITE_GRANT_REQUIRED")
        caps = grant.task_scope.requested_capabilities
        if (caps is not None and not caps <= grant.capability_scope) or any(
            cap not in grant.capability_scope or (caps is not None and cap not in caps)
            for cap in grant.task_scope.resource_scopes or {}
        ):
            raise ValueError("GRAPH_INVALID_GRANT_SCOPE")
        return value

    @property
    def grant(self) -> Delegation:
        return Delegation.model_validate_json(self.delegation_json)


class GraphSnapshot(VersionedModel):
    domain: Literal["agentsec.graph.v1"] = "agentsec.graph.v1"
    generation: Annotated[int, Field(ge=1)]
    root: PrincipalRef
    nodes: Annotated[tuple[AgentNode, ...], Field(min_length=1, max_length=32)]
    edges: Annotated[tuple[DelegationEdge, ...], Field(min_length=1, max_length=32)]

    @field_validator("nodes")
    @classmethod
    def ordered_nodes(cls, value: tuple[AgentNode, ...]) -> tuple[AgentNode, ...]:
        if len({n.node_id for n in value}) != len(value) or len(
            {n.principal for n in value}
        ) != len(value):
            raise ValueError("GRAPH_DUPLICATE_NODE")
        return tuple(sorted(value, key=lambda n: n.node_id))

    @field_validator("edges")
    @classmethod
    def ordered_edges(cls, value: tuple[DelegationEdge, ...]) -> tuple[DelegationEdge, ...]:
        if len({e.child_id for e in value}) != len(value) or len(
            {e.grant.delegation_id for e in value}
        ) != len(value):
            raise ValueError("GRAPH_DUPLICATE_EDGE")
        return tuple(sorted(value, key=lambda e: e.child_id))

    @model_validator(mode="after")
    def tree(self) -> Self:
        if self.root.principal_type not in {PrincipalType.USER, PrincipalType.SERVICE}:
            raise ValueError("GRAPH_EXTERNAL_ROOT_REQUIRED")
        nodes = {n.node_id: n for n in self.nodes}
        edges = {e.child_id: e for e in self.edges}
        if nodes.keys() != edges.keys() or sum(e.parent_id is None for e in self.edges) != 1:
            raise ValueError("GRAPH_INCOMPLETE_TREE")
        for edge in self.edges:
            if edge.parent_id is not None and edge.parent_id not in nodes:
                raise ValueError("GRAPH_UNKNOWN_PARENT")
            grant = edge.grant
            parent = edges[edge.parent_id].grant if edge.parent_id is not None else None
            if (
                grant.delegate != nodes[edge.child_id].principal
                or grant.delegator
                != (nodes[edge.parent_id].principal if edge.parent_id is not None else self.root)
                or grant.parent_delegation_id != (parent.delegation_id if parent else None)
            ):
                raise ValueError("GRAPH_GRANT_BINDING_MISMATCH")
            if parent and (
                grant.task_scope.task_id != parent.task_scope.task_id
                or grant.issued_at < parent.issued_at
                or (
                    parent.expires_at is not None
                    and (grant.expires_at is None or grant.expires_at > parent.expires_at)
                )
            ):
                raise ValueError("GRAPH_PARENT_WINDOW_OR_TASK_MISMATCH")
            self.path(edge.child_id)
            if sum(e.parent_id == edge.child_id for e in self.edges) > 8:
                raise ValueError("GRAPH_FANOUT_LIMIT")
        if len(canonical_json(self).encode()) > 131072:
            raise ValueError("GRAPH_SIZE_LIMIT")
        return self

    def path(self, node_id: str) -> tuple[str, ...]:
        edges = {e.child_id: e for e in self.edges}
        path: list[str] = []
        current: str | None = node_id
        while current is not None:
            if current in path or current not in edges:
                raise ValueError("GRAPH_CYCLE_OR_ORPHAN")
            path.append(current)
            if len(path) > 8:
                raise ValueError("GRAPH_DEPTH_LIMIT")
            current = edges[current].parent_id
        return tuple(reversed(path))

    @property
    def digest(self) -> str:
        return content_digest(self)


class GraphBinding(VersionedModel):
    """Safe commitment only; cannot prove graph authority without protected session state."""

    graph_digest: Digest
    generation: Annotated[int, Field(ge=1)]
    node_id: Identifier
    path: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=8)]
    authority_path_digest: Digest

    @model_validator(mode="after")
    def path_end(self) -> Self:
        if self.path[-1] != self.node_id or len(set(self.path)) != len(self.path):
            raise ValueError("GRAPH_INVALID_PATH")
        return self


class AncestorDecision(SecurityModel):
    node_id: Identifier
    plan_identity: PlanIdentity
    outcome: PolicyOutcome
    reason_code: ReasonCode
    matched_rule_ids: frozenset[Identifier]
