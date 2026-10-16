"""Immutable, protocol-independent executable intent and source inventory."""

from typing import Literal

from agentsec.contracts.models import ApprovalSettings, ToolRule
from agentsec.domain.base import (
    CapabilityId,
    Count,
    Digest,
    Identifier,
    NonEmpty,
    SecurityModel,
    VersionedModel,
)
from agentsec.domain.identity import AgentIdentity, PrincipalRef, TaskScope
from agentsec.domain.serialization import content_digest


class AgentBinding(SecurityModel):
    agent_id: Identifier
    environment: Identifier
    owner: PrincipalRef | None = None
    trust_level: Identifier | None = None

    @classmethod
    def from_identity(cls, agent: AgentIdentity) -> "AgentBinding":
        return cls(**{name: getattr(agent, name) for name in cls.model_fields})

    def request_agent(self) -> AgentIdentity:
        return AgentIdentity(**self.model_dump(), name="Compiled agent")


class PlanIdentity(SecurityModel):
    contract_id: Identifier
    compiler_version: str
    effective_policy_hash: Digest
    compiled_plan_digest: Digest


class ResourceCeiling(SecurityModel):
    capability: CapabilityId
    resources: frozenset[NonEmpty]


class CompiledScope(SecurityModel):
    task_id: Identifier
    requested_capabilities: frozenset[CapabilityId] | None
    resources: tuple[ResourceCeiling, ...] | None

    def request_scope(self) -> TaskScope:
        return TaskScope(
            task_id=self.task_id,
            description="Compiled task scope",
            requested_capabilities=self.requested_capabilities,
            resource_scopes=(
                {r.capability: r.resources for r in self.resources}
                if self.resources is not None
                else None
            ),
        )


class RuntimeBudgets(SecurityModel):
    max_tool_calls: Count | None = None
    max_external_writes: Count | None = None
    max_destructive_calls: Count | None = None
    max_runtime_seconds: Count | None = None


class SemanticAtom(SecurityModel):
    atom_id: str
    source_ref: str
    compiled: bool
    runtime_supported: bool
    adapter_required: bool = False
    intent_digest: Digest


class CompiledSecurityPlan(VersionedModel):
    compiler_version: Literal["phase3-v2"] = "phase3-v2"
    contract_id: Identifier
    contract_schema_version: Literal["0.1"]
    effective_policy_hash: Digest
    agent: AgentBinding
    principal: PrincipalRef
    environment: Identifier
    rules: tuple[ToolRule, ...]
    scope: CompiledScope | None
    budgets: RuntimeBudgets
    approvals: ApprovalSettings
    atoms: tuple[SemanticAtom, ...]

    @property
    def identity(self) -> PlanIdentity:
        # Computed from the artifact, never from a caller-supplied digest field.
        return PlanIdentity(
            contract_id=self.contract_id,
            compiler_version=self.compiler_version,
            effective_policy_hash=self.effective_policy_hash,
            compiled_plan_digest=content_digest(self),
        )

    def matches_scope(self, scope: TaskScope | None) -> bool:
        if scope is None or self.scope is None:
            return scope is None and self.scope is None
        return (
            scope.task_id == self.scope.task_id
            and scope.requested_capabilities == self.scope.requested_capabilities
            and scope.resource_scopes == self.scope.request_scope().resource_scopes
        )

    @property
    def task_scope(self) -> TaskScope | None:
        # A fresh mutable domain mapping never aliases compiled state.
        return self.scope.request_scope() if self.scope else None

    @property
    def gaps(self) -> tuple[str, ...]:
        return tuple(a.source_ref for a in self.atoms if not a.compiled)
