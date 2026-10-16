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


class ResourceCeiling(SecurityModel):
    capability: CapabilityId
    resources: frozenset[NonEmpty]


class CompiledScope(SecurityModel):
    task_id: Identifier
    description: NonEmpty
    requested_capabilities: frozenset[CapabilityId] | None
    resources: tuple[ResourceCeiling, ...] | None

    def request_scope(self) -> TaskScope:
        return TaskScope(
            task_id=self.task_id,
            description=self.description,
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
    compiler_version: Literal["phase3-v1"] = "phase3-v1"
    contract_id: Identifier
    contract_schema_version: Literal["0.1"]
    effective_policy_hash: Digest
    agent: AgentIdentity
    principal: PrincipalRef
    environment: Identifier
    rules: tuple[ToolRule, ...]
    scope: CompiledScope | None
    budgets: RuntimeBudgets
    approvals: ApprovalSettings
    atoms: tuple[SemanticAtom, ...]

    @property
    def task_scope(self) -> TaskScope | None:
        # A fresh mutable domain mapping never aliases compiled state.
        return self.scope.request_scope() if self.scope else None

    @property
    def gaps(self) -> tuple[str, ...]:
        return tuple(a.source_ref for a in self.atoms if not a.compiled)
