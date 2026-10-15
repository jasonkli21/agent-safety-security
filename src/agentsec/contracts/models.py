"""Contract v0.1: declarative security intent, not an executing policy engine."""

from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from agentsec.contracts.validation import validate_contract_semantics
from agentsec.domain.base import (
    CapabilityId,
    Count,
    Identifier,
    NonEmpty,
    SecurityModel,
    Timeout,
    VersionedModel,
)
from agentsec.domain.identity import AgentIdentity, PrincipalRef, TaskScope
from agentsec.domain.taxonomy import DataLabel, RuleDecision, SecurityCategory


class ContractMetadata(SecurityModel):
    contract_id: Identifier
    name: NonEmpty
    description: NonEmpty | None = None
    contract_version: Identifier | None = None


class IdentityBinding(SecurityModel):
    principal: PrincipalRef
    acts_on_behalf_of: PrincipalRef | None = None


class ToolRule(SecurityModel):
    rule_id: Identifier
    capability: CapabilityId
    decision: RuleDecision
    resource: NonEmpty | None = None


class ToolPolicy(SecurityModel):
    rules: tuple[ToolRule, ...] = ()

    @field_validator("rules")
    @classmethod
    def ordered_rules(cls, rules: tuple[ToolRule, ...]) -> tuple[ToolRule, ...]:
        return tuple(sorted(rules, key=lambda r: r.rule_id))


class DataRule(SecurityModel):
    rule_id: Identifier
    label: DataLabel
    denied_destinations: frozenset[Identifier] = frozenset()
    allowed_destinations: frozenset[Identifier] = frozenset()
    denied_capabilities: frozenset[CapabilityId] = frozenset()
    allowed_capabilities: frozenset[CapabilityId] = frozenset()


class DataPolicy(SecurityModel):
    rules: tuple[DataRule, ...] = ()

    @field_validator("rules")
    @classmethod
    def ordered_rules(cls, rules: tuple[DataRule, ...]) -> tuple[DataRule, ...]:
        return tuple(sorted(rules, key=lambda r: r.rule_id))


class Budgets(SecurityModel):
    max_model_calls: Count | None = None
    max_tool_calls: Count | None = None
    max_external_writes: Count | None = None
    max_destructive_calls: Count | None = None
    max_runtime_seconds: Count | None = None
    max_cost_usd: Annotated[float, Field(ge=0)] | None = None
    max_delegated_agents: Count | None = None


class ApprovalSettings(SecurityModel):
    default_timeout_seconds: Timeout = 120


class Invariant(SecurityModel):
    id: Identifier
    description: NonEmpty
    category: SecurityCategory | None = None


class Environment(SecurityModel):
    mode: Identifier


class AgentSecurityContract(VersionedModel):
    metadata: ContractMetadata
    agent: AgentIdentity
    identity: IdentityBinding
    task_scope: TaskScope | None = None
    tools: ToolPolicy = ToolPolicy()
    data: DataPolicy = DataPolicy()
    budgets: Budgets = Budgets()
    approvals: ApprovalSettings = ApprovalSettings()
    invariants: tuple[Invariant, ...] = ()
    environment: Environment

    @field_validator("invariants")
    @classmethod
    def ordered_invariants(cls, invariants: tuple[Invariant, ...]) -> tuple[Invariant, ...]:
        return tuple(sorted(invariants, key=lambda i: i.id))

    @model_validator(mode="after")
    def semantic_checks(self) -> Self:
        validate_contract_semantics(self)
        return self
