"""Compile validated contract facts once; no protocol or runtime state belongs here."""

from agentsec.compiler.models import (
    AgentBinding,
    CompiledScope,
    CompiledSecurityPlan,
    ResourceCeiling,
    RuntimeBudgets,
    SemanticAtom,
)
from agentsec.contracts.canonical import effective_policy_hash
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.serialization import content_digest


def compile_contract(contract: AgentSecurityContract) -> CompiledSecurityPlan:
    atoms: list[SemanticAtom] = []

    def atom(ref: str, value: object, *, supported: bool = True, adapter: bool = False) -> None:
        atoms.append(
            SemanticAtom(
                atom_id=ref,
                source_ref=ref,
                compiled=supported,
                runtime_supported=supported,
                adapter_required=adapter,
                intent_digest=content_digest(value),
            )
        )

    agent = AgentBinding.from_identity(contract.agent)
    atom("identity", (agent, contract.identity.principal, contract.environment))
    atom("tools.default_deny", "DENY")
    for rule in contract.tools.rules:
        atom(f"tools.rules/{rule.rule_id}", rule, adapter=rule.resource is not None)
    scope = contract.task_scope
    if scope is not None:
        atom(
            "task_scope",
            scope.model_dump(exclude={"description"}),
            adapter=bool(scope.resource_scopes),
        )
    for name in RuntimeBudgets.model_fields:
        if (value := getattr(contract.budgets, name)) is not None:
            atom(f"budgets.{name}", value)
    atom("approvals.default_timeout_seconds", contract.approvals.default_timeout_seconds)
    for data_rule in contract.data.rules:
        atom(f"data.rules/{data_rule.rule_id}", data_rule, adapter=True)
    for invariant in contract.invariants:
        atom(f"invariants/{invariant.id}", invariant, supported=False)
    if contract.identity.acts_on_behalf_of is not None:
        atom("identity.acts_on_behalf_of", contract.identity.acts_on_behalf_of, supported=False)
    for name in ("max_model_calls", "max_cost_usd", "max_delegated_agents"):
        if (value := getattr(contract.budgets, name)) is not None:
            atom(f"budgets.{name}", value, supported=False)
    return CompiledSecurityPlan(
        schema_version="0.1",
        contract_schema_version=contract.schema_version,
        contract_id=contract.metadata.contract_id,
        effective_policy_hash=effective_policy_hash(contract),
        agent=agent,
        principal=contract.identity.principal,
        environment=contract.environment.mode,
        rules=contract.tools.rules,
        data_rules=contract.data.rules,
        scope=(
            CompiledScope(
                task_id=scope.task_id,
                requested_capabilities=scope.requested_capabilities,
                resources=(
                    tuple(
                        ResourceCeiling(capability=k, resources=v)
                        for k, v in sorted(scope.resource_scopes.items())
                    )
                    if scope.resource_scopes is not None
                    else None
                ),
            )
            if scope
            else None
        ),
        budgets=RuntimeBudgets(
            **{n: getattr(contract.budgets, n) for n in RuntimeBudgets.model_fields}
        ),
        approvals=contract.approvals,
        atoms=tuple(sorted(atoms, key=lambda a: a.atom_id)),
    )
