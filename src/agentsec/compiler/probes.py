"""Declarative obligations: this module never calls the native evaluator for expectations."""

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from itertools import product

from agentsec.compiler.models import CompiledSecurityPlan
from agentsec.domain.authority import AuthorityContext
from agentsec.domain.identity import Delegation, PrincipalRef, TaskScope
from agentsec.domain.policy import PolicyRequest
from agentsec.domain.provenance import DataArtifactRef, DataOrigin
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.domain.taxonomy import DataLabel, PolicyOutcome, ReasonCode, TrustClass
from agentsec.identity.static import StaticIdentityProvider
from agentsec.provenance import ProvenanceEngine


@dataclass(frozen=True)
class PolicyProbe:
    probe_id: str
    capability: str
    resource: str | None
    expected: PolicyOutcome
    reason: ReasonCode
    atom_ids: tuple[str, ...]
    matched_rule_ids: frozenset[str] = frozenset()

    data_artifact_refs: tuple[DataArtifactRef, ...] = ()
    data_destination: str | None = None
    derivable: bool = True
    obligation_kind: str = "tool_policy"

    authority: AuthorityContext | None = None

    def request(self, plan: CompiledSecurityPlan) -> PolicyRequest:
        authority = self.authority or synthetic_authority(plan)
        grant = authority.delegation if authority else None
        return PolicyRequest(
            schema_version="0.1",
            request_id=self.probe_id,
            principal=plan.principal,
            authority=authority,
            delegation_id=grant.delegation_id if grant else None,
            agent=plan.agent.request_agent(),
            environment=plan.environment,
            task_scope=plan.task_scope,
            tool_id="conformance-tool",
            capability=self.capability,
            resource=self.resource,
            data_artifact_refs=self.data_artifact_refs,
            data_destination=self.data_destination,
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
        # Grouped identity/scope consistency has no generated negative probes.
        # Do not claim it is tested merely because valid fields occur in a request.
        atoms: list[str] = []
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
                matched_rule_ids=frozenset(
                    r.rule_id
                    for r in plan.rules
                    if reason != ReasonCode.OUTSIDE_TASK_SCOPE
                    and r.capability == capability
                    and (r.resource is None or r.resource == resource)
                ),
            )
        )
    return tuple(probes) + generate_flow_probes(plan) + generate_authority_probes(plan)


def flow_partition(*plans: CompiledSecurityPlan) -> tuple[tuple[DataLabel, str, str | None], ...]:
    """Exact independent label/capability/destination partitions; no model text."""
    labels = {r.label for p in plans for r in p.data_rules}
    caps = {
        c
        for p in plans
        for r in p.data_rules
        for c in r.allowed_capabilities | r.denied_capabilities
    }
    caps.update(r.capability for p in plans for r in p.rules)
    destinations = {
        d
        for p in plans
        for r in p.data_rules
        for d in r.allowed_destinations | r.denied_destinations
    }
    return tuple(
        product(
            sorted(labels),
            sorted(caps | {sentinel(caps, "flow.other")}),
            (None, *sorted(destinations), sentinel(destinations, "flow-other")),
        )
    )


def flow_obligation(
    plan: CompiledSecurityPlan,
    labels: frozenset[DataLabel],
    capability: str,
    destination: str | None,
) -> tuple[PolicyOutcome | None, ReasonCode | None, frozenset[str]]:
    """Independent declarative set oracle. None outcome means preserve ordinary policy."""
    rules = [r for r in plan.data_rules if r.label in labels]
    ids = frozenset(r.rule_id for r in rules)
    forbidden_capabilities = set().union(*(r.denied_capabilities for r in rules))
    capability_allowlists = [r.allowed_capabilities for r in rules if r.allowed_capabilities]
    forbidden_destinations = set().union(*(r.denied_destinations for r in rules))
    destination_allowlists = [r.allowed_destinations for r in rules if r.allowed_destinations]
    if (
        capability in forbidden_capabilities
        or any(capability not in allowed for allowed in capability_allowlists)
        or (
            destination is not None
            and (
                destination in forbidden_destinations
                or any(destination not in allowed for allowed in destination_allowlists)
            )
        )
    ):
        return PolicyOutcome.DENY, ReasonCode.DATA_FLOW_DENIED, ids
    if destination is None and (forbidden_destinations or destination_allowlists):
        return PolicyOutcome.ERROR, ReasonCode.DATA_FLOW_CONTEXT_MISSING, ids
    return None, None, ids


def synthetic_artifacts(labels: frozenset[DataLabel]) -> tuple[DataArtifactRef, ...]:
    ids = iter(("flow-source", "flow-derived"))
    graph = ProvenanceEngine(lambda: datetime(2026, 1, 1, tzinfo=UTC), lambda: next(ids))
    origin = DataOrigin(
        origin_type="synthetic", source_id="conformance-source", trust_class=TrustClass.TOOL_OUTPUT
    )
    source = graph.derive(origin, labels=labels)
    return (graph.derive(origin, parents=(source,)),)


def generate_flow_probes(plan: CompiledSecurityPlan) -> tuple[PolicyProbe, ...]:
    """Non-vacuous witnesses for each authored restriction, or explicit NOT_RUN.

    Base authorization is derived declaratively and must permit reaching the flow clamp.
    Each axis gets its own witness so an unrelated denial cannot cover it accidentally.
    """
    bases = [
        (c, r, *obligation(plan, c, r))
        for c, r in partition(plan)
        if obligation(plan, c, r)[0] in {PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL}
    ]
    destinations = sorted(
        {d for r in plan.data_rules for d in r.allowed_destinations | r.denied_destinations}
    )
    dests = (None, *destinations, sentinel(set(destinations), "flow-other"))
    probes: list[PolicyProbe] = []
    for rule in plan.data_rules:
        labels = frozenset({rule.label})
        kinds = ["preserve"]
        if rule.denied_capabilities:
            kinds.append("denied_capability")
        if rule.allowed_capabilities:
            kinds.append("outside_allowed_capabilities")
        if rule.denied_destinations:
            kinds.append("denied_destination")
        if rule.allowed_destinations:
            kinds.append("outside_allowed_destinations")
        if rule.allowed_destinations or rule.denied_destinations:
            kinds.append("missing_destination")
        for kind in kinds:
            witness = None
            for c, resource, base, base_reason in bases:
                cap_safe = c not in rule.denied_capabilities and (
                    not rule.allowed_capabilities or c in rule.allowed_capabilities
                )
                for dest in dests:
                    out, reason, ids = flow_obligation(plan, labels, c, dest)
                    qualifies = {
                        "preserve": out is None,
                        "denied_capability": c in rule.denied_capabilities,
                        "outside_allowed_capabilities": bool(rule.allowed_capabilities)
                        and c not in rule.allowed_capabilities,
                        "denied_destination": cap_safe and dest in rule.denied_destinations,
                        "outside_allowed_destinations": cap_safe
                        and dest is not None
                        and bool(rule.allowed_destinations)
                        and dest not in rule.allowed_destinations,
                        "missing_destination": cap_safe and dest is None,
                    }[kind]
                    if qualifies:
                        matched = (
                            frozenset(
                                r.rule_id
                                for r in plan.rules
                                if r.capability == c and r.resource in {None, resource}
                            )
                            | ids
                        )
                        witness = PolicyProbe(
                            "flow-" + content_digest((rule.rule_id, kind)).split(":")[1][:24],
                            c,
                            resource,
                            out or base,
                            reason or base_reason,
                            (f"data.rules/{rule.rule_id}",),
                            matched,
                            synthetic_artifacts(labels),
                            dest,
                            True,
                            kind,
                        )
                        break
                if witness:
                    break
            if witness is None:
                witness = PolicyProbe(
                    "flow-" + content_digest((rule.rule_id, kind)).split(":")[1][:24],
                    "flow.unavailable",
                    None,
                    PolicyOutcome.DENY,
                    ReasonCode.DATA_FLOW_DENIED,
                    (f"data.rules/{rule.rule_id}",),
                    derivable=False,
                    obligation_kind=kind,
                )
            probes.append(witness)
    # Exercise any-deny-wins with all configured labels over every permitted base partition.
    if len(plan.data_rules) > 1:
        labels = frozenset(r.label for r in plan.data_rules)
        for c, resource, _base, base_reason in bases:
            for dest in dests:
                out, reason, ids = flow_obligation(plan, labels, c, dest)
                if out == PolicyOutcome.DENY:
                    matched = (
                        frozenset(
                            r.rule_id
                            for r in plan.rules
                            if r.capability == c and r.resource in {None, resource}
                        )
                        | ids
                    )
                    probes.append(
                        PolicyProbe(
                            "flow-multi-" + content_digest((c, resource, dest)).split(":")[1][:24],
                            c,
                            resource,
                            out,
                            reason or base_reason,
                            tuple(f"data.rules/{r.rule_id}" for r in plan.data_rules),
                            matched,
                            synthetic_artifacts(labels),
                            dest,
                            obligation_kind="any_deny_wins",
                        )
                    )
                    break
    return tuple(probes)


def synthetic_authority(plan: CompiledSecurityPlan) -> AuthorityContext | None:
    """Trusted synthetic facts, never an external authentication claim."""
    if plan.compiler_version != "phase6-v1":
        return None
    credential = StaticIdentityProvider(plan.principal).verify(
        None, datetime(2000, 1, 1, tzinfo=UTC)
    )
    grant = None
    if plan.acts_on_behalf_of:
        grant = Delegation(
            schema_version="0.1",
            delegation_id="synthetic-direct",
            delegator=plan.acts_on_behalf_of,
            delegate=plan.principal,
            capability_scope=frozenset(c for c, _ in partition(plan)),
            task_scope=TaskScope(
                task_id=plan.scope.task_id if plan.scope else "synthetic-task",
                description="Trusted synthetic ceiling",
            ),
            issued_at=datetime(2000, 1, 1, tzinfo=UTC),
            expires_at=datetime(2100, 1, 1, tzinfo=UTC),
        )
    return AuthorityContext(
        schema_version="0.1",
        credential=credential,
        delegation_json=canonical_json(grant) if grant else None,
    )


def generate_authority_probes(plan: CompiledSecurityPlan) -> tuple[PolicyProbe, ...]:
    authority = synthetic_authority(plan)
    if authority is None:
        return ()
    bases = [(c, r, *obligation(plan, c, r)) for c, r in partition(plan)]
    probes = []
    for c, resource, out, reason in bases:
        if out not in {PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL}:
            continue
        matched = frozenset(
            r.rule_id for r in plan.rules if r.capability == c and r.resource in {None, resource}
        )
        base = PolicyProbe(
            "authority-valid-" + content_digest((c, resource))[7:23],
            c,
            resource,
            out,
            reason,
            ("identity.authority",)
            + (("identity.acts_on_behalf_of",) if plan.acts_on_behalf_of else ()),
            matched,
            authority=authority,
            obligation_kind="authority_valid",
        )
        probes.append(base)
        variants = [
            (
                "credential_ceiling",
                AuthorityContext(
                    schema_version="0.1",
                    credential=authority.credential.model_copy(
                        update={"capability_ceiling": frozenset()}
                    ),
                    delegation_json=authority.delegation_json,
                ),
                ReasonCode.OUTSIDE_AUTHORITY_SCOPE,
            ),
            (
                "expired",
                AuthorityContext(
                    schema_version="0.1",
                    credential=authority.credential.model_copy(
                        update={"expires_at": datetime(2001, 1, 1, tzinfo=UTC)}
                    ),
                    delegation_json=authority.delegation_json,
                ),
                ReasonCode.AUTHORITY_EXPIRED,
            ),
        ]
        grant = authority.delegation
        if grant:
            variants.append(
                (
                    "missing_delegation",
                    AuthorityContext(schema_version="0.1", credential=authority.credential),
                    ReasonCode.DELEGATION_REQUIRED,
                )
            )
            other = PrincipalRef(
                principal_id=sentinel(
                    {plan.principal.principal_id, grant.delegator.principal_id}, "synthetic-other"
                ),
                principal_type=plan.principal.principal_type,
            )
            for kind, updates, expected in (
                ("delegator_mismatch", {"delegator": other}, ReasonCode.INVALID_DELEGATION),
                ("delegate_mismatch", {"delegate": other}, ReasonCode.INVALID_DELEGATION),
                (
                    "expired_delegation",
                    {"expires_at": datetime(2001, 1, 1, tzinfo=UTC)},
                    ReasonCode.AUTHORITY_EXPIRED,
                ),
                (
                    "delegation_capability",
                    {"capability_scope": frozenset()},
                    ReasonCode.OUTSIDE_AUTHORITY_SCOPE,
                ),
                (
                    "delegation_resource",
                    {
                        "task_scope": grant.task_scope.model_copy(
                            update={"resource_scopes": {c: frozenset()}}
                        )
                    },
                    ReasonCode.OUTSIDE_AUTHORITY_SCOPE,
                ),
            ):
                variants.append(
                    (
                        kind,
                        AuthorityContext(
                            schema_version="0.1",
                            credential=authority.credential,
                            delegation_json=canonical_json(grant.model_copy(update=updates)),
                        ),
                        expected,
                    )
                )
        for kind, context, expected in variants:
            probes.append(
                replace(
                    base,
                    probe_id=base.probe_id + "-" + kind,
                    expected=PolicyOutcome.DENY,
                    reason=expected,
                    matched_rule_ids=frozenset(),
                    authority=context,
                    obligation_kind="authority_" + kind,
                )
            )
        # One discriminating base is sufficient for generic binding/freshness checks.
        break
    return tuple(probes)
