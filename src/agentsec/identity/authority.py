"""Pure restrictive authority composition shared by runtime, policy and replay."""

from datetime import datetime

from agentsec.domain.authority import AuthorityContext
from agentsec.domain.identity import PrincipalRef, TaskScope
from agentsec.domain.taxonomy import ReasonCode


def intersect_scopes(left: TaskScope | None, right: TaskScope | None) -> TaskScope | None:
    if left is None or right is None:
        scope = left if right is None else right
        return scope.model_copy(deep=True) if scope else None
    if left.task_id != right.task_id:
        raise ValueError("TASK_ID_MISMATCH")
    a, b = left.requested_capabilities, right.requested_capabilities
    caps = b if a is None else a if b is None else a & b
    ar, br = left.resource_scopes, right.resource_scopes
    resources = None
    if ar is not None or br is not None:
        resources = dict(ar or {})
        for cap, values in (br or {}).items():
            resources[cap] = resources[cap] & values if cap in resources else values
    return TaskScope(
        task_id=left.task_id,
        description="Effective authority ceiling",
        requested_capabilities=caps,
        resource_scopes=resources,
    )


def outside_scope(scope: TaskScope | None, capability: str, resource: str | None) -> bool:
    return scope is not None and (
        (
            scope.requested_capabilities is not None
            and capability not in scope.requested_capabilities
        )
        or (
            scope.resource_scopes is not None
            and capability in scope.resource_scopes
            and resource not in scope.resource_scopes[capability]
        )
    )


def authority_failure(
    authority: AuthorityContext | None,
    principal: PrincipalRef,
    obo: PrincipalRef | None,
    scope: TaskScope | None,
    now: datetime,
    *,
    capability: str | None = None,
    resource: str | None = None,
) -> ReasonCode | None:
    if authority is None:
        return ReasonCode.DELEGATION_REQUIRED if obo else None
    credential = authority.credential
    if credential.principal != principal:
        return ReasonCode.IDENTITY_MISMATCH
    if now < credential.valid_from or (
        credential.expires_at is not None and now >= credential.expires_at
    ):
        return ReasonCode.AUTHORITY_EXPIRED
    contract_scope = scope
    grant = authority.delegation
    if obo is not None and grant is None:
        return ReasonCode.DELEGATION_REQUIRED
    if grant is not None:
        if (
            obo is None
            or grant.delegator != obo
            or grant.delegate != principal
            or grant.parent_delegation_id is not None
            or grant.expires_at is None
        ):
            return ReasonCode.INVALID_DELEGATION
        if now < grant.issued_at or now >= grant.expires_at:
            return ReasonCode.AUTHORITY_EXPIRED
        task_caps = grant.task_scope.requested_capabilities
        if task_caps is not None and not task_caps <= grant.capability_scope:
            return ReasonCode.INVALID_DELEGATION
        if any(
            c not in grant.capability_scope or (task_caps is not None and c not in task_caps)
            for c in grant.task_scope.resource_scopes or {}
        ):
            return ReasonCode.INVALID_DELEGATION
        try:
            scope = intersect_scopes(scope, grant.task_scope)
        except ValueError:
            return ReasonCode.INVALID_DELEGATION
    if capability is not None:
        if outside_scope(contract_scope, capability, resource):
            return ReasonCode.OUTSIDE_TASK_SCOPE
        if (
            (
                credential.capability_ceiling is not None
                and capability not in credential.capability_ceiling
            )
            or (grant is not None and capability not in grant.capability_scope)
            or outside_scope(scope, capability, resource)
        ):
            return ReasonCode.OUTSIDE_AUTHORITY_SCOPE
    return None
