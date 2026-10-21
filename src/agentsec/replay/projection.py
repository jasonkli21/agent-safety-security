"""Stable causal event projection; only explicitly enumerated volatility is removed."""

from itertools import zip_longest
from typing import Literal, cast

from pydantic import JsonValue

from agentsec.domain.events import (
    ApprovalRequestedPayload,
    SecurityEvent,
    ToolDispatchedPayload,
    ToolReturnedPayload,
)
from agentsec.domain.findings import Finding
from agentsec.domain.replay import (
    CandidateRouteManifest,
    RouteComparison,
    TraceDiff,
    TraceDifference,
    TraceFact,
)
from agentsec.domain.serialization import canonical_json, content_digest, normalize
from agentsec.eval.models import AssertionResult

# IDs are normalized by namespace, preserving cross-event links and sequence ordering.
ID_FIELDS = {
    "request_id": "request",
    "policy_request_id": "request",
    "decision_id": "decision",
    "approval_id": "approval",
    "dispatch_id": "dispatch",
    "artifact_id": "artifact",
    "parent_artifact_ids": "artifact",
    "artifact_refs": "artifact",
    "output_artifact_refs": "artifact",
    "evidence_artifact_refs": "artifact",
    "trajectory_ref": "trajectory",
}
VOLATILE = {
    "requested_at",
    "decided_at",
    "created_at",
    "expires_at",
    "human_reason",
    "redacted_summary",
    "policy_input_digest",
    "resource_digest",
    "task_scope_digest",
}


def project(events: tuple[SecurityEvent, ...]) -> tuple[TraceFact, ...]:
    identities: dict[str, dict[str, str]] = {}

    def identity(namespace: str, value: str) -> str:
        mapping = identities.setdefault(namespace, {})
        if value not in mapping:
            mapping[value] = f"{namespace}-{len(mapping)}"
        return mapping[value]

    def visit(value: JsonValue, field: str = "") -> JsonValue:
        if field in ID_FIELDS:
            if isinstance(value, str):
                return identity(ID_FIELDS[field], value)
            if isinstance(value, list):
                return cast(
                    list[JsonValue], sorted(identity(ID_FIELDS[field], str(v)) for v in value)
                )
        if isinstance(value, dict):
            return {k: visit(v, k) for k, v in value.items() if k not in VOLATILE}
        if isinstance(value, list):
            items = [visit(v) for v in value]
            if field in {"artifacts", "data_artifact_refs"}:
                items.sort(key=canonical_json)
            return items
        return value

    def payload(event: SecurityEvent) -> JsonValue:
        value = visit(normalize(event.payload))
        if isinstance(event.payload, ApprovalRequestedPayload) and isinstance(value, dict):
            approval = event.payload.approval
            value["approval_timeout_seconds"] = (
                (approval.expires_at - approval.created_at).total_seconds()
                if approval.expires_at is not None
                else None
            )
        return value

    return tuple(
        TraceFact(
            kind=e.event_type.value,
            canonical_payload=canonical_json(
                {
                    "payload": payload(e),
                    "labels": normalize(e.labels),
                    "actor": normalize(e.actor),
                }
            ),
        )
        for e in events
    )


def compare_execution_routes(
    events: tuple[SecurityEvent, ...], candidate: CandidateRouteManifest | None
) -> RouteComparison:
    """Compare recorded route identities to protected candidate metadata, without execution."""
    dispatches = [
        event.payload for event in events if isinstance(event.payload, ToolDispatchedPayload)
    ]
    if candidate is None or not dispatches:
        return RouteComparison(status="UNKNOWN")

    source: dict[str, set[str]] = {}
    missing_source: set[str] = set()
    for dispatch in dispatches:
        if dispatch.execution_binding is None:
            missing_source.add(dispatch.tool_id)
        else:
            source.setdefault(dispatch.tool_id, set()).add(
                content_digest(dispatch.execution_binding)
            )

    candidate_routes: dict[str, set[str]] = {}
    for route in candidate.routes:
        candidate_routes.setdefault(route.tool_id, set()).add(
            content_digest(route.execution_binding)
        )

    missing_candidate = set(source) - set(candidate_routes)
    changed = {
        tool_id
        for tool_id, bindings in source.items()
        if tool_id in candidate_routes and not bindings.issubset(candidate_routes[tool_id])
    }
    if missing_source or missing_candidate:
        status: Literal["UNKNOWN", "UNCHANGED", "CHANGED", "INCOMPLETE"] = "INCOMPLETE"
    elif changed:
        status = "CHANGED"
    else:
        status = "UNCHANGED"
    return RouteComparison(
        status=status,
        changed_tool_ids=tuple(sorted(changed)),
        missing_source_route_tool_ids=tuple(sorted(missing_source)),
        missing_candidate_route_tool_ids=tuple(sorted(missing_candidate)),
    )


def semantic_diff(
    source: tuple[SecurityEvent, ...],
    replay: tuple[SecurityEvent, ...],
    *,
    limitations: frozenset[str] = frozenset(),
    source_assertions: tuple[AssertionResult, ...] = (),
    replay_assertions: tuple[AssertionResult, ...] = (),
    source_findings: tuple[Finding, ...] = (),
    replay_findings: tuple[Finding, ...] = (),
) -> TraceDiff:
    def outcome_facts(
        events: tuple[SecurityEvent, ...],
        assertions: tuple[AssertionResult, ...],
        findings: tuple[Finding, ...],
    ) -> tuple[TraceFact, ...]:
        event_ids = {e.event_id: i for i, e in enumerate(events)}
        artifact_ids = {
            a.artifact_id: i
            for i, a in enumerate(
                a
                for e in events
                if isinstance(e.payload, ToolReturnedPayload)
                for a in e.payload.artifacts
            )
        }
        return tuple(
            TraceFact(
                kind="ASSERTION",
                canonical_payload=canonical_json((a.assertion_index, a.assertion_type, a.status)),
            )
            for a in assertions
        ) + tuple(
            TraceFact(
                kind="FINDING",
                canonical_payload=canonical_json(
                    (
                        f.category,
                        f.severity,
                        sorted(
                            str(event_ids[r]) if r in event_ids else "external:" + r
                            for r in f.event_refs
                        ),
                        sorted(
                            str(artifact_ids[r]) if r in artifact_ids else "external:" + r
                            for r in f.artifact_refs
                        ),
                    )
                ),
            )
            for f in findings
        )

    source_facts = project(source) + outcome_facts(source, source_assertions, source_findings)
    replay_facts = project(replay) + outcome_facts(replay, replay_assertions, replay_findings)
    differences = tuple(
        TraceDifference(index=i, source=a, replay=b)
        for i, (a, b) in enumerate(zip_longest(source_facts, replay_facts))
        if a != b
    )
    return TraceDiff(
        schema_version="0.1",
        status="INCOMPLETE" if limitations else "CHANGED" if differences else "UNCHANGED",
        differences=differences,
        limitations=limitations,
    )
