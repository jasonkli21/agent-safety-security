"""Explicit customer-side allowlist projection. Never serialize event/result bodies."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from agentsec.compiler.reporting import ConformanceReport, CoverageReport
from agentsec.control_plane.models import Counters, Metadata
from agentsec.domain.events import (
    EffectVerifiedPayload,
    PolicyEvaluatedPayload,
    SecurityEvent,
    ToolDispatchedPayload,
)
from agentsec.domain.replay import ReplayResult
from agentsec.domain.taxonomy import EventType, PolicyOutcome
from agentsec.eval.models import EvaluationResult, EvaluationStatus, aggregate
from agentsec.evidence.dispatch import dispatch_admissions


def project_events(
    *,
    events: tuple[SecurityEvent, ...],
    run_id: UUID,
    agent_id: str,
    environment: str,
    repository: str,
    start: datetime,
    end: datetime,
) -> Metadata:
    counts = {kind: sum(e.event_type == kind for e in events) for kind in EventType}
    modes = {
        e.payload.enforcement_mode.value
        for e in events
        if isinstance(e.payload, ToolDispatchedPayload)
    }
    mode: Literal["UNKNOWN", "ENFORCE", "SHADOW", "DISABLED"] = "UNKNOWN"
    if modes == {"ENFORCE"}:
        mode = "ENFORCE"
    elif "DISABLED" in modes:
        mode = "DISABLED"
    elif "SHADOW" in modes:
        mode = "SHADOW"
    return Metadata(
        run_id=run_id,
        agent_id=agent_id,
        environment=environment,
        repository=repository,
        source="RUNTIME",
        period_start=start,
        period_end=end,
        mode=mode,
        counters=Counters(
            requested=counts[EventType.TOOL_REQUESTED],
            denied=sum(
                isinstance(e.payload, PolicyEvaluatedPayload)
                and e.payload.decision.outcome == PolicyOutcome.DENY
                for e in events
            ),
            approval_requested=counts[EventType.APPROVAL_REQUESTED],
            approval_decided=counts[EventType.APPROVAL_DECIDED],
            dispatched=len(dispatch_admissions(events)),
            returned=counts[EventType.TOOL_RETURNED],
            effect_verified=sum(
                isinstance(e.payload, EffectVerifiedPayload) and e.payload.verified for e in events
            ),
        ),
        # Counting does not prove causal completeness or source authenticity.
        completeness="INCOMPLETE",
    )


def project_ci(
    *,
    evaluations: tuple[EvaluationResult, ...],
    regressions: tuple[str, ...],
    conformance: ConformanceReport,
    coverage: CoverageReport,
    run_id: UUID,
    agent_id: str,
    environment: str,
    repository: str,
    start: datetime,
    end: datetime,
) -> Metadata:
    if conformance.plan_identity != coverage.plan_identity:
        raise ValueError("PLAN_MISMATCH")
    if any(r not in {"PASS", "FAIL", "ERROR", "DRAFT"} for r in regressions):
        raise ValueError("REGRESSION_STATUS")
    if any(e.effective_policy_hash != conformance.effective_policy_hash for e in evaluations):
        # Different tested policies cannot be presented as one policy's CI result.
        raise ValueError("PLAN_MISMATCH")
    statuses = {r.status for r in (*conformance.probes, *conformance.eval_cases)}
    covered = bool(coverage.atoms) and all(
        a.runtime_supported
        and a.adapter_status != "UNPROVEN"
        and a.probe_status == "PASS"
        and a.eval_status == "PASS"
        for a in coverage.atoms
    )
    ci: Literal["UNKNOWN", "PASS", "FAIL", "ERROR", "INCONCLUSIVE"] = (
        aggregate(tuple(e.overall_status for e in evaluations)).value if evaluations else "UNKNOWN"
    )
    if "ERROR" in statuses:
        ci = "ERROR"
    elif "FAIL" in statuses and ci not in {"ERROR", "FAIL"}:
        ci = "FAIL"
    regression: Literal["UNKNOWN", "PASS", "FAIL", "ERROR", "DRAFT"] = "UNKNOWN"
    for status in ("ERROR", "FAIL", "DRAFT", "PASS"):
        if status in regressions:
            regression = status
            break
    return Metadata(
        run_id=run_id,
        agent_id=agent_id,
        environment=environment,
        repository=repository,
        source="CI",
        period_start=start,
        period_end=end,
        ci=ci,
        regression=regression,
        coverage="SYNTHETIC_PASS"
        if covered and statuses == {"PASS"}
        else "GAPS"
        if coverage.atoms
        else "UNKNOWN",
        counters=Counters(
            errors=sum(e.overall_status == EvaluationStatus.ERROR for e in evaluations)
        ),
    )


def project_replay(
    *,
    result: ReplayResult,
    run_id: UUID,
    agent_id: str,
    environment: str,
    repository: str,
    start: datetime,
    end: datetime,
) -> Metadata:
    """Offline replay assessment only; source identities, events and findings stay local."""
    blocked = bool(result.assessment.blockers) or not result.assertions
    failed = any(
        a.status in {EvaluationStatus.FAIL, EvaluationStatus.ERROR} for a in result.assertions
    )
    unknown = any(a.status == EvaluationStatus.INCONCLUSIVE for a in result.assertions)
    return Metadata(
        run_id=run_id,
        agent_id=agent_id,
        environment=environment,
        repository=repository,
        source="CI",
        period_start=start,
        period_end=end,
        replay="BLOCKED" if blocked or unknown else "FAIL" if failed else "PASS",
        ci="INCONCLUSIVE" if blocked or unknown else "FAIL" if failed else "PASS",
    )
