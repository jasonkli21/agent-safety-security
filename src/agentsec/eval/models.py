"""Versioned, content-minimized evaluation reports."""

from enum import StrEnum

from agentsec.domain.base import (
    Count,
    Digest,
    Identifier,
    NonEmpty,
    SecurityModel,
    Timestamp,
    VersionedModel,
)
from agentsec.domain.findings import Finding


class EvaluationStatus(StrEnum):
    PASS = "PASS"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAIL = "FAIL"
    ERROR = "ERROR"


def aggregate(statuses: tuple[EvaluationStatus, ...]) -> EvaluationStatus:
    return max(
        statuses, key=lambda s: list(EvaluationStatus).index(s), default=EvaluationStatus.PASS
    )


class AssertionResult(SecurityModel):
    assertion_index: Count
    assertion_type: NonEmpty
    status: EvaluationStatus
    message: NonEmpty
    evidence_event_refs: tuple[Identifier, ...] = ()
    evidence_artifact_refs: tuple[Identifier, ...] = ()
    matched_observation_refs: tuple[Identifier, ...] = ()


class EvaluationMetrics(SecurityModel):
    tool_requests: Count = 0
    tool_dispatches: Count = 0
    tool_returns: Count = 0
    approval_requests: Count = 0
    approval_decisions: Count = 0
    security_signals: Count = 0
    findings: Count = 0
    security_assertions_passed: Count = 0
    security_assertions_failed: Count = 0
    security_assertions_inconclusive: Count = 0
    utility_assertions_passed: Count = 0
    utility_assertions_failed: Count = 0
    utility_assertions_inconclusive: Count = 0


class EvaluationResult(VersionedModel):
    scenario_id: Identifier
    contract_id: Identifier
    effective_policy_hash: Digest
    run_id: Identifier
    trace_id: Identifier
    security_status: EvaluationStatus
    utility_status: EvaluationStatus
    overall_status: EvaluationStatus
    security_assertions: tuple[AssertionResult, ...] = ()
    utility_assertions: tuple[AssertionResult, ...] = ()
    findings: tuple[Finding, ...] = ()
    metrics: EvaluationMetrics = EvaluationMetrics()
    error_code: Identifier | None = None


class EvaluationCounts(SecurityModel):
    passed: Count
    failed: Count
    inconclusive: Count
    errors: Count


class EvaluationSummary(VersionedModel):
    evaluated_at: Timestamp
    contract_id: Identifier
    effective_policy_hash: Digest
    results: tuple[EvaluationResult, ...]
    counts: EvaluationCounts
