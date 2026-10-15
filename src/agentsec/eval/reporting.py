"""Default reports contain references and counts, never raw captured text."""

from agentsec.domain.base import Timestamp
from agentsec.domain.serialization import canonical_json
from agentsec.eval.models import (
    EvaluationCounts,
    EvaluationResult,
    EvaluationStatus,
    EvaluationSummary,
)
from agentsec.eval.trajectory import EvaluationError

EXIT_CODES = {
    EvaluationStatus.PASS: 0,
    EvaluationStatus.FAIL: 1,
    EvaluationStatus.INCONCLUSIVE: 3,
    EvaluationStatus.ERROR: 4,
}


def render_report(result: EvaluationResult, format: str = "text") -> str:
    if format == "json":
        return canonical_json(result)
    lines = [
        f"Scenario: {result.scenario_id}",
        f"Contract: {result.contract_id}",
        f"Security: {result.security_status}",
        f"Utility: {result.utility_status}",
        f"Overall: {result.overall_status}",
    ]
    if result.error_code:
        lines.append(f"Error: {result.error_code}")
    for title, assertions in (
        ("Security assertions", result.security_assertions),
        ("Utility assertions", result.utility_assertions),
    ):
        lines.append(title)
        for assertion in assertions:
            lines.append(f"  {assertion.status} {assertion.assertion_type}: {assertion.message}")
            if assertion.evidence_event_refs:
                lines.append("    evidence: " + ", ".join(assertion.evidence_event_refs))
    lines += [
        "Metrics",
        f"  tool requests: {result.metrics.tool_requests}",
        f"  tool dispatches: {result.metrics.tool_dispatches}",
        f"  findings: {result.metrics.findings}",
    ]
    return "\n".join(lines)


def summarize(
    results: tuple[EvaluationResult, ...], *, evaluated_at: Timestamp
) -> EvaluationSummary:
    """Summarize evaluations of one contract identity without combining security and utility."""
    if not results:
        raise EvaluationError("EMPTY_EVALUATION_SUMMARY")
    first = results[0]
    if any(
        (r.contract_id, r.effective_policy_hash) != (first.contract_id, first.effective_policy_hash)
        for r in results
    ):
        raise EvaluationError("SUMMARY_CONTRACT_MISMATCH")
    return EvaluationSummary(
        schema_version="0.1",
        evaluated_at=evaluated_at,
        contract_id=first.contract_id,
        effective_policy_hash=first.effective_policy_hash,
        results=results,
        counts=EvaluationCounts(
            passed=sum(r.overall_status == EvaluationStatus.PASS for r in results),
            failed=sum(r.overall_status == EvaluationStatus.FAIL for r in results),
            inconclusive=sum(r.overall_status == EvaluationStatus.INCONCLUSIVE for r in results),
            errors=sum(r.overall_status == EvaluationStatus.ERROR for r in results),
        ),
    )
