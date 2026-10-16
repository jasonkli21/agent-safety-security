"""Fail-closed corpus validation and execution, with explicit draft accounting."""

from pathlib import Path

from agentsec.compiler.models import CompiledSecurityPlan
from agentsec.contracts.loader import load_artifact
from agentsec.domain.events import RunStartedPayload, ToolRequestedPayload
from agentsec.domain.replay import (
    Fidelity,
    RegressionCase,
    RegressionState,
    ReplayAssessment,
    ReplayError,
    SourceBinding,
)
from agentsec.domain.scenarios import ApprovalRequired, MaxToolCalls, ToolNotCalled
from agentsec.eval.models import EvaluationStatus
from agentsec.replay.bundle import validate_program
from agentsec.replay.engine import run_program


def validate_case(case: RegressionCase) -> None:
    # Revalidate unchecked Python copies as well as file-loaded objects.
    RegressionCase.model_validate_json(case.model_dump_json(round_trip=True))
    if case.program is not None:
        validate_program(case.program)
    if case.state == RegressionState.DRAFT:
        return
    assert case.program is not None and case.plan is not None
    tools = {t.tool_id: t for t in case.program.tools}
    if case.plan.gaps or case.plan.budgets.max_runtime_seconds is not None:
        raise ReplayError("UNSUPPORTED_REGRESSION_PLAN")
    if any(
        isinstance(e.payload, ToolRequestedPayload)
        and (
            e.payload.request.tool_id not in tools
            or e.payload.request.capability not in tools[e.payload.request.tool_id].capabilities
        )
        for e in case.program.events
    ):
        raise ReplayError("MISSING_REGRESSION_TOOL_METADATA")
    start = case.program.events[0].payload
    assert isinstance(start, RunStartedPayload)
    if (start.contract_id, start.effective_policy_hash) != (
        case.plan.contract_id,
        case.plan.effective_policy_hash,
    ) or (start.plan_identity is not None and start.plan_identity != case.plan.identity):
        raise ReplayError("REGRESSION_PLAN_MISMATCH")
    if any(
        isinstance(e.payload, ToolRequestedPayload) and e.payload.redacted_fields
        for e in case.program.events
    ):
        raise ReplayError("MATERIAL_REDACTION")
    if any(
        not isinstance(a, (ToolNotCalled, MaxToolCalls, ApprovalRequired))
        for a in case.program.expectations
    ):
        raise ReplayError("UNSUPPORTED_REGRESSION_ASSERTION")


def run_case(case: RegressionCase, current: CompiledSecurityPlan | None = None) -> str:
    validate_case(case)
    if case.state == RegressionState.DRAFT:
        return "DRAFT"
    assert case.program is not None and case.plan is not None
    result = run_program(
        case.program,
        case.plan,
        current or case.current_plan or case.plan,
        source_digest=case.source_bundle_digest,
        assessment=ReplayAssessment(
            fidelity=Fidelity.SECURITY_RUNTIME, source_binding=SourceBinding.LEGACY_INFERRED
        ),
    )
    if result.assessment.blockers or not result.assertions:
        return "ERROR"
    if all(a.status == EvaluationStatus.PASS for a in result.assertions):
        return "PASS"
    return "FAIL"


def load_corpus(root: Path) -> tuple[RegressionCase, ...]:
    paths = sorted(root.rglob("*.json"))
    if not root.is_dir() or not paths:
        raise ReplayError("REGRESSION_CORPUS_EMPTY")
    cases = tuple(load_artifact(p, RegressionCase) for p in paths)
    if len({c.regression_id for c in cases}) != len(cases):
        raise ReplayError("DUPLICATE_REGRESSION_ID")
    for case in cases:
        validate_case(case)
    return cases
