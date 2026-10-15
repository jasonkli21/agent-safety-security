"""Local orchestration, content-minimized results, and evidence failure handling."""

from pathlib import Path

from agentsec.contracts.canonical import effective_policy_hash
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.events import RunStartedPayload
from agentsec.domain.scenarios import Scenario
from agentsec.domain.taxonomy import EventType
from agentsec.eval.assertions import evaluate_assertion
from agentsec.eval.findings import project_findings
from agentsec.eval.models import EvaluationMetrics, EvaluationResult, aggregate
from agentsec.eval.models import EvaluationStatus as Status
from agentsec.eval.ports import AgentTarget, EvaluationContext
from agentsec.eval.trajectory import EvaluationError, require, validate_evaluation_trajectory
from agentsec.evidence.jsonl import EvidenceError, JsonlEventSink


def evaluate(
    *,
    contract: AgentSecurityContract,
    scenario: Scenario,
    target: AgentTarget,
    context: EvaluationContext | None = None,
    evidence_out: Path | None = None,
) -> EvaluationResult:
    context = context or EvaluationContext()
    require(not context.recorder.events, "CONTEXT_ALREADY_USED")
    context.run_id = context.new_id("run")
    context.trace_id = context.new_id("trace")

    def result(security: Status, utility: Status, error: str | None = None) -> EvaluationResult:
        return EvaluationResult(
            schema_version="0.1",
            scenario_id=scenario.scenario_id,
            contract_id=contract.metadata.contract_id,
            effective_policy_hash=effective_policy_hash(contract),
            run_id=context.run_id,
            trace_id=context.trace_id,
            security_status=security,
            utility_status=utility,
            overall_status=aggregate((security, utility)),
            error_code=error,
        )

    try:
        observation = target.run(contract=contract, scenario=scenario, context=context)
        require(
            observation.scenario_id == scenario.scenario_id
            and observation.run_id == context.run_id
            and observation.trace_id == context.trace_id,
            "OBSERVATION_IDENTITY_MISMATCH",
        )
        validate_evaluation_trajectory(observation)
        for event in observation.events:
            if isinstance(event.payload, RunStartedPayload):
                require(
                    event.payload.contract_id == contract.metadata.contract_id
                    and event.payload.effective_policy_hash == effective_policy_hash(contract),
                    "CONTRACT_MISMATCH",
                )
        if evidence_out is not None:
            with JsonlEventSink(evidence_out) as sink:
                for event in observation.events:
                    sink.append(event)
        observation = observation.model_copy(
            update={"findings": project_findings(scenario, observation)}
        )
        security = tuple(
            evaluate_assertion(a, i, scenario, observation)
            for i, a in enumerate(scenario.assertions)
        )
        utility = tuple(
            evaluate_assertion(a, i, scenario, observation)
            for i, a in enumerate(scenario.utility_assertions)
        )
        counts = {kind: sum(e.event_type == kind for e in observation.events) for kind in EventType}
        metrics = EvaluationMetrics(
            tool_requests=counts[EventType.TOOL_REQUESTED],
            tool_dispatches=counts[EventType.TOOL_DISPATCHED],
            tool_returns=counts[EventType.TOOL_RETURNED],
            approval_requests=counts[EventType.APPROVAL_REQUESTED],
            approval_decisions=counts[EventType.APPROVAL_DECIDED],
            security_signals=counts[EventType.SECURITY_SIGNAL],
            findings=len(observation.findings),
            security_assertions_passed=sum(a.status == Status.PASS for a in security),
            security_assertions_failed=sum(a.status == Status.FAIL for a in security),
            security_assertions_inconclusive=sum(a.status == Status.INCONCLUSIVE for a in security),
            utility_assertions_passed=sum(a.status == Status.PASS for a in utility),
            utility_assertions_failed=sum(a.status == Status.FAIL for a in utility),
            utility_assertions_inconclusive=sum(a.status == Status.INCONCLUSIVE for a in utility),
        )
        base = result(
            aggregate(tuple(a.status for a in security)),
            aggregate(tuple(a.status for a in utility)),
        )
        return base.model_copy(
            update={
                "security_assertions": security,
                "utility_assertions": utility,
                "findings": observation.findings,
                "metrics": metrics,
            }
        )
    except (EvaluationError, EvidenceError) as exc:
        return result(Status.ERROR, Status.ERROR, exc.code)
