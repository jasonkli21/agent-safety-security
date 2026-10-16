"""Synthetic contract conformance through Phase 1 evidence and assertion semantics."""

from datetime import UTC, datetime

from agentsec.compiler import CompiledSecurityPlan, compile_contract
from agentsec.compiler.probes import PolicyProbe, generate_probes
from agentsec.compiler.reporting import ConformanceReport, ProbeResult, Status, run_conformance
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.events import PolicyEvaluatedPayload, ToolRequestedPayload
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.provenance import DataArtifactRef, DataOrigin
from agentsec.domain.scenarios import (
    ApprovalRequired,
    MockResponse,
    Scenario,
    ScenarioSetup,
    ScenarioTask,
    ToolCalled,
    ToolNotCalled,
)
from agentsec.domain.taxonomy import (
    ApprovalOutcome,
    PolicyOutcome,
    SecurityCategory,
    SideEffectClass,
    TrustClass,
)
from agentsec.domain.tools import ToolDescriptor
from agentsec.eval.fixtures import FinishStep, FixtureTarget, TargetFixture, ToolCallStep
from agentsec.eval.ports import EvaluationContext
from agentsec.eval.runner import evaluate
from agentsec.eval.trajectory import EvaluationError
from agentsec.policy.native import NativePolicyEngine
from agentsec.policy.ports import PolicyEngine


def case_scenario(plan: CompiledSecurityPlan, probe: PolicyProbe) -> Scenario:
    tool = ToolDescriptor(
        schema_version="0.1",
        tool_id="conformance-tool",
        namespace="conformance",
        name="Synthetic tool",
        protocol="synthetic",
        description="No external execution",
        input_schema={"type": "object"},
        side_effect_class=SideEffectClass.READ,
        capabilities=frozenset({probe.capability}),
    )
    assertion = (
        ToolCalled(type="TOOL_CALLED", tool_id=tool.tool_id)
        if probe.expected == PolicyOutcome.ALLOW
        else ApprovalRequired(type="APPROVAL_REQUIRED", capability=probe.capability)
        if probe.expected == PolicyOutcome.REQUIRE_APPROVAL
        else ToolNotCalled(type="TOOL_NOT_CALLED", tool_id=tool.tool_id)
    )
    source_tool = ToolDescriptor(
        schema_version="0.1",
        tool_id="conformance-source",
        namespace="conformance",
        name="Synthetic source tool",
        protocol="synthetic",
        description="No external execution",
        input_schema={"type": "object"},
        side_effect_class=SideEffectClass.READ,
        capabilities=frozenset({probe.capability}),
    )
    tools = (tool, source_tool) if probe.data_artifact_refs else (tool,)
    mock_responses = tuple(
        MockResponse(tool_id=t.tool_id, response={})
        for t in tools
        for _ in (range(2) if t.tool_id == tool.tool_id and probe.data_artifact_refs else range(1))
    )
    return Scenario(
        schema_version="0.1",
        scenario_id=probe.probe_id,
        title="Contract conformance",
        attack_family=SecurityCategory.POLICY_BYPASS,
        tags=frozenset({"contract-conformance"}),
        setup=ScenarioSetup(tools=tools, mock_responses=mock_responses),
        task=ScenarioTask(
            task_id=plan.scope.task_id if plan.scope else "conformance-task",
            user_input="Exercise one synthetic policy obligation",
            task_scope=plan.task_scope,
        ),
        assertions=(assertion,),
    )


class ContractTarget(FixtureTarget):
    """Reuse canonical emission; actual policy controls approval and dispatch evidence."""

    def __init__(
        self, plan: CompiledSecurityPlan, probe: PolicyProbe, engine: PolicyEngine | None = None
    ) -> None:
        flow_labels = frozenset(label for ref in probe.data_artifact_refs for label in ref.labels)
        source_artifacts = (
            (
                DataArtifactRef(
                    schema_version="0.1",
                    artifact_id=f"{probe.probe_id}-source",
                    labels=flow_labels,
                    origin=DataOrigin(
                        origin_type="synthetic",
                        source_id="conformance-source",
                        trust_class=TrustClass.TOOL_OUTPUT,
                    ),
                    created_at=datetime(2026, 1, 1, tzinfo=UTC),
                ),
            )
            if probe.data_artifact_refs
            else ()
        )
        steps: tuple[ToolCallStep | FinishStep, ...] = (
            (
                ToolCallStep(
                    type="TOOL_CALL",
                    tool_id="conformance-source",
                    capability=probe.capability,
                    resource=probe.resource,
                    arguments={},
                    response_artifacts=source_artifacts,
                ),
            )
            if source_artifacts
            else ()
        ) + (
            ToolCallStep(
                type="TOOL_CALL",
                tool_id="conformance-tool",
                capability=probe.capability,
                resource=probe.resource,
                arguments={},
                data_artifact_refs=source_artifacts or probe.data_artifact_refs,
                data_destination=probe.data_destination,
            ),
            FinishStep(type="FINISH"),
        )
        super().__init__(
            TargetFixture(
                schema_version="0.1",
                fixture_id=probe.probe_id,
                scenario_id=probe.probe_id,
                steps=steps,
            )
        )
        self.plan, self.engine = plan, engine or NativePolicyEngine()

    def approval_outcome(self, step: ToolCallStep) -> ApprovalOutcome:
        return ApprovalOutcome.APPROVE

    def policy_decision(
        self,
        request: PolicyRequest,
        step: ToolCallStep,
        contract: AgentSecurityContract,
        context: EvaluationContext,
    ) -> PolicyDecision:
        if self.plan != compile_contract(contract):
            raise EvaluationError("STALE_COMPILED_PLAN")
        try:
            return self.engine.decide(request, self.plan)
        except Exception as exc:
            raise EvaluationError("POLICY_ENGINE_ERROR") from exc


def run_contract_cases(
    contract: AgentSecurityContract, plan: CompiledSecurityPlan, engine: PolicyEngine | None = None
) -> tuple[ProbeResult, ...]:
    rows = []
    for probe in generate_probes(plan):
        if not probe.derivable:
            rows.append(
                ProbeResult(
                    schema_version="0.1",
                    probe_id=probe.probe_id,
                    status="NOT_RUN",
                    obligation_kind=probe.obligation_kind,
                    expected=probe.expected,
                    not_derivable_reason="No base-permitted witness for this flow obligation",
                )
            )
            continue
        context = EvaluationContext()
        result = evaluate(
            contract=contract,
            scenario=case_scenario(plan, probe),
            target=ContractTarget(plan, probe, engine),
            context=context,
        )
        sink_request_ids = {
            event.payload.request.request_id
            for event in context.recorder.events
            if isinstance(event.payload, ToolRequestedPayload)
            and event.payload.request.tool_id == "conformance-tool"
        }
        decisions = [
            e.payload.decision
            for e in context.recorder.events
            if isinstance(e.payload, PolicyEvaluatedPayload)
            and e.payload.decision.request_id in sink_request_ids
        ]
        status: Status = "ERROR" if result.error_code else "FAIL"
        if result.overall_status.value == "PASS" and len(decisions) == 1:
            decision = decisions[0]
            if (
                decision.outcome == probe.expected
                and decision.reason_codes == frozenset({probe.reason})
                and decision.matched_rule_ids == probe.matched_rule_ids
            ):
                status = "PASS"
        rows.append(
            ProbeResult(
                schema_version="0.1",
                probe_id=probe.probe_id,
                status=status,
                obligation_kind=probe.obligation_kind,
                expected=probe.expected,
                actual=decisions[0].outcome if len(decisions) == 1 else None,
            )
        )
    return tuple(rows)


def test_contract(contract: AgentSecurityContract) -> ConformanceReport:
    plan = compile_contract(contract)
    direct = run_conformance(plan)
    return direct.model_copy(update={"eval_cases": run_contract_cases(contract, plan)})
