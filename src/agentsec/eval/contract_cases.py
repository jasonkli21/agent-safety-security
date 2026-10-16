"""Synthetic contract conformance through Phase 1 evidence and assertion semantics."""

from agentsec.compiler import CompiledSecurityPlan, compile_contract
from agentsec.compiler.probes import PolicyProbe, generate_probes
from agentsec.compiler.reporting import ConformanceReport, ProbeResult, Status, run_conformance
from agentsec.contracts.canonical import effective_policy_hash
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.events import PolicyEvaluatedPayload
from agentsec.domain.policy import PolicyDecision, PolicyRequest
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
    return Scenario(
        schema_version="0.1",
        scenario_id=probe.probe_id,
        title="Contract conformance",
        attack_family=SecurityCategory.POLICY_BYPASS,
        tags=frozenset({"contract-conformance"}),
        setup=ScenarioSetup(
            tools=(tool,), mock_responses=(MockResponse(tool_id=tool.tool_id, response={}),)
        ),
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
        super().__init__(
            TargetFixture(
                schema_version="0.1",
                fixture_id=probe.probe_id,
                scenario_id=probe.probe_id,
                steps=(
                    ToolCallStep(
                        type="TOOL_CALL",
                        tool_id="conformance-tool",
                        capability=probe.capability,
                        resource=probe.resource,
                        arguments={},
                    ),
                    FinishStep(type="FINISH"),
                ),
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
        if (
            self.plan.contract_id != contract.metadata.contract_id
            or self.plan.effective_policy_hash != effective_policy_hash(contract)
        ):
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
        context = EvaluationContext()
        result = evaluate(
            contract=contract,
            scenario=case_scenario(plan, probe),
            target=ContractTarget(plan, probe, engine),
            context=context,
        )
        decisions = [
            e.payload.decision
            for e in context.recorder.events
            if isinstance(e.payload, PolicyEvaluatedPayload)
        ]
        status: Status = "ERROR" if result.error_code else "FAIL"
        if result.overall_status.value == "PASS" and len(decisions) == 1:
            decision = decisions[0]
            if decision.outcome == probe.expected and probe.reason in decision.reason_codes:
                status = "PASS"
        rows.append(
            ProbeResult(
                schema_version="0.1",
                probe_id=probe.probe_id,
                status=status,
                expected=probe.expected,
                actual=decisions[0].outcome if len(decisions) == 1 else None,
            )
        )
    return tuple(rows)


def test_contract(contract: AgentSecurityContract) -> ConformanceReport:
    plan = compile_contract(contract)
    direct = run_conformance(plan)
    return direct.model_copy(update={"eval_cases": run_contract_cases(contract, plan)})
