"""Reuse evaluation assertion/finding semantics over content-free replay observations."""

from agentsec.domain.findings import Finding
from agentsec.domain.replay import ReplayProgram
from agentsec.domain.scenarios import Scenario, ScenarioSetup, ScenarioTask
from agentsec.domain.taxonomy import SecurityCategory
from agentsec.eval.assertions import evaluate_assertion
from agentsec.eval.findings import project_findings
from agentsec.eval.models import AssertionResult
from agentsec.eval.observations import EvaluationObservation, ObservationCoverage


def evaluate_program(
    program: ReplayProgram,
    *,
    complete: bool,
    source_findings: bool = False,
) -> tuple[tuple[AssertionResult, ...], tuple[Finding, ...]]:
    if not program.expectations:
        return (), program.findings if source_findings else ()
    scenario = Scenario(
        schema_version="0.1",
        scenario_id="replay-assertions",
        title="Replay expectations",
        attack_family=SecurityCategory.POLICY_BYPASS,
        setup=ScenarioSetup(tools=program.tools),
        task=ScenarioTask(task_id="replay-task", user_input="Structured replay"),
        assertions=program.expectations,
    )
    observation = EvaluationObservation(
        scenario_id="replay-assertions",
        run_id=program.events[0].run_id if program.events else "replay-run",
        trace_id=program.events[0].trace_id if program.events else "replay-trace",
        events=program.events,
        findings=program.findings if source_findings else (),
        coverage=ObservationCoverage(event_stream_complete=complete),
    )
    # Source finding scenario/run references were validated before this reporting projection.
    findings = project_findings(scenario, observation)
    observation = observation.model_copy(update={"findings": findings})
    return tuple(
        evaluate_assertion(a, i, scenario, observation) for i, a in enumerate(program.expectations)
    ), findings
