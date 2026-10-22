"""Minimal graph incident manifests; protected replay material is supplied separately."""

from typing import Literal

from agentsec.domain.base import Digest, Identifier, VersionedModel
from agentsec.domain.replay import Incident, ReplayBundle, ReplayError
from agentsec.domain.scenarios import (
    ApprovalRequired,
    Assertion,
    MaxToolCalls,
    Scenario,
    ScenarioSetup,
    ScenarioTask,
    ToolNotCalled,
)
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import SecurityCategory
from agentsec.eval.assertions import evaluate_assertion
from agentsec.eval.models import AssertionResult, EvaluationStatus
from agentsec.eval.observations import EvaluationObservation, ObservationCoverage
from agentsec.incident.classify import classify
from agentsec.multi_agent.replay import GraphReplayInput, replay_graph


class GraphRegressionCase(VersionedModel):
    regression_id: Identifier
    source_incident_id: Identifier
    source_bundle_digest: Digest
    source_session_evidence_digest: Digest
    source_graph_digest: Digest | None
    node_id: Identifier
    state: Literal["ACTIVE", "DRAFT"]
    reason: Identifier
    expectations: tuple[Assertion, ...]


class GraphRegressionResult(VersionedModel):
    regression_id: Identifier
    status: Literal["PASS", "FAIL", "BLOCKED"]
    blockers: frozenset[str] = frozenset()
    assertions: tuple[AssertionResult, ...] = ()


def promote_graph(
    bundle: ReplayBundle,
    incident: Incident,
    source: GraphReplayInput,
    node_id: str,
) -> GraphRegressionCase:
    """Never exports graph grants, requests, action arguments or credential facts."""
    source = GraphReplayInput.model_validate_json(source.model_dump_json(round_trip=True))
    operator = [b for b in incident.classification_basis if b.rule == "OPERATOR_SUPPLIED"]
    if (
        len(operator) > 1
        or classify(bundle, operator[0].category if operator else None) != incident
    ):
        raise ReplayError("INCIDENT_BINDING_MISMATCH")
    if source.material is None:
        graph_digest = None
    else:
        graph_digest = source.material.graph.digest
    if source.material is not None and node_id not in {
        p.node_id for p in source.material.participants
    }:
        raise ReplayError("GRAPH_INCIDENT_SOURCE_MISMATCH")
    subset = tuple(e for e in source.events if e.run_id == bundle.source_run_id)
    if subset != bundle.program.events or (
        source.material is not None
        and source.material.participant(node_id).plan != bundle.source_plan
    ):
        raise ReplayError("GRAPH_INCIDENT_SOURCE_MISMATCH")
    reason: str = "EXPLICIT_SAFE_EXPECTATIONS_EXTERNAL_PROTECTED_SOURCE"
    active = bool(bundle.program.expectations) and all(
        isinstance(
            a,
            (
                ToolNotCalled,
                MaxToolCalls,
                ApprovalRequired,
            ),
        )
        for a in bundle.program.expectations
    )
    if not active:
        reason = "PROMOTION_EXPECTATION_REVIEW"
    elif replay_graph(source).blockers:
        active, reason = False, "PROMOTION_INCOMPLETE_GRAPH_INPUT"
    return GraphRegressionCase(
        schema_version="0.1",
        regression_id="graph-regression-"
        + content_digest(
            (
                incident.incident_id,
                source.source_evidence_digest,
                node_id,
                bundle.program.expectations,
            )
        )[7:31],
        source_incident_id=incident.incident_id,
        source_bundle_digest=bundle.bundle_digest,
        source_session_evidence_digest=source.source_evidence_digest,
        source_graph_digest=graph_digest,
        node_id=node_id,
        state="ACTIVE" if active else "DRAFT",
        reason=reason,
        expectations=bundle.program.expectations,
    )


def run_graph_case(case: GraphRegressionCase, source: GraphReplayInput) -> GraphRegressionResult:
    case = GraphRegressionCase.model_validate_json(case.model_dump_json())
    source = GraphReplayInput.model_validate_json(source.model_dump_json(round_trip=True))
    blockers = set(replay_graph(source).blockers)
    if case.state != "ACTIVE":
        blockers.add("DRAFT_GRAPH_REGRESSION")
    if source.source_evidence_digest != case.source_session_evidence_digest or (
        source.material is None or source.material.graph.digest != case.source_graph_digest
    ):
        blockers.add("GRAPH_REGRESSION_SOURCE_MISMATCH")
    if not case.expectations or any(
        not isinstance(
            a,
            (
                ToolNotCalled,
                MaxToolCalls,
                ApprovalRequired,
            ),
        )
        for a in case.expectations
    ):
        blockers.add("UNSUPPORTED_GRAPH_EXPECTATION")
    if source.material is not None and case.node_id not in {
        p.node_id for p in source.material.participants
    }:
        blockers.add("GRAPH_RUN_BINDING_MISSING")
    if blockers:
        return GraphRegressionResult(
            schema_version="0.1",
            regression_id=case.regression_id,
            status="BLOCKED",
            blockers=frozenset(blockers),
        )
    # Reuse the Phase 1 assertion semantics over the selected validated source run.
    assert source.material is not None
    plan = source.material.participant(case.node_id).plan
    run_ids = {
        e.run_id
        for e in source.events
        if getattr(e.payload, "plan_identity", None) == plan.identity
    }
    if len(run_ids) != 1:
        return GraphRegressionResult(
            schema_version="0.1",
            regression_id=case.regression_id,
            status="BLOCKED",
            blockers=frozenset({"GRAPH_RUN_BINDING_MISSING"}),
        )
    run_id = next(iter(run_ids))
    events = tuple(e for e in source.events if e.run_id == run_id)
    scenario = Scenario(
        schema_version="0.1",
        scenario_id="graph-regression",
        title="Reviewed graph incident",
        attack_family=SecurityCategory.DELEGATION_ESCALATION,
        setup=ScenarioSetup(tools=source.tools),
        task=ScenarioTask(task_id="graph-regression", user_input="Replay recorded facts"),
        assertions=case.expectations,
    )
    observation = EvaluationObservation(
        scenario_id=scenario.scenario_id,
        run_id=run_id,
        trace_id=events[0].trace_id,
        events=events,
        coverage=ObservationCoverage(event_stream_complete=True),
    )
    results = tuple(
        evaluate_assertion(a, i, scenario, observation) for i, a in enumerate(case.expectations)
    )
    return GraphRegressionResult(
        schema_version="0.1",
        regression_id=case.regression_id,
        status="PASS" if all(r.status == EvaluationStatus.PASS for r in results) else "FAIL",
        assertions=results,
    )
