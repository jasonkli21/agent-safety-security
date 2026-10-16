"""Evaluation-time causality, separate from Phase 0 sequence validation."""

from agentsec.contracts.errors import ArtifactValidationError
from agentsec.domain.events import (
    ApprovalDecidedPayload,
    ApprovalRequestedPayload,
    EffectVerifiedPayload,
    PolicyEvaluatedPayload,
    RunStartedPayload,
    ToolDispatchedPayload,
    ToolRequestedPayload,
    ToolReturnedPayload,
    validate_event_sequence,
)
from agentsec.domain.taxonomy import ApprovalOutcome, EnforcementMode, EventType, PolicyOutcome
from agentsec.eval.observations import EvaluationObservation, TextSurface


class EvaluationError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str = "INVALID_TRAJECTORY") -> None:
    if not condition:
        raise EvaluationError(code)


def validate_evaluation_trajectory(observation: EvaluationObservation) -> None:
    events = observation.events
    try:
        validate_event_sequence(list(events))
    except ArtifactValidationError as exc:
        raise EvaluationError("INVALID_TRAJECTORY") from exc
    requests: dict[str, ToolRequestedPayload] = {}
    decisions: dict[str, PolicyEvaluatedPayload] = {}
    request_decisions: set[str] = set()
    approvals: dict[str, ApprovalRequestedPayload] = {}
    approved: dict[str, ApprovalDecidedPayload] = {}
    dispatches: dict[str, ToolDispatchedPayload] = {}
    returns: set[str] = set()
    redeemed: set[str] = set()
    start: RunStartedPayload | None = None
    terminal = False
    for index, event in enumerate(events):
        require(event.run_id == observation.run_id and event.trace_id == observation.trace_id)
        require(not terminal)
        p = event.payload
        if isinstance(p, RunStartedPayload):
            require(index == 0 and start is None)
            require(p.scenario_id == observation.scenario_id)
            start = p
        elif event.event_type in {EventType.RUN_FINISHED, EventType.RUN_TERMINATED}:
            terminal = True
        elif isinstance(p, ToolRequestedPayload):
            require(p.request.request_id not in requests)
            requests[p.request.request_id] = p
        elif isinstance(p, PolicyEvaluatedPayload):
            d = p.decision
            require(d.request_id in requests and d.decision_id not in decisions)
            require(d.request_id not in request_decisions)
            if start is not None:
                require(
                    d.contract_id == start.contract_id
                    and d.effective_policy_hash == start.effective_policy_hash
                )
            decisions[d.decision_id] = p
            request_decisions.add(d.request_id)
        elif isinstance(p, ApprovalRequestedPayload):
            a = p.approval
            require(a.policy_request_id in requests and a.approval_id not in approvals)
            require(a.action_digest == requests[a.policy_request_id].action_digest)
            require(
                any(
                    d.decision.request_id == a.policy_request_id
                    and d.decision.outcome == PolicyOutcome.REQUIRE_APPROVAL
                    for d in decisions.values()
                )
            )
            approvals[a.approval_id] = p
        elif isinstance(p, ApprovalDecidedPayload):
            approval_decision = p.decision
            require(
                approval_decision.approval_id in approvals
                and approval_decision.approval_id not in approved
            )
            a = approvals[approval_decision.approval_id].approval
            require(approval_decision.decided_at >= a.created_at)
            require(a.expires_at is None or approval_decision.decided_at < a.expires_at)
            approved[approval_decision.approval_id] = p
        elif isinstance(p, ToolDispatchedPayload):
            require(p.enforcement_mode == EnforcementMode.ENFORCE)
            require(p.request_id in requests and p.decision_id in decisions)
            require(p.dispatch_id not in dispatches)
            r = requests[p.request_id]
            assert p.decision_id is not None
            d = decisions[p.decision_id].decision
            require(p.tool_id == r.request.tool_id and p.action_digest == r.action_digest)
            require(d.request_id == p.request_id)
            require(d.outcome in {PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL})
            if d.outcome == PolicyOutcome.REQUIRE_APPROVAL:
                require(p.approval_id in approved)
            if p.approval_id is not None:
                require(p.approval_id in approved and p.approval_id not in redeemed)
                a = approvals[p.approval_id].approval
                require(a.policy_request_id == p.request_id and a.action_digest == p.action_digest)
                require(approved[p.approval_id].decision.outcome == ApprovalOutcome.APPROVE)
                require(a.expires_at is None or event.occurred_at < a.expires_at)
                redeemed.add(p.approval_id)
            dispatches[p.dispatch_id] = p
        elif isinstance(p, (ToolReturnedPayload, EffectVerifiedPayload)):
            require(p.dispatch_id in dispatches)
            dispatch = dispatches[p.dispatch_id]
            require(p.request_id == dispatch.request_id)
            if isinstance(p, ToolReturnedPayload):
                require(p.tool_id == dispatch.tool_id and p.dispatch_id not in returns)
                returns.add(p.dispatch_id)
    if observation.coverage.event_stream_complete:
        require(start is not None and terminal)
    source_ids = [t.source_id for t in observation.text_observations]
    require(len(source_ids) == len(set(source_ids)), "INVALID_OBSERVATION")
    event_map = {e.event_id: e for e in events}
    captured_requests: set[str] = set()
    for text in observation.text_observations:
        if text.surface == TextSurface.TOOL_ARGUMENT:
            require(text.source_id in event_map, "INVALID_OBSERVATION")
            source = event_map[text.source_id].payload
            require(isinstance(source, ToolRequestedPayload), "INVALID_OBSERVATION")
            if isinstance(source, ToolRequestedPayload):
                captured_requests.add(source.request.request_id)
    if observation.coverage.tool_arguments_complete:
        require(captured_requests == set(requests), "INVALID_OBSERVATION")
    finding_ids = [f.finding_id for f in observation.findings]
    require(len(finding_ids) == len(set(finding_ids)), "INVALID_OBSERVATION")
    for finding in observation.findings:
        require(
            finding.run_id in {None, observation.run_id}
            and finding.scenario_id in {None, observation.scenario_id},
            "INVALID_OBSERVATION",
        )
        require(finding.event_refs <= event_map.keys(), "INVALID_OBSERVATION")
