"""Offline local graph security-semantic reconstruction. No provider or dispatcher ports."""

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from agentsec.domain.approvals import NormalizedAction, action_digest
from agentsec.domain.base import Digest, VersionedModel
from agentsec.domain.events import (
    ApprovalDecidedPayload,
    ApprovalRequestedPayload,
    DataExposedPayload,
    GraphEventPayload,
    PolicyEvaluatedPayload,
    RunFinishedPayload,
    RunStartedPayload,
    SecurityEvent,
    SecuritySignalPayload,
    ToolDispatchedPayload,
    ToolRequestedPayload,
    ToolReturnedPayload,
    validate_event_sequence,
)
from agentsec.domain.graph import GraphSnapshot
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.replay import ReplayError, ReplayProgram
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import DataLabel, EnforcementMode, PolicyOutcome
from agentsec.domain.tools import ToolDescriptor
from agentsec.multi_agent.authority import GraphMaterial, check_path, decide_path
from agentsec.multi_agent.budgets import HierarchicalBudgets
from agentsec.provenance.engine import ProvenanceEngine
from agentsec.replay.bundle import validate_program
from agentsec.runtime.approvals import ApprovalLedger
from agentsec.runtime.models import RuntimeFailure


class GraphReplayInput(VersionedModel):
    events: Annotated[tuple[SecurityEvent, ...], Field(min_length=1, max_length=8192)]
    source_evidence_digest: Digest
    material: GraphMaterial | None = None
    requests: Annotated[tuple[PolicyRequest, ...], Field(max_length=1024)] = ()
    actions: Annotated[tuple[NormalizedAction, ...], Field(max_length=1024)] = ()
    tools: Annotated[tuple[ToolDescriptor, ...], Field(max_length=128)] = ()

    @model_validator(mode="after")
    def commitments(self) -> Self:
        validate_event_sequence(list(self.events))
        if content_digest(self.events) != self.source_evidence_digest:
            raise ValueError("GRAPH_REPLAY_EVIDENCE_DIGEST_MISMATCH")
        for keys in (
            [r.request_id for r in self.requests],
            [t.tool_id for t in self.tools],
            [action_digest(a) for a in self.actions],
        ):
            if len(keys) != len(set(keys)):
                raise ValueError("GRAPH_REPLAY_DUPLICATE_MATERIAL")
        return self


class GraphReplayResult(VersionedModel):
    source_evidence_digest: Digest
    fidelity: Literal["SECURITY_SEMANTIC", "INCOMPLETE"]
    blockers: frozenset[str]
    candidate_graph_comparison: Literal["UNKNOWN", "UNCHANGED", "CHANGED", "INCOMPLETE"]
    checked_requests: int
    checked_deliveries: int
    limitations: frozenset[str] = frozenset(
        {
            "RECORDED_FACTS_NOT_AUTHENTICATED",
            "NO_LIVE_EFFECTS",
            "NO_CONTENT_OR_MODEL_REPLAY",
            "NO_RUNTIME_ATTESTATION",
            "SINGLE_RECORDED_GRAPH_EPOCH",
        }
    )


def replay_graph(
    source: GraphReplayInput,
    *,
    candidate_graph: GraphSnapshot | None = None,
) -> GraphReplayResult:
    source = GraphReplayInput.model_validate_json(source.model_dump_json(round_trip=True))
    blockers: set[str] = set()
    for run_id in {e.run_id for e in source.events}:
        try:
            if not validate_program(
                ReplayProgram(
                    schema_version="0.1",
                    events=tuple(e for e in source.events if e.run_id == run_id),
                    tools=source.tools,
                )
            ):
                blockers.add("INCOMPLETE_SOURCE_STREAM")
        except ReplayError as exc:
            blockers.add(exc.code)
    material = source.material
    comparison: Literal["UNKNOWN", "UNCHANGED", "CHANGED", "INCOMPLETE"] = "UNKNOWN"
    checked = deliveries = 0
    if material is None:
        blockers.add("MISSING_GRAPH_ANCESTOR_MATERIAL")
        if candidate_graph is not None:
            comparison = "INCOMPLETE"
    else:
        if candidate_graph is not None:
            comparison = "UNCHANGED" if material.graph == candidate_graph else "CHANGED"
        if any(p.plan.budgets.max_runtime_seconds is not None for p in material.participants):
            blockers.add("MISSING_MONOTONIC_DURATION")
        now = source.events[0].occurred_at
        budgets = HierarchicalBudgets(lambda: material, lambda: None, lambda: 0.0)
        approvals = ApprovalLedger(lambda: now)
        requests: dict[str, PolicyRequest] = {}
        request_payloads: dict[str, ToolRequestedPayload] = {}
        decisions: dict[str, PolicyDecision] = {}
        tokens: dict[str, str] = {}
        dispatches: dict[str, SecurityEvent] = {}
        runs: dict[str, str] = {}
        active: set[str] = set()
        terminated: set[str] = set()
        starts: dict[str, RunStartedPayload] = {}
        sent: dict[str, GraphEventPayload] = {}
        imported: set[str] = set()
        provenance = {p.node_id: ProvenanceEngine(lambda: now) for p in material.participants}
        supplied = {r.request_id: r for r in source.requests}
        actions = {action_digest(a): a for a in source.actions}
        tools = {t.tool_id: t for t in source.tools}
        for event in source.events:
            now = event.occurred_at
            p = event.payload
            try:
                if isinstance(p, RunStartedPayload):
                    if event.run_id in starts:
                        raise RuntimeFailure("GRAPH_DUPLICATE_RUN")
                    starts[event.run_id] = p
                elif isinstance(p, GraphEventPayload):
                    check_path(material, p.binding, now)
                    if p.operation == "RECONFIGURED":
                        blockers.add("GRAPH_EPOCH_HISTORY_UNAVAILABLE")
                    elif p.operation == "ADMITTED":
                        node = p.binding.node_id
                        if node in active or event.run_id in runs:
                            raise RuntimeFailure("GRAPH_DUPLICATE_ADMISSION")
                        if not set(p.binding.path[:-1]) <= active:
                            raise RuntimeFailure("GRAPH_ANCESTOR_INACTIVE")
                        start = starts.get(event.run_id)
                        if (
                            start is None
                            or start.plan_identity != material.participant(node).plan.identity
                        ):
                            raise RuntimeFailure("GRAPH_SOURCE_PLAN_MISMATCH")
                        budgets.admit(node)
                        active.add(node)
                        runs[event.run_id] = node
                    elif p.operation == "REVOKED":
                        active.discard(p.binding.node_id)

                    else:
                        if p.peer_binding is None or p.message_id is None or p.artifact is None:
                            raise RuntimeFailure("GRAPH_MESSAGE_EVIDENCE_INCOMPLETE")
                        check_path(material, p.peer_binding, now)
                        pair = (p.binding.node_id, p.peer_binding.node_id)
                        adjacent = {(e.parent_id, e.child_id) for e in material.graph.edges}
                        if pair not in adjacent and pair[::-1] not in adjacent:
                            raise RuntimeFailure("GRAPH_NONADJACENT_ROUTE")
                        dispatch = dispatches.get(p.source_dispatch_id or "")
                        if (
                            dispatch is None
                            or dispatch.event_id != p.source_event_id
                            or (
                                dispatch.run_id != p.source_run_id
                                or dispatch.trace_id != p.source_trace_id
                            )
                        ):
                            raise RuntimeFailure("GRAPH_MESSAGE_SOURCE_MISSING")
                        assert isinstance(dispatch.payload, ToolDispatchedPayload)
                        request = requests[dispatch.payload.request_id]
                        if (
                            request.graph_binding != p.binding
                            or request.request_id != p.source_request_id
                        ):
                            raise RuntimeFailure("GRAPH_MESSAGE_SENDER_MISMATCH")
                        if request.capability != "agent.message.send" or (
                            request.data_destination != f"agent:{p.peer_binding.node_id}"
                        ):
                            raise RuntimeFailure("GRAPH_MESSAGE_ROUTE_MISMATCH")
                        if content_digest(request.data_artifact_refs) != p.source_artifact_digest:
                            raise RuntimeFailure("GRAPH_MESSAGE_LINEAGE_MISMATCH")
                        required_labels = {DataLabel.USER_PROVIDED, DataLabel.UNTRUSTED_CONTENT} | {
                            label for ref in request.data_artifact_refs for label in ref.labels
                        }
                        if (
                            not required_labels <= p.artifact.labels
                            or p.artifact.content_hash != p.content_hash
                        ):
                            raise RuntimeFailure("GRAPH_MESSAGE_LABEL_OR_CONTENT_MISMATCH")
                        if p.operation == "MESSAGE_SENT":
                            if p.message_id in sent or runs.get(event.run_id) != pair[0]:
                                raise RuntimeFailure("GRAPH_MESSAGE_DUPLICATE_OR_SENDER")
                            sent[p.message_id] = p
                        else:
                            if p.message_id in imported or runs.get(event.run_id) != pair[1]:
                                raise RuntimeFailure("GRAPH_MESSAGE_DUPLICATE_OR_RECIPIENT")
                            expected = p.model_copy(update={"operation": "MESSAGE_SENT"})
                            if sent.get(p.message_id) != expected:
                                raise RuntimeFailure("GRAPH_MESSAGE_SEND_COMMITMENT_MISSING")
                            engine = provenance[pair[1]]
                            engine.register(p.artifact)
                            engine.expose(p.artifact)
                            imported.add(p.message_id)
                            deliveries += 1
                elif isinstance(p, ToolRequestedPayload):
                    r = supplied.get(p.request.request_id, p.request)
                    if p.redacted_fields and r == p.request:
                        # Compiled task scope is independently supplied protected material.
                        if p.redacted_fields == {"task_scope"} and r.graph_binding is not None:
                            r = r.model_copy(
                                update={
                                    "task_scope": material.participant(
                                        r.graph_binding.node_id
                                    ).plan.task_scope
                                }
                            )
                        else:
                            raise RuntimeFailure("GRAPH_MATERIAL_REDACTION")
                    if p.policy_input_digest is None or content_digest(r) != p.policy_input_digest:
                        raise RuntimeFailure("GRAPH_POLICY_INPUT_DIGEST_MISMATCH")
                    if r.request_id in requests or r.graph_binding is None:
                        raise RuntimeFailure("GRAPH_REQUEST_DUPLICATE_OR_UNBOUND")
                    request_node = runs.get(event.run_id)
                    if (
                        request_node != r.graph_binding.node_id
                        or not set(r.graph_binding.path) <= active
                    ):
                        raise RuntimeFailure("GRAPH_ANCESTOR_INACTIVE")
                    if provenance[r.graph_binding.node_id].snapshot() != r.data_artifact_refs:
                        raise RuntimeFailure("GRAPH_PROVENANCE_MISMATCH")
                    requests[r.request_id] = r
                    request_payloads[r.request_id] = p
                    if p.trust_snapshot_digest:
                        blockers.add("TRUST_NOT_REVERIFIED")
                elif isinstance(p, PolicyEvaluatedPayload):
                    r = requests[p.decision.request_id]
                    if r.request_id in decisions:
                        raise RuntimeFailure("GRAPH_DUPLICATE_DECISION")
                    d = decide_path(material, r, now)
                    decisions[r.request_id] = d
                    if (d.outcome, d.reason_codes, d.matched_rule_ids) != (
                        p.decision.outcome,
                        p.decision.reason_codes,
                        p.decision.matched_rule_ids,
                    ):
                        raise RuntimeFailure("GRAPH_SOURCE_DECISION_MISMATCH")
                    checked += 1
                    if d.outcome in {PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL}:
                        tool = tools.get(r.tool_id or "")
                        if tool is None or tool.capabilities != frozenset({r.capability}):
                            raise RuntimeFailure("GRAPH_TOOL_METADATA_MISSING")
                        assert r.graph_binding is not None
                        try:
                            tokens[r.request_id] = budgets.reserve(
                                tool, r.graph_binding, request_payloads[r.request_id].action_digest
                            )
                        except RuntimeFailure as exc:
                            if exc.code != "BUDGET_EXCEEDED":
                                raise
                elif isinstance(p, ApprovalRequestedPayload):
                    r = requests[p.approval.policy_request_id]
                    a = actions.get(p.approval.action_digest)
                    if (
                        a is None
                        or a.graph_binding != r.graph_binding
                        or (
                            a.capability != r.capability
                            or a.resource != r.resource
                            or a.data_artifact_refs != r.data_artifact_refs
                            or a.data_destination != r.data_destination
                            or a.principal != r.principal
                        )
                    ):
                        raise RuntimeFailure("GRAPH_EXACT_APPROVAL_MATERIAL_MISSING")
                    approvals.create(p.approval)
                elif isinstance(p, ApprovalDecidedPayload):
                    approvals.record(p.decision)
                elif isinstance(p, ToolDispatchedPayload):
                    r = requests[p.request_id]
                    d = decisions[p.request_id]
                    if (
                        p.enforcement_mode != EnforcementMode.ENFORCE
                        or d.outcome
                        not in {
                            PolicyOutcome.ALLOW,
                            PolicyOutcome.REQUIRE_APPROVAL,
                        }
                        or p.action_digest != request_payloads[p.request_id].action_digest
                    ):
                        raise RuntimeFailure("GRAPH_UNAUTHORIZED_DISPATCH")
                    if p.dispatch_id in dispatches or p.request_id not in tokens:
                        raise RuntimeFailure("GRAPH_UNRESERVED_DISPATCH")
                    assert r.graph_binding is not None
                    check_path(material, r.graph_binding, now, r.capability, r.resource)
                    if not set(r.graph_binding.path) <= active:
                        raise RuntimeFailure("GRAPH_ANCESTOR_INACTIVE")
                    if d.outcome == PolicyOutcome.REQUIRE_APPROVAL:
                        if p.approval_id is None:
                            raise RuntimeFailure("GRAPH_APPROVAL_REQUIRED")
                        approvals.redeem(p.approval_id, p.action_digest)
                    token = tokens.pop(p.request_id)
                    budgets.commit(token)
                    budgets.forget(token)
                    dispatches[p.dispatch_id] = event
                elif isinstance(p, ToolReturnedPayload):
                    if p.dispatch_id not in dispatches:
                        raise RuntimeFailure("GRAPH_RETURN_WITHOUT_DISPATCH")
                    node = runs[event.run_id]
                    for artifact in p.artifacts:
                        provenance[node].register(artifact)
                elif isinstance(p, DataExposedPayload):
                    provenance[runs[event.run_id]].expose(p.artifact)
                elif isinstance(p, SecuritySignalPayload):
                    if (p.redacted_summary or "").startswith(("DISPATCH_", "TRUST_")):
                        blockers.add("SOURCE_UNCERTAINTY_REQUIRES_REVIEW")
                elif isinstance(p, RunFinishedPayload):
                    terminated.add(event.run_id)
            except (ValueError, KeyError, StopIteration, RuntimeFailure) as exc:
                blockers.add(
                    exc.code if isinstance(exc, RuntimeFailure) else "GRAPH_INVALID_SOURCE_FACTS"
                )
        if set(sent) - imported:
            blockers.add("UNCONFIRMED_MESSAGE_DELIVERY")
        if set(starts) != terminated:
            blockers.add("INCOMPLETE_SOURCE_STREAM")
        if set(requests) != set(decisions):
            blockers.add("MISSING_POLICY_DECISION")
        if tokens:
            blockers.add("UNRESOLVED_RESERVATION_LIFECYCLE")
    if blockers and candidate_graph is not None:
        comparison = "INCOMPLETE"
    return GraphReplayResult(
        schema_version="0.1",
        source_evidence_digest=source.source_evidence_digest,
        fidelity="INCOMPLETE" if blockers else "SECURITY_SEMANTIC",
        blockers=frozenset(blockers),
        candidate_graph_comparison=comparison,
        checked_requests=checked,
        checked_deliveries=deliveries,
    )
