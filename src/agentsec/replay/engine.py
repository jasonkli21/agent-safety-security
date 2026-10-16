"""Replay structured security transitions using native policy and runtime-owned ledgers.

There is deliberately no dispatcher, adapter, callback for tool execution, or MCP import.
Responses are content-free scripted facts. New paths without substitutes remain incomplete.
"""

from collections.abc import Callable
from datetime import datetime
from functools import partial

from agentsec.compiler import compile_contract
from agentsec.compiler.models import CompiledSecurityPlan
from agentsec.contracts.models import AgentSecurityContract, Budgets
from agentsec.domain.events import (
    ApprovalDecidedPayload,
    ApprovalRequestedPayload,
    DataExposedPayload,
    EffectVerifiedPayload,
    EventPayload,
    PolicyEvaluatedPayload,
    RunFinishedPayload,
    RunStartedPayload,
    RunTerminatedPayload,
    SecurityEvent,
    SecuritySignalPayload,
    ToolDispatchedPayload,
    ToolRequestedPayload,
    ToolReturnedPayload,
)
from agentsec.domain.findings import Finding
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.replay import (
    Fidelity,
    ReplayAssessment,
    ReplayBundle,
    ReplayError,
    ReplayProgram,
    ReplayResult,
    SourceBinding,
)
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import (
    ApprovalOutcome,
    EventType,
    PolicyOutcome,
    SecurityCategory,
    Severity,
)
from agentsec.eval.models import AssertionResult
from agentsec.identity.authority import authority_failure
from agentsec.policy.native import NativePolicyEngine
from agentsec.provenance.engine import ProvenanceEngine
from agentsec.replay.bundle import recovered_request, validate_bundle, validate_program
from agentsec.replay.expectations import evaluate_program
from agentsec.replay.projection import semantic_diff
from agentsec.runtime.approvals import ApprovalLedger
from agentsec.runtime.budgets import BudgetLedger
from agentsec.runtime.models import RuntimeFailure


def run_program(
    program: ReplayProgram,
    source_plan: CompiledSecurityPlan,
    current: CompiledSecurityPlan,
    *,
    source_digest: str,
    assessment: ReplayAssessment,
    id_factory: Callable[[str], str] | None = None,
) -> ReplayResult:
    complete = validate_program(program)
    start = program.events[0].payload
    assert isinstance(start, RunStartedPayload)
    if (start.contract_id, start.effective_policy_hash) != (
        source_plan.contract_id,
        source_plan.effective_policy_hash,
    ) or (start.plan_identity is not None and start.plan_identity != source_plan.identity):
        raise ReplayError("SOURCE_PLAN_MISMATCH")
    counters: dict[str, int] = {}

    def new_id(prefix: str) -> str:
        if id_factory is not None:
            return id_factory(prefix)
        counters[prefix] = counters.get(prefix, 0) + 1
        return f"replay-{prefix}-{counters[prefix]}"

    now = program.events[0].occurred_at

    def clock() -> datetime:
        return now

    events: list[SecurityEvent] = []
    source_event: SecurityEvent | None = None

    def emit(payload: EventPayload) -> None:
        events.append(
            SecurityEvent(
                schema_version="0.1",
                event_id=new_id("event"),
                event_type=payload.kind,
                occurred_at=clock(),
                run_id="replay-run",
                trace_id="replay-trace",
                sequence=len(events),
                payload=payload,
                actor=source_event.actor if source_event else None,
                labels=source_event.labels if source_event else frozenset(),
                subject=source_event.subject if source_event else None,
            )
        )

    limitations = set(assessment.limitations)
    blockers = set(assessment.blockers)
    if any(
        isinstance(e.payload, ToolRequestedPayload)
        and (e.payload.redacted_fields - ({"authority"} if program.authority else set()))
        for e in program.events
    ):
        blockers.add("MATERIAL_REDACTION")
    if current.compiler_version == "phase6-v1" and any(
        isinstance(e.payload, ToolRequestedPayload)
        and recovered_request(e.payload, program).authority is None
        for e in program.events
    ):
        blockers.add("MISSING_AUTHORITY_CONTEXT")
    if current.gaps:
        blockers.add("UNSUPPORTED_POLICY_SEMANTICS")
    if current.budgets.max_runtime_seconds is not None:
        # Wall timestamps cannot prove a historical monotonic runtime duration.
        blockers.add("MISSING_MONOTONIC_DURATION")
    requests: dict[str, PolicyRequest] = {}
    actions: dict[str, str] = {}
    decisions: dict[str, PolicyDecision] = {}
    tokens: dict[str, str] = {}
    budget_blocked: set[str] = set()
    dispatched: set[str] = set()
    substitutions: list[str] = []
    approval_requests: dict[str, str] = {}
    approved_requests: dict[str, str] = {}
    returned: dict[str, ToolReturnedPayload] = {}
    source_dispatch_requests = {
        e.payload.request_id for e in program.events if isinstance(e.payload, ToolDispatchedPayload)
    }
    tools = {t.tool_id: t for t in program.tools}
    if any(
        isinstance(e.payload, ToolRequestedPayload) and e.payload.request.tool_id not in tools
        for e in program.events
    ):
        limitations.add("MISSING_TOOL_METADATA")
    policy = NativePolicyEngine(clock, lambda: new_id("decision"))
    budgets = BudgetLedger(
        Budgets(**current.budgets.model_dump()), lambda: 0.0, lambda: new_id("reservation")
    )
    approvals = ApprovalLedger(clock)
    provenance = ProvenanceEngine(clock, lambda: new_id("artifact"))

    def dispatch(request_id: str, dispatch_id: str, approval_id: str | None = None) -> bool:
        d = decisions[request_id]
        if d.outcome not in {PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL}:
            return False
        r = requests[request_id]
        if current.compiler_version == "phase6-v1" and authority_failure(
            r.authority,
            current.principal,
            current.acts_on_behalf_of,
            current.task_scope,
            clock(),
            capability=r.capability,
            resource=r.resource,
        ):
            return False
        if request_id in budget_blocked:
            return False
        original_context = next(
            e.payload.request.data_artifact_refs
            for e in program.events
            if isinstance(e.payload, ToolRequestedPayload)
            and e.payload.request.request_id == request_id
        )
        if requests[request_id].data_artifact_refs != original_context:
            blockers.add("ACTION_CONTEXT_BINDING_UNAVAILABLE")
            return False
        if d.outcome == PolicyOutcome.REQUIRE_APPROVAL:
            if approval_id is None or approved_requests.get(request_id) != approval_id:
                return False
            try:
                approvals.redeem(approval_id, actions[request_id])
            except RuntimeFailure:
                blockers.add("APPROVAL_BINDING_UNAVAILABLE")
                return False
        if request_id in tokens:
            budgets.commit(tokens.pop(request_id))
        else:
            tool = tools.get(requests[request_id].tool_id or "")
            if tool is None:
                limitations.add("MISSING_TOOL_METADATA")
            else:
                try:
                    token, _ = budgets.reserve(tool)
                    budgets.commit(token)
                except RuntimeFailure:
                    return False
        emit(
            ToolDispatchedPayload(
                kind=EventType.TOOL_DISPATCHED,
                dispatch_id=dispatch_id,
                request_id=request_id,
                tool_id=requests[request_id].tool_id or "unknown-tool",
                action_digest=actions[request_id],
                decision_id=d.decision_id,
                approval_id=approval_id,
            )
        )
        dispatched.add(dispatch_id)
        substitutions.append(dispatch_id)
        return True

    if not blockers:
        for event in program.events:
            source_event = event
            now = event.occurred_at
            p = event.payload
            if isinstance(p, RunStartedPayload):
                emit(
                    p.model_copy(
                        update={
                            "contract_id": current.contract_id,
                            "effective_policy_hash": current.effective_policy_hash,
                            "plan_identity": current.identity
                            if p.plan_identity is not None
                            else None,
                        }
                    )
                )
            elif isinstance(p, ToolRequestedPayload):
                r = recovered_request(p, program).model_copy(
                    update={"data_artifact_refs": provenance.snapshot()}
                )
                requests[r.request_id], actions[r.request_id] = r, p.action_digest
                emit(
                    p.model_copy(
                        update={
                            "request": r,
                            "policy_input_digest": content_digest(r),
                            "redacted_fields": p.redacted_fields - {"authority"},
                            "authority_digest": None,
                        }
                    )
                )
            elif isinstance(p, PolicyEvaluatedPayload):
                r = requests[p.decision.request_id]
                d = policy.decide(r, current)
                decisions[r.request_id] = d
                emit(PolicyEvaluatedPayload(kind=EventType.POLICY_EVALUATED, decision=d))
                if d.outcome in {PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL}:
                    tool = tools.get(r.tool_id or "")
                    if tool is not None:
                        try:
                            tokens[r.request_id], _ = budgets.reserve(tool)
                        except RuntimeFailure:
                            budget_blocked.add(r.request_id)
                            emit(
                                SecuritySignalPayload(
                                    kind=EventType.SECURITY_SIGNAL,
                                    category=SecurityCategory.RESOURCE_EXHAUSTION,
                                    severity=Severity.HIGH,
                                )
                            )
                    if (
                        d.outcome == PolicyOutcome.ALLOW
                        and r.request_id not in (source_dispatch_requests)
                        and r.request_id not in budget_blocked
                    ):
                        if dispatch(r.request_id, new_id("dispatch")):
                            limitations.add("MISSING_SUBSTITUTE_RESULT")
                    if d.outcome == PolicyOutcome.REQUIRE_APPROVAL and p.decision.outcome != (
                        PolicyOutcome.REQUIRE_APPROVAL
                    ):
                        blockers.add("MISSING_APPROVAL_SCRIPT")
            elif isinstance(p, ApprovalRequestedPayload):
                rid = p.approval.policy_request_id
                if decisions[rid].outcome != PolicyOutcome.REQUIRE_APPROVAL:
                    continue
                # Historical action hashes include full arguments and policy identity. No grant
                # may cross a changed policy or changed causal frontier without a full action.
                original = next(
                    recovered_request(e.payload, program)
                    for e in program.events
                    if isinstance(e.payload, ToolRequestedPayload)
                    and e.payload.request.request_id == rid
                )
                if assessment.source_binding != SourceBinding.EXACT:
                    blockers.add("APPROVAL_SOURCE_PLAN_UNBOUND")
                    continue
                if current.identity != source_plan.identity or requests[rid] != original:
                    blockers.add("APPROVAL_BINDING_UNAVAILABLE")
                    continue
                approvals.create(p.approval)
                approval_requests[p.approval.approval_id] = rid
                emit(p)
            elif isinstance(p, ApprovalDecidedPayload):
                approval_rid = approval_requests.get(p.decision.approval_id)
                if approval_rid is None:
                    continue
                rid = approval_rid
                try:
                    approvals.record(p.decision)
                except RuntimeFailure:
                    blockers.add("APPROVAL_BINDING_UNAVAILABLE")
                    continue
                emit(p)
                if p.decision.outcome == ApprovalOutcome.APPROVE:
                    approved_requests[rid] = p.decision.approval_id
                elif rid in tokens:
                    budgets.release(tokens.pop(rid))
            elif isinstance(p, ToolDispatchedPayload):
                dispatch(p.request_id, p.dispatch_id, p.approval_id)
            elif isinstance(p, ToolReturnedPayload):
                if p.dispatch_id not in dispatched:
                    continue
                snapshot = requests[p.request_id].data_artifact_refs
                original_snapshot = next(
                    e.payload.request.data_artifact_refs
                    for e in program.events
                    if isinstance(e.payload, ToolRequestedPayload)
                    and e.payload.request.request_id == p.request_id
                )
                if snapshot != original_snapshot:
                    # Source evidence cannot separate inherited from configured source labels.
                    blockers.add("CHANGED_PROVENANCE_SUBSTITUTE")
                    continue
                for artifact in p.artifacts:
                    provenance.register(artifact)
                returned[p.dispatch_id] = p
                emit(p)
            elif isinstance(p, DataExposedPayload):
                if p.dispatch_id in returned:
                    provenance.expose(p.artifact, partial(emit, p))
            elif isinstance(p, EffectVerifiedPayload):
                limitations.add("SOURCE_EFFECT_NOT_REEXECUTED")
            elif isinstance(p, SecuritySignalPayload):
                # Signals are source observations, not a detector execution under current policy.
                limitations.add("SOURCE_SIGNALS_NOT_REEVALUATED")
                if p.category != SecurityCategory.RESOURCE_EXHAUSTION:
                    emit(p.model_copy(update={"redacted_summary": None}))
            elif isinstance(p, RunTerminatedPayload):
                # Termination is an input fact; do not invent a candidate runtime termination.
                limitations.add("SOURCE_TERMINATION_NOT_REEXECUTED")
                emit(p)
            elif isinstance(p, RunFinishedPayload):
                # Output text is unavailable; artifact references are source metadata only.
                emit(p)
        undecided = set(requests) - set(decisions)
        if undecided:
            blockers.add("MISSING_POLICY_DECISION")
        if {
            rid
            for rid, d in decisions.items()
            if d.outcome == PolicyOutcome.REQUIRE_APPROVAL and rid not in budget_blocked
        } - set(approval_requests.values()):
            blockers.add("MISSING_APPROVAL_SCRIPT")
        if set(approval_requests.values()) - {
            approval_requests[e.payload.decision.approval_id]
            for e in events
            if isinstance(e.payload, ApprovalDecidedPayload)
        }:
            blockers.add("PENDING_APPROVAL")
    if not complete:
        limitations.add("INCOMPLETE_SOURCE_STREAM")
    runtime_incomplete = blockers or limitations & {
        "MISSING_TOOL_METADATA",
        "MISSING_SUBSTITUTE_RESULT",
        "INCOMPLETE_SOURCE_STREAM",
        "SOURCE_EFFECT_NOT_REEXECUTED",
        "SOURCE_SIGNALS_NOT_REEVALUATED",
        "SOURCE_TERMINATION_NOT_REEXECUTED",
    }
    result_assessment = ReplayAssessment(
        fidelity=Fidelity.BLOCKED if blockers else assessment.fidelity,
        source_binding=assessment.source_binding,
        blockers=frozenset(blockers),
        limitations=frozenset(limitations),
    )
    assertions: tuple[AssertionResult, ...] = ()
    findings: tuple[Finding, ...] = ()
    source_assertions: tuple[AssertionResult, ...] = ()
    source_findings: tuple[Finding, ...] = ()
    if not blockers & {"MISSING_RAW_ASSERTION_SURFACES", "MISSING_ASSERTION_TOOL"}:
        source_assertions, source_findings = evaluate_program(
            program,
            complete=complete,
            source_findings=True,
        )
        assertions, findings = evaluate_program(
            program.model_copy(update={"events": tuple(events)}),
            complete=complete and not bool(blockers) and "MISSING_TOOL_METADATA" not in limitations,
        )
    comparison_limits = frozenset(blockers | (set(limitations) if runtime_incomplete else set()))
    return ReplayResult(
        schema_version="0.1",
        replay_id="replay-" + content_digest((source_digest, current.identity))[7:31],
        source_bundle_digest=source_digest,
        source_identity=source_plan.identity if start.plan_identity is not None else None,
        current_identity=current.identity,
        assessment=result_assessment,
        events=tuple(events),
        assertions=assertions,
        findings=findings,
        diff=semantic_diff(
            program.events,
            tuple(events),
            limitations=comparison_limits,
            source_assertions=source_assertions,
            replay_assertions=assertions,
            source_findings=source_findings,
            replay_findings=findings,
        ),
        substituted_dispatch_ids=tuple(substitutions),
    )


def replay(bundle: ReplayBundle, current: AgentSecurityContract | None = None) -> ReplayResult:
    bundle = validate_bundle(bundle)
    plan = compile_contract(current) if current is not None else bundle.source_plan
    return run_program(
        bundle.program,
        bundle.source_plan,
        plan,
        source_digest=bundle.bundle_digest,
        assessment=bundle.assessment,
    )
