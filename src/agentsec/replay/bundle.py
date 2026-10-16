"""Validate historical input before packaging; digests prove integrity, not authenticity."""

from pathlib import Path

from agentsec.compiler import compile_contract
from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import MAX_BYTES
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.events import (
    DataExposedPayload,
    PolicyEvaluatedPayload,
    RunFinishedPayload,
    RunStartedPayload,
    SecurityEvent,
    ToolDispatchedPayload,
    ToolRequestedPayload,
    ToolReturnedPayload,
    validate_event_sequence,
)
from agentsec.domain.findings import Finding
from agentsec.domain.replay import (
    Fidelity,
    ReplayAssessment,
    ReplayBundle,
    ReplayError,
    ReplayProgram,
    SourceBinding,
)
from agentsec.domain.scenarios import Assertion, OutputNotContainsCanary, ToolCalled, ToolNotCalled
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.domain.taxonomy import EnforcementMode, EventType
from agentsec.domain.tools import ToolDescriptor
from agentsec.eval.observations import EvaluationObservation, ObservationCoverage
from agentsec.eval.trajectory import EvaluationError, validate_evaluation_trajectory
from agentsec.evidence.jsonl import read_jsonl


def validate_program(program: ReplayProgram) -> bool:
    events = program.events
    if not events or not isinstance(events[0].payload, RunStartedPayload):
        raise ReplayError("MISSING_RUN_START")
    if len({(e.run_id, e.trace_id) for e in events}) != 1:
        raise ReplayError("MIXED_SOURCE")
    complete = events[-1].event_type in {EventType.RUN_FINISHED, EventType.RUN_TERMINATED}
    # Validate provenance even for a runtime prefix without its final terminal event.
    checked = events
    if not complete:
        checked += (
            SecurityEvent(
                schema_version="0.1",
                event_id="replay-validation-terminal",
                event_type=EventType.RUN_FINISHED,
                occurred_at=events[-1].occurred_at,
                run_id=events[0].run_id,
                trace_id=events[0].trace_id,
                sequence=events[-1].sequence + 1,
                payload=RunFinishedPayload(kind=EventType.RUN_FINISHED),
            ),
        )
    start = events[0].payload
    if start.scenario_id is None:
        checked = (
            checked[0].model_copy(
                update={"payload": start.model_copy(update={"scenario_id": "runtime-replay"})}
            ),
            *checked[1:],
        )
    modes = {
        event.payload.enforcement_mode
        for event in events
        if isinstance(event.payload, ToolDispatchedPayload)
    }
    if modes - {EnforcementMode.ENFORCE}:
        _validate_non_enforcing_source(events)
        for event in events:
            p = event.payload
            if (
                isinstance(p, ToolRequestedPayload)
                and not p.redacted_fields
                and p.policy_input_digest is not None
                and content_digest(p.request) != p.policy_input_digest
            ):
                raise ReplayError("POLICY_INPUT_DIGEST_MISMATCH")
        return complete
    try:
        validate_evaluation_trajectory(
            EvaluationObservation(
                scenario_id=start.scenario_id or "runtime-replay",
                run_id=events[0].run_id,
                trace_id=events[0].trace_id,
                events=checked,
                findings=program.findings,
                coverage=ObservationCoverage(event_stream_complete=True),
            )
        )
    except EvaluationError as exc:
        raise ReplayError(exc.code) from exc
    for event in events:
        p = event.payload
        if (
            isinstance(p, ToolRequestedPayload)
            and not p.redacted_fields
            and (
                p.policy_input_digest is not None
                and content_digest(p.request) != p.policy_input_digest
            )
        ):
            raise ReplayError("POLICY_INPUT_DIGEST_MISMATCH")
    ids = [t.tool_id for t in program.tools]
    if len(ids) != len(set(ids)):
        raise ReplayError("DUPLICATE_TOOL_ID")
    return complete


def _validate_non_enforcing_source(events: tuple[SecurityEvent, ...]) -> None:
    """Validate truthful SHADOW/DISABLED lifecycle links without ENFORCE scoring rules."""
    try:
        validate_event_sequence(list(events))
    except ArtifactValidationError as exc:
        raise ReplayError("INVALID_TRAJECTORY") from exc
    requests: dict[str, ToolRequestedPayload] = {}
    decisions: dict[str, PolicyEvaluatedPayload] = {}
    decision_requests: set[str] = set()
    dispatches: dict[str, ToolDispatchedPayload] = {}
    returns: dict[str, ToolReturnedPayload] = {}
    exposures: set[str] = set()
    modes: set[EnforcementMode] = set()
    start = events[0].payload
    assert isinstance(start, RunStartedPayload)
    for event in events:
        p = event.payload
        if isinstance(p, ToolRequestedPayload):
            if p.request.request_id in requests:
                raise ReplayError("INVALID_TRAJECTORY")
            requests[p.request.request_id] = p
        elif isinstance(p, PolicyEvaluatedPayload):
            if (
                p.decision.request_id not in requests
                or p.decision.request_id in decision_requests
                or p.decision.decision_id in decisions
                or p.decision.contract_id != start.contract_id
                or p.decision.effective_policy_hash != start.effective_policy_hash
            ):
                raise ReplayError("INVALID_TRAJECTORY")
            decisions[p.decision.decision_id] = p
            decision_requests.add(p.decision.request_id)
        elif isinstance(p, ToolDispatchedPayload):
            modes.add(p.enforcement_mode)
            request = requests.get(p.request_id)
            if request is None or p.dispatch_id in dispatches:
                raise ReplayError("INVALID_TRAJECTORY")
            if p.tool_id != request.request.tool_id or p.action_digest != request.action_digest:
                raise ReplayError("INVALID_TRAJECTORY")
            if p.enforcement_mode == EnforcementMode.DISABLED:
                if p.decision_id is not None or p.approval_id is not None:
                    raise ReplayError("INVALID_TRAJECTORY")
            else:
                decision_event = decisions.get(p.decision_id or "")
                if decision_event is None or decision_event.decision.request_id != p.request_id:
                    raise ReplayError("INVALID_TRAJECTORY")
            dispatches[p.dispatch_id] = p
        elif isinstance(p, ToolReturnedPayload):
            dispatch = dispatches.get(p.dispatch_id)
            if (
                dispatch is None
                or p.request_id != dispatch.request_id
                or p.tool_id != dispatch.tool_id
                or p.dispatch_id in returns
            ):
                raise ReplayError("INVALID_TRAJECTORY")
            returns[p.dispatch_id] = p
        elif isinstance(p, DataExposedPayload):
            returned = returns.get(p.dispatch_id)
            if (
                returned is None
                or p.dispatch_id in exposures
                or p.request_id != returned.request_id
                or p.tool_id != returned.tool_id
                or p.artifact not in returned.artifacts
            ):
                raise ReplayError("INVALID_TRAJECTORY")
            exposures.add(p.dispatch_id)
    if len(modes) > 1:
        raise ReplayError("INVALID_TRAJECTORY")


def assess(program: ReplayProgram, contract: AgentSecurityContract) -> ReplayAssessment:
    complete = validate_program(program)
    plan = compile_contract(contract)
    start = program.events[0].payload
    assert isinstance(start, RunStartedPayload)
    if (start.contract_id, start.effective_policy_hash) != (
        plan.contract_id,
        plan.effective_policy_hash,
    ):
        raise ReplayError("SOURCE_CONTRACT_MISMATCH")
    binding = SourceBinding.LEGACY_INFERRED
    if start.plan_identity is not None:
        if start.plan_identity != plan.identity:
            raise ReplayError("SOURCE_PLAN_MISMATCH")
        binding = SourceBinding.EXACT
    blockers: set[str] = set()
    limitations = {"NO_MODEL_REPLAY", "NO_RAW_RESPONSES", "OPERATOR_TOOL_METADATA"}
    if not complete:
        limitations.add("INCOMPLETE_SOURCE_STREAM")
    if binding == SourceBinding.LEGACY_INFERRED:
        limitations.add("LEGACY_SOURCE_PLAN")
    if any(
        isinstance(e.payload, ToolDispatchedPayload)
        and e.payload.enforcement_mode != EnforcementMode.ENFORCE
        for e in program.events
    ):
        blockers.add("UNSUPPORTED_SOURCE_ENFORCEMENT_MODE")
    tools = {t.tool_id: t for t in program.tools}
    for event in program.events:
        p = event.payload
        if isinstance(p, ToolRequestedPayload):
            if p.redacted_fields:
                blockers.add("MATERIAL_REDACTION")
            elif p.policy_input_digest is not None and content_digest(p.request) != (
                p.policy_input_digest
            ):
                raise ReplayError("POLICY_INPUT_DIGEST_MISMATCH")
            tool = tools.get(p.request.tool_id or "")
            if tool is None:
                limitations.add("MISSING_TOOL_METADATA")
            elif p.request.capability not in tool.capabilities:
                raise ReplayError("TOOL_CAPABILITY_MISMATCH")
    requested = {
        e.payload.request.request_id
        for e in program.events
        if isinstance(e.payload, ToolRequestedPayload)
    }
    decided = {
        e.payload.decision.request_id
        for e in program.events
        if isinstance(e.payload, PolicyEvaluatedPayload)
    }
    if requested != decided:
        blockers.add("MISSING_POLICY_DECISION")
    if any(
        isinstance(a, (ToolNotCalled, ToolCalled)) and a.tool_id not in tools
        for a in program.expectations
    ):
        blockers.add("MISSING_ASSERTION_TOOL")
    if plan.gaps:
        blockers.add("UNSUPPORTED_POLICY_SEMANTICS")
    if plan.budgets.max_runtime_seconds is not None:
        blockers.add("MISSING_MONOTONIC_DURATION")
    if any(isinstance(a, OutputNotContainsCanary) for a in program.expectations):
        blockers.add("MISSING_RAW_ASSERTION_SURFACES")
    return ReplayAssessment(
        fidelity=Fidelity.BLOCKED
        if blockers
        else (
            Fidelity.POLICY if "MISSING_TOOL_METADATA" in limitations else Fidelity.SECURITY_RUNTIME
        ),
        source_binding=binding,
        blockers=frozenset(blockers),
        limitations=frozenset(limitations),
    )


def create_bundle(
    events: tuple[SecurityEvent, ...],
    contract: AgentSecurityContract,
    *,
    tools: tuple[ToolDescriptor, ...] = (),
    expectations: tuple[Assertion, ...] = (),
    findings: tuple[Finding, ...] = (),
) -> ReplayBundle:
    # Re-parse to reject unchecked model_copy mutations and detach caller-owned maps.
    program = ReplayProgram.model_validate_json(
        ReplayProgram(
            schema_version="0.1",
            events=events,
            tools=tools,
            expectations=expectations,
            findings=tuple(
                f.model_copy(
                    update={
                        "title": f.category.value,
                        "description": "Canonical source finding",
                        "expected": None,
                        "observed": None,
                        "remediation_hint": None,
                    }
                )
                for f in findings
            ),
        ).model_dump_json(round_trip=True)
    )
    contract = AgentSecurityContract.model_validate_json(contract.model_dump_json(round_trip=True))
    assessment = assess(program, contract)
    values = dict(
        schema_version="0.1",
        source_run_id=events[0].run_id,
        source_trace_id=events[0].trace_id,
        source_evidence_digest=content_digest(program.events),
        source_contract=contract,
        source_plan=compile_contract(contract),
        program=program,
        assessment=assessment,
    )
    bundle = ReplayBundle(
        schema_version="0.1",
        source_run_id=events[0].run_id,
        source_trace_id=events[0].trace_id,
        source_evidence_digest=content_digest(program.events),
        source_contract=contract,
        source_plan=compile_contract(contract),
        program=program,
        assessment=assessment,
        bundle_digest=content_digest(values),
    )
    if len(canonical_json(bundle).encode("utf-8")) > MAX_BYTES:
        raise ReplayError("BUNDLE_TOO_LARGE")
    return bundle


def validate_bundle(bundle: ReplayBundle) -> ReplayBundle:
    bundle = ReplayBundle.model_validate_json(bundle.model_dump_json(round_trip=True))
    expected = create_bundle(
        bundle.program.events,
        bundle.source_contract,
        tools=bundle.program.tools,
        expectations=bundle.program.expectations,
        findings=bundle.program.findings,
    )
    if bundle != expected:
        raise ReplayError("BUNDLE_BINDING_MISMATCH")
    return bundle


def bundle_from_jsonl(path: Path, contract: AgentSecurityContract) -> ReplayBundle:
    return create_bundle(read_jsonl(path, max_bytes=MAX_BYTES), contract)
