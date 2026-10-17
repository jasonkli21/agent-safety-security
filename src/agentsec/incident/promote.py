"""Export reviewed expectations and content-free replay material, never a policy fix."""

from agentsec.compiler import compile_contract
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.events import (
    ApprovalRequestedPayload,
    PolicyEvaluatedPayload,
    SecuritySignalPayload,
    ToolRequestedPayload,
)
from agentsec.domain.replay import (
    Fidelity,
    Incident,
    RegressionCase,
    RegressionState,
    ReplayBundle,
    ReplayError,
    ReplayProgram,
)
from agentsec.domain.scenarios import ApprovalRequired, MaxToolCalls, ToolNotCalled
from agentsec.domain.serialization import content_digest
from agentsec.incident.classify import classify
from agentsec.replay.bundle import validate_bundle
from agentsec.replay.engine import replay


def promote(
    bundle: ReplayBundle,
    incident: Incident,
    current: AgentSecurityContract | None = None,
) -> RegressionCase:
    bundle = validate_bundle(bundle)
    operator_basis = tuple(
        b for b in incident.classification_basis if b.rule == "OPERATOR_SUPPLIED"
    )
    if len(operator_basis) > 1 or incident != classify(
        bundle,
        operator_basis[0].category if operator_basis else None,
    ):
        raise ReplayError("INCIDENT_BINDING_MISMATCH")
    reason = "EXPLICIT_SAFE_EXPECTATIONS"
    active = True
    if not bundle.program.expectations or any(
        not isinstance(
            a,
            (
                ToolNotCalled,
                MaxToolCalls,
                ApprovalRequired,
            ),
        )
        for a in bundle.program.expectations
    ):
        reason, active = "PROMOTION_EXPECTATION_REVIEW", False
    if bundle.assessment.fidelity != Fidelity.SECURITY_RUNTIME:
        reason, active = "PROMOTION_INCOMPLETE_INPUT", False
    if bundle.program.authority is not None and any(
        isinstance(e.payload, ToolRequestedPayload) and "authority" in e.payload.redacted_fields
        for e in bundle.program.events
    ):
        reason, active = "PROMOTION_PROTECTED_AUTHORITY_REVIEW", False
    if bundle.source_plan.scope is not None or any(r.resource for r in bundle.source_plan.rules):
        reason, active = "PROMOTION_MATERIAL_RESOURCE_REVIEW", False
    for e in bundle.program.events:
        if isinstance(e.payload, ToolRequestedPayload) and (
            e.payload.request.resource is not None or e.payload.request.task_scope is not None
        ):
            reason, active = "PROMOTION_MATERIAL_RESOURCE_REVIEW", False
    current_plan = compile_contract(current) if current else None
    if current_plan is not None and (
        current_plan.scope is not None or any(r.resource for r in current_plan.rules)
    ):
        reason, active = "PROMOTION_MATERIAL_RESOURCE_REVIEW", False
    if active and (
        "INCOMPLETE_SOURCE_STREAM" in bundle.assessment.limitations
        or replay(bundle, current).assessment.blockers
    ):
        reason, active = "PROMOTION_INCOMPLETE_INPUT", False
    program = None
    if active:
        # Trusted IDs/classifications/hashes remain; arbitrary content never enters exports.
        events = []
        for event in bundle.program.events:
            p = event.payload
            if isinstance(p, ToolRequestedPayload):
                r = p.request.model_copy(
                    update={
                        "arguments_summary": None,
                        "agent": bundle.source_plan.agent.request_agent(),
                    }
                )
                p = p.model_copy(update={"request": r, "policy_input_digest": content_digest(r)})
            elif isinstance(p, PolicyEvaluatedPayload):
                p = p.model_copy(
                    update={"decision": p.decision.model_copy(update={"human_reason": None})}
                )
            elif isinstance(p, ApprovalRequestedPayload):
                p = p.model_copy(
                    update={
                        "approval": p.approval.model_copy(
                            update={"summary": "Source action commitment"}
                        )
                    }
                )
            elif isinstance(p, SecuritySignalPayload):
                p = p.model_copy(update={"redacted_summary": None})
            events.append(event.model_copy(update={"payload": p}))
        tools = tuple(
            t.model_copy(
                update={
                    "name": t.tool_id,
                    "description": "Replay metadata",
                    "input_schema": {},
                    "output_schema": None,
                    "version": None,
                }
            )
            for t in bundle.program.tools
        )
        program = ReplayProgram(
            schema_version="0.1",
            events=tuple(events),
            tools=tools,
            expectations=bundle.program.expectations,
            findings=(),
        )
    return RegressionCase(
        schema_version="0.1",
        regression_id="regression-"
        + content_digest((incident.incident_id, bundle.program.expectations))[7:31],
        source_incident_id=incident.incident_id,
        source_bundle_digest=bundle.bundle_digest,
        source_evidence_digest=bundle.source_evidence_digest,
        state=RegressionState.ACTIVE if active else RegressionState.DRAFT,
        reason=reason,
        plan=bundle.source_plan if active else None,
        current_plan=current_plan if active else None,
        program=program,
    )
