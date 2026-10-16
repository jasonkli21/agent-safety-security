"""Strict scripted evidence generation, never contract policy evaluation."""

from collections import defaultdict, deque
from typing import Annotated, Literal, Self

from pydantic import Field, JsonValue, field_validator, model_validator
from pydantic_core import PydanticCustomError

from agentsec.contracts.canonical import effective_policy_hash
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.approvals import (
    ApprovalDecision,
    ApprovalRequest,
    NormalizedAction,
    action_digest,
)
from agentsec.domain.base import CapabilityId, Identifier, NonEmpty, SecurityModel, VersionedModel
from agentsec.domain.events import (
    ApprovalDecidedPayload,
    ApprovalRequestedPayload,
    DataExposedPayload,
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
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.provenance import DataArtifactRef, canonical_artifacts
from agentsec.domain.scenarios import Scenario
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.domain.taxonomy import (
    ApprovalOutcome,
    EventType,
    PolicyOutcome,
    ReasonCode,
    SecurityCategory,
    Severity,
    SideEffectClass,
)
from agentsec.domain.tools import ToolDescriptor
from agentsec.eval.observations import (
    EvaluationObservation,
    ObservationCoverage,
    TextObservation,
    TextSurface,
)
from agentsec.eval.ports import EvaluationContext
from agentsec.eval.trajectory import EvaluationError


class ToolCallStep(SecurityModel):
    type: Literal["TOOL_CALL"]
    tool_id: Identifier
    capability: CapabilityId
    arguments: dict[str, JsonValue]
    resource: NonEmpty | None = None
    data_artifact_refs: tuple[DataArtifactRef, ...] = ()
    data_destination: Identifier | None = None
    response_artifacts: tuple[DataArtifactRef, ...] = ()
    _canonical_artifacts = field_validator("data_artifact_refs")(canonical_artifacts)
    policy_outcome: PolicyOutcome | None = None
    reason_codes: frozenset[ReasonCode] = frozenset()
    matched_rule_ids: frozenset[Identifier] = frozenset()
    approval_outcome: ApprovalOutcome | None = None
    external_sink_text: str | None = None

    @model_validator(mode="after")
    def approval_consistent(self) -> Self:
        if (
            self.approval_outcome is not None
            and self.policy_outcome != PolicyOutcome.REQUIRE_APPROVAL
        ):
            raise PydanticCustomError("INVALID_SCHEMA", "Approval requires REQUIRE_APPROVAL")
        return self


class SignalStep(SecurityModel):
    type: Literal["SECURITY_SIGNAL"]
    category: SecurityCategory
    severity: Severity
    artifact_refs: frozenset[Identifier] = frozenset()
    redacted_summary: NonEmpty | None = None


class OutputStep(SecurityModel):
    type: Literal["OUTPUT"]
    text: str


class TerminateStep(SecurityModel):
    type: Literal["TERMINATE"]
    reason: ReasonCode


class FinishStep(SecurityModel):
    type: Literal["FINISH"]


FixtureStep = Annotated[
    ToolCallStep | SignalStep | OutputStep | TerminateStep | FinishStep, Field(discriminator="type")
]


class TargetFixture(VersionedModel):
    fixture_id: Identifier
    scenario_id: Identifier
    steps: Annotated[tuple[FixtureStep, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def terminal_path(self) -> Self:
        if sum(
            isinstance(s, (TerminateStep, FinishStep)) for s in self.steps
        ) != 1 or not isinstance(self.steps[-1], (TerminateStep, FinishStep)):
            raise PydanticCustomError("INVALID_SCHEMA", "Exactly one terminal step must be last")
        return self


class MockResponseResolver:
    def __init__(self, scenario: Scenario) -> None:
        self._queues: dict[str, deque[JsonValue]] = defaultdict(deque)
        for mock in scenario.setup.mock_responses:
            self._queues[mock.tool_id].append(mock.response)

    def consume(self, tool_id: str) -> JsonValue:
        if not self._queues[tool_id]:
            raise EvaluationError("MOCK_RESPONSE_EXHAUSTED")
        return self._queues[tool_id].popleft()


class FixtureTarget:
    def __init__(self, fixture: TargetFixture) -> None:
        self.fixture = fixture

    def run(
        self, *, contract: AgentSecurityContract, scenario: Scenario, context: EvaluationContext
    ) -> EvaluationObservation:
        if self.fixture.scenario_id != scenario.scenario_id:
            raise EvaluationError("SCENARIO_MISMATCH")
        tools = {t.tool_id: t for t in scenario.setup.tools}
        self._validate_compatibility(tools)
        responses = MockResponseResolver(scenario)
        texts: list[TextObservation] = []
        policy_hash = effective_policy_hash(contract)

        def emit(payload: EventPayload) -> SecurityEvent:
            event = SecurityEvent(
                schema_version="0.1",
                event_id=context.new_id("event"),
                event_type=payload.kind,
                occurred_at=context.clock(),
                run_id=context.run_id,
                trace_id=context.trace_id,
                sequence=len(context.recorder.events),
                payload=payload,
            )
            context.recorder.append(event)
            return event

        emit(
            RunStartedPayload(
                kind=EventType.RUN_STARTED,
                contract_id=contract.metadata.contract_id,
                effective_policy_hash=policy_hash,
                scenario_id=scenario.scenario_id,
            )
        )
        for step in self.fixture.steps:
            if isinstance(step, ToolCallStep):
                tool = tools[step.tool_id]
                action = NormalizedAction(
                    schema_version="0.1",
                    principal=contract.identity.principal,
                    agent_id=contract.agent.agent_id,
                    environment=contract.agent.environment,
                    task_id=scenario.task.task_id,
                    tool_id=tool.tool_id,
                    capability=step.capability,
                    resource=step.resource,
                    data_artifact_refs=step.data_artifact_refs,
                    data_destination=step.data_destination,
                    arguments=step.arguments,
                    tool_schema_hash=tool.schema_hash,
                    tool_description_hash=tool.description_hash,
                    effective_policy_hash=policy_hash,
                )
                digest = action_digest(action)
                request = PolicyRequest(
                    schema_version="0.1",
                    request_id=context.new_id("request"),
                    principal=contract.identity.principal,
                    agent=contract.agent,
                    task_scope=scenario.task.task_scope,
                    capability=step.capability,
                    tool_id=tool.tool_id,
                    resource=step.resource,
                    data_artifact_refs=step.data_artifact_refs,
                    data_destination=step.data_destination,
                    environment=contract.agent.environment,
                    requested_at=context.clock(),
                )
                redacted_resource = redact_canaries(step.resource, scenario)
                evidence_request = request.model_copy(update={"resource": redacted_resource})
                resource_was_redacted = redacted_resource != step.resource
                event = emit(
                    ToolRequestedPayload(
                        kind=EventType.TOOL_REQUESTED,
                        request=evidence_request,
                        action_digest=digest,
                        policy_input_digest=content_digest(request),
                        redacted_fields=(
                            frozenset({"resource"}) if resource_was_redacted else frozenset()
                        ),
                        resource_digest=(
                            content_digest(step.resource) if resource_was_redacted else None
                        ),
                    )
                )
                # Capture decoded strings so JSON escaping cannot hide canaries.
                texts.append(
                    TextObservation(
                        surface=TextSurface.TOOL_ARGUMENT,
                        source_id=event.event_id,
                        text="",
                        argument_values=argument_values(step.arguments),
                    )
                )
                decision = self.policy_decision(request, step, contract, context)
                if decision is None:
                    continue
                reasons = decision.reason_codes
                emit(PolicyEvaluatedPayload(kind=EventType.POLICY_EVALUATED, decision=decision))
                approval_id = None
                if decision.outcome == PolicyOutcome.REQUIRE_APPROVAL:
                    approval_id = context.new_id("approval")
                    approval = ApprovalRequest(
                        schema_version="0.1",
                        approval_id=approval_id,
                        policy_request_id=request.request_id,
                        action_digest=digest,
                        summary="Scripted exact-action approval",
                        reason_codes=reasons,
                        created_at=context.clock(),
                    )
                    emit(
                        ApprovalRequestedPayload(
                            kind=EventType.APPROVAL_REQUESTED, approval=approval
                        )
                    )
                    approval_outcome = self.approval_outcome(step)
                    if approval_outcome is not None:
                        emit(
                            ApprovalDecidedPayload(
                                kind=EventType.APPROVAL_DECIDED,
                                decision=ApprovalDecision(
                                    schema_version="0.1",
                                    approval_id=approval_id,
                                    approver=contract.identity.principal,
                                    outcome=approval_outcome,
                                    decided_at=context.clock(),
                                ),
                            )
                        )
                dispatch = decision.outcome == PolicyOutcome.ALLOW or (
                    decision.outcome == PolicyOutcome.REQUIRE_APPROVAL
                    and self.approval_outcome(step) == ApprovalOutcome.APPROVE
                )
                if dispatch:
                    dispatch_id = context.new_id("dispatch")
                    emit(
                        ToolDispatchedPayload(
                            kind=EventType.TOOL_DISPATCHED,
                            dispatch_id=dispatch_id,
                            request_id=request.request_id,
                            tool_id=tool.tool_id,
                            action_digest=digest,
                            decision_id=decision.decision_id,
                            approval_id=approval_id,
                        )
                    )
                    response = responses.consume(tool.tool_id)
                    emit(
                        ToolReturnedPayload(
                            kind=EventType.TOOL_RETURNED,
                            dispatch_id=dispatch_id,
                            request_id=request.request_id,
                            tool_id=tool.tool_id,
                            success=True,
                            artifacts=step.response_artifacts,
                            response_hash=content_digest(response),
                        )
                    )
                    for artifact in step.response_artifacts:
                        emit(
                            DataExposedPayload(
                                kind=EventType.DATA_EXPOSED,
                                dispatch_id=dispatch_id,
                                request_id=request.request_id,
                                tool_id=tool.tool_id,
                                artifact=artifact,
                            )
                        )
                    if step.external_sink_text is not None:
                        texts.append(
                            TextObservation(
                                surface=TextSurface.EXTERNAL_SINK,
                                source_id=context.new_id("sink"),
                                text=step.external_sink_text,
                            )
                        )
            elif isinstance(step, SignalStep):
                # Untrusted summaries are intentionally not persisted.
                emit(
                    SecuritySignalPayload(
                        kind=EventType.SECURITY_SIGNAL,
                        category=step.category,
                        severity=step.severity,
                        artifact_refs=step.artifact_refs,
                    )
                )
            elif isinstance(step, OutputStep):
                texts.append(
                    TextObservation(
                        surface=TextSurface.FINAL_OUTPUT,
                        source_id=context.new_id("output"),
                        text=step.text,
                    )
                )
            elif isinstance(step, TerminateStep):
                emit(RunTerminatedPayload(kind=EventType.RUN_TERMINATED, reason=step.reason))
            else:
                emit(RunFinishedPayload(kind=EventType.RUN_FINISHED))
        return EvaluationObservation(
            scenario_id=scenario.scenario_id,
            run_id=context.run_id,
            trace_id=context.trace_id,
            events=context.recorder.events,
            text_observations=tuple(texts),
            coverage=ObservationCoverage(
                event_stream_complete=True,
                final_output_complete=True,
                external_sink_capture_complete=True,
                finding_set_complete=True,
                tool_arguments_complete=True,
            ),
        )

    def approval_outcome(self, step: ToolCallStep) -> ApprovalOutcome | None:
        return step.approval_outcome

    def policy_decision(
        self,
        request: PolicyRequest,
        step: ToolCallStep,
        contract: AgentSecurityContract,
        context: EvaluationContext,
    ) -> PolicyDecision | None:
        if step.policy_outcome is None:
            return None
        reasons = step.reason_codes or frozenset(
            {
                {
                    PolicyOutcome.ALLOW: ReasonCode.EXPLICIT_ALLOW,
                    PolicyOutcome.DENY: ReasonCode.EXPLICIT_DENY,
                    PolicyOutcome.REQUIRE_APPROVAL: ReasonCode.APPROVAL_REQUIRED,
                    PolicyOutcome.ERROR: ReasonCode.POLICY_ENGINE_ERROR,
                }[step.policy_outcome]
            }
        )
        return PolicyDecision(
            schema_version="0.1",
            decision_id=context.new_id("decision"),
            request_id=request.request_id,
            outcome=step.policy_outcome,
            matched_rule_ids=step.matched_rule_ids,
            reason_codes=reasons,
            contract_id=contract.metadata.contract_id,
            effective_policy_hash=effective_policy_hash(contract),
            decided_at=context.clock(),
        )

    def _validate_compatibility(self, tools: dict[str, ToolDescriptor]) -> None:
        """Reject contradictory fixture claims before emitting any canonical event."""
        for step in self.fixture.steps:
            if not isinstance(step, ToolCallStep):
                continue
            tool = tools.get(step.tool_id)
            if tool is None or step.capability not in tool.capabilities:
                raise EvaluationError("UNKNOWN_TOOL_CAPABILITY")
            if step.external_sink_text is None:
                continue
            dispatches = step.policy_outcome == PolicyOutcome.ALLOW or (
                step.policy_outcome == PolicyOutcome.REQUIRE_APPROVAL
                and step.approval_outcome == ApprovalOutcome.APPROVE
            )
            if tool.side_effect_class != SideEffectClass.EXTERNAL_WRITE or not dispatches:
                raise EvaluationError("INVALID_SINK_CAPTURE")


def argument_values(value: JsonValue) -> tuple[str, ...]:
    """Keep decoded leaves separate to avoid cross-field matches and JSON escape loss."""
    if isinstance(value, dict):
        return tuple(part for k, v in value.items() for part in (k, *argument_values(v)))
    if isinstance(value, list):
        return tuple(part for v in value for part in argument_values(v))
    return (value if isinstance(value, str) else canonical_json(value),)


def redact_canaries(value: str | None, scenario: Scenario) -> str | None:
    if value is None:
        return None
    for canary in scenario.setup.canaries:
        value = value.replace(canary.value, "[REDACTED]")
    return value
