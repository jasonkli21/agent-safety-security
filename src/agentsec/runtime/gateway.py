"""Protocol-independent authorization boundary; exactly one dispatch per invocation."""

import asyncio
from collections.abc import Awaitable, Callable
from copy import deepcopy
from datetime import timedelta
from typing import Literal
from uuid import uuid4

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as SchemaValidationError
from pydantic import JsonValue

from agentsec.contracts.canonical import effective_policy_hash
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.approvals import ApprovalRequest, NormalizedAction, action_digest
from agentsec.domain.events import (
    ApprovalDecidedPayload,
    ApprovalRequestedPayload,
    PolicyEvaluatedPayload,
    RunFinishedPayload,
    RunStartedPayload,
    SecuritySignalPayload,
    ToolDispatchedPayload,
    ToolRequestedPayload,
    ToolReturnedPayload,
)
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.domain.taxonomy import (
    EnforcementMode,
    EventType,
    PolicyOutcome,
    ReasonCode,
    SecurityCategory,
    Severity,
)
from agentsec.domain.tools import ToolDescriptor
from agentsec.policy.coverage import coverage_gaps
from agentsec.policy.native import NativePolicyEngine
from agentsec.policy.ports import PolicyEngine
from agentsec.runtime.approvals import ApprovalBroker, ApprovalLedger
from agentsec.runtime.budgets import BudgetLedger
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.models import RuntimeFailure, ToolResponse


def _approval_presentation(
    tool_name: str,
    capability: str,
    resource: str | None,
    arguments: dict[str, JsonValue],
    display_paths: tuple[tuple[str, ...], ...],
    digest: str,
) -> str:
    def display(value: JsonValue) -> str:
        if not isinstance(value, (str, bool, int, float)) and value is not None:
            return "[hidden non-scalar value]"
        rendered = canonical_json(value)
        return rendered if len(rendered) <= 160 else rendered[:157] + "..."

    lines = [
        "Review this action. The digest binds the complete action.",
        f"Tool: {tool_name}",
        f"Capability: {capability}",
        f"Resource: {display(resource) if resource is not None else '[not configured]'}",
        f"Action digest: {digest}",
    ]
    for path in display_paths:
        current: JsonValue = arguments
        for key in path:
            if not isinstance(current, dict) or key not in current:
                current = None
                break
            current = current[key]
        label = ".".join(path)
        rendered_label = canonical_json(label)
        if len(rendered_label) > 96:
            rendered_label = rendered_label[:93] + "..."
        lines.append(f"Configured field {rendered_label}: {display(current)}")
    lines.append("Other arguments are hidden; check the configured fields before approving.")
    return "\n".join(lines)


class RuntimeGateway:
    def __init__(
        self,
        contract: AgentSecurityContract,
        mode: EnforcementMode,
        events: RuntimeEvents,
        broker: ApprovalBroker,
        *,
        policy: PolicyEngine | None = None,
        budgets: BudgetLedger | None = None,
    ) -> None:
        self._contract = contract.model_copy(deep=True)
        self.mode, self.events, self.broker = mode, events, broker
        self.policy = policy or NativePolicyEngine(events.clock)
        self.budgets = budgets or BudgetLedger(contract.budgets)
        self.approvals = ApprovalLedger(events.clock)
        self._closed = False
        if mode == EnforcementMode.ENFORCE and coverage_gaps(contract):
            raise RuntimeFailure("UNSUPPORTED_POLICY_SEMANTICS")
        self.events.emit(
            RunStartedPayload(
                kind=EventType.RUN_STARTED,
                contract_id=contract.metadata.contract_id,
                effective_policy_hash=effective_policy_hash(contract),
            )
        )
        if coverage_gaps(contract):
            self.signal(SecurityCategory.POLICY_BYPASS, "UNSUPPORTED_POLICY_SEMANTICS")

    @property
    def contract(self) -> AgentSecurityContract:
        """Return a defensive copy for adapter-level, read-only coverage checks."""
        return self._contract.model_copy(deep=True)

    def signal(self, category: SecurityCategory, code: str) -> None:
        self.events.emit(
            SecuritySignalPayload(
                kind=EventType.SECURITY_SIGNAL,
                category=category,
                severity=Severity.HIGH,
                redacted_summary=code,
            )
        )

    def finish(self) -> None:
        self._closed = True
        self.events.emit(RunFinishedPayload(kind=EventType.RUN_FINISHED))

    async def call(
        self,
        tool: ToolDescriptor,
        arguments: dict[str, JsonValue],
        resource: str | None,
        dispatch: Callable[[dict[str, JsonValue]], Awaitable[ToolResponse]],
        *,
        bound: bool,
        approval_display_paths: tuple[tuple[str, ...], ...] = (),
        resource_coverage_gap: bool = False,
    ) -> ToolResponse:
        if self._closed:
            raise RuntimeFailure("SESSION_CLOSED")
        enforce = self.mode == EnforcementMode.ENFORCE
        if not bound and enforce:
            self.signal(SecurityCategory.UNAUTHORIZED_TOOL_USE, "UNBOUND_TOOL")
            raise RuntimeFailure("UNBOUND_TOOL")
        contract = self._contract
        arguments = deepcopy(arguments)
        tool = tool.model_copy(deep=True)
        capability = next(iter(tool.capabilities))
        if len(tool.capabilities) != 1:
            raise RuntimeFailure("AMBIGUOUS_CAPABILITY")
        action = NormalizedAction(
            schema_version="0.1",
            principal=contract.identity.principal,
            agent_id=contract.agent.agent_id,
            environment=contract.environment.mode,
            task_id=contract.task_scope.task_id if contract.task_scope else None,
            capability=capability,
            tool_id=tool.tool_id,
            resource=resource,
            arguments=arguments,
            tool_schema_hash=tool.schema_hash,
            tool_description_hash=tool.description_hash,
            effective_policy_hash=effective_policy_hash(contract),
        )
        digest = action_digest(action)
        # Resource values and argument keys can carry secrets: evidence gets only a digest.
        request = PolicyRequest(
            schema_version="0.1",
            request_id=str(uuid4()),
            principal=contract.identity.principal,
            agent=contract.agent,
            task_scope=contract.task_scope,
            capability=capability,
            tool_id=tool.tool_id,
            resource=resource,
            arguments_summary=None,
            environment=contract.environment.mode,
            requested_at=self.events.clock(),
        )
        redacted_fields: frozenset[Literal["resource", "task_scope"]] = frozenset()
        if request.resource is not None:
            redacted_fields |= frozenset({"resource"})
        if request.task_scope is not None:
            redacted_fields |= frozenset({"task_scope"})
        evidence_request = request.model_copy(update={"resource": None, "task_scope": None})
        self.events.emit(
            ToolRequestedPayload(
                kind=EventType.TOOL_REQUESTED,
                request=evidence_request,
                action_digest=digest,
                policy_input_digest=content_digest(request),
                redacted_fields=redacted_fields,
                resource_digest=(content_digest(request.resource) if request.resource else None),
                task_scope_digest=(
                    content_digest(request.task_scope) if request.task_scope is not None else None
                ),
            )
        )
        decision: PolicyDecision | None = None
        if self.mode != EnforcementMode.DISABLED:
            try:
                if resource_coverage_gap:
                    decision = PolicyDecision(
                        schema_version="0.1",
                        decision_id=str(uuid4()),
                        request_id=request.request_id,
                        outcome=PolicyOutcome.ERROR,
                        reason_codes=frozenset({ReasonCode.INVALID_REQUEST}),
                        human_reason="UNSUPPORTED_RESOURCE_COVERAGE",
                        contract_id=contract.metadata.contract_id,
                        effective_policy_hash=effective_policy_hash(contract),
                        decided_at=self.events.clock(),
                    )
                else:
                    decision = PolicyDecision.model_validate_json(
                        self.policy.decide(request, contract).model_dump_json()
                    )
                if (
                    decision.request_id != request.request_id
                    or decision.contract_id != contract.metadata.contract_id
                    or decision.effective_policy_hash != effective_policy_hash(contract)
                ):
                    raise RuntimeFailure("INVALID_POLICY_DECISION")
                if not bound:
                    decision = decision.model_copy(
                        update={
                            "outcome": PolicyOutcome.DENY,
                            "matched_rule_ids": frozenset(),
                            "reason_codes": frozenset({ReasonCode.UNKNOWN_CAPABILITY}),
                        }
                    )
            except Exception:
                decision = PolicyDecision(
                    schema_version="0.1",
                    decision_id=str(uuid4()),
                    request_id=request.request_id,
                    outcome=PolicyOutcome.ERROR,
                    reason_codes=frozenset({ReasonCode.POLICY_ENGINE_ERROR}),
                    contract_id=contract.metadata.contract_id,
                    effective_policy_hash=effective_policy_hash(contract),
                    decided_at=self.events.clock(),
                )
            self.events.emit(
                PolicyEvaluatedPayload(kind=EventType.POLICY_EVALUATED, decision=decision)
            )
            if enforce and decision.outcome in {PolicyOutcome.DENY, PolicyOutcome.ERROR}:
                raise RuntimeFailure(
                    "POLICY_DENIED"
                    if decision.outcome == PolicyOutcome.DENY
                    else "POLICY_ENGINE_ERROR"
                )
        token: str | None = None
        approval: ApprovalRequest | None = None
        try:
            token, exceeded = self.budgets.reserve(tool, enforce=enforce)
            if exceeded and self.mode != EnforcementMode.DISABLED:
                self.signal(SecurityCategory.RESOURCE_EXHAUSTION, "BUDGET_EXCEEDED")
            if (
                decision is not None
                and decision.outcome == PolicyOutcome.REQUIRE_APPROVAL
                and enforce
            ):
                now = self.events.clock()
                approval = ApprovalRequest(
                    schema_version="0.1",
                    approval_id=str(uuid4()),
                    policy_request_id=request.request_id,
                    action_digest=digest,
                    summary=(
                        f"Approval required for {tool.name} ({capability}); exact action {digest}"
                    ),
                    reason_codes=decision.reason_codes,
                    created_at=now,
                    expires_at=now + timedelta(seconds=contract.approvals.default_timeout_seconds),
                )
                self.approvals.create(approval)
                self.events.emit(
                    ApprovalRequestedPayload(kind=EventType.APPROVAL_REQUESTED, approval=approval)
                )
                try:
                    result = await asyncio.wait_for(
                        self.broker.decide(
                            approval,
                            _approval_presentation(
                                tool.name,
                                capability,
                                resource,
                                arguments,
                                approval_display_paths,
                                digest,
                            ),
                        ),
                        timeout=contract.approvals.default_timeout_seconds,
                    )
                    self.approvals.record(result)
                except RuntimeFailure:
                    raise
                except TimeoutError as exc:
                    raise RuntimeFailure("APPROVAL_TIMEOUT") from exc
                except Exception as exc:
                    raise RuntimeFailure("APPROVAL_FAILED") from exc
                self.events.emit(
                    ApprovalDecidedPayload(kind=EventType.APPROVAL_DECIDED, decision=result)
                )
                self.approvals.redeem(approval.approval_id, digest)
            dispatch_id = str(uuid4())
            # No await between final expiry/budget checks, evidence and dispatcher entry.
            self.budgets.commit(token, enforce=enforce)
            try:
                self.events.emit(
                    ToolDispatchedPayload(
                        kind=EventType.TOOL_DISPATCHED,
                        dispatch_id=dispatch_id,
                        request_id=request.request_id,
                        tool_id=tool.tool_id,
                        action_digest=digest,
                        decision_id=decision.decision_id if decision else None,
                        enforcement_mode=self.mode,
                        approval_id=approval.approval_id if approval else None,
                    )
                )
            except RuntimeFailure:
                self.budgets.refund(tool)
                raise
            token = None
            try:
                response = await dispatch(deepcopy(arguments))
            except asyncio.CancelledError:
                self.signal(
                    SecurityCategory.TRACE_INTEGRITY_FAILURE, "DISPATCH_CANCELLED_EFFECT_UNKNOWN"
                )
                raise
            except Exception as exc:
                self.events.emit(
                    ToolReturnedPayload(
                        kind=EventType.TOOL_RETURNED,
                        dispatch_id=dispatch_id,
                        request_id=request.request_id,
                        tool_id=tool.tool_id,
                        success=False,
                    )
                )
                raise RuntimeFailure("UPSTREAM_FAILURE") from exc
            self.events.emit(
                ToolReturnedPayload(
                    kind=EventType.TOOL_RETURNED,
                    dispatch_id=dispatch_id,
                    request_id=request.request_id,
                    tool_id=tool.tool_id,
                    success=response.success,
                    response_hash=content_digest(response.body),
                )
            )
            if tool.output_schema is not None and response.success:
                try:
                    Draft202012Validator(tool.output_schema).validate(response.structured)
                except SchemaValidationError as exc:
                    self.signal(SecurityCategory.ARGUMENT_VIOLATION, "OUTPUT_SCHEMA_VIOLATION")
                    if enforce:
                        raise RuntimeFailure("OUTPUT_SCHEMA_VIOLATION") from exc
            return response
        except RuntimeFailure as exc:
            if exc.code == "BUDGET_EXCEEDED":
                self.signal(SecurityCategory.RESOURCE_EXHAUSTION, exc.code)
            elif exc.code.startswith("APPROVAL") or exc.code == "INVALID_APPROVAL":
                self.signal(SecurityCategory.APPROVAL_BYPASS, exc.code)
            raise
        finally:
            if token is not None:
                self.budgets.release(token)
            if approval is not None:
                self.approvals.invalidate(approval.approval_id)
