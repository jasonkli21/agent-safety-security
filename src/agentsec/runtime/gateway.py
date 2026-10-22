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

from agentsec.compiler import CompiledSecurityPlan, compile_contract
from agentsec.contracts.models import AgentSecurityContract, Budgets
from agentsec.domain.approvals import ApprovalRequest, NormalizedAction, action_digest
from agentsec.domain.authority import AuthorityContext, AuthoritySummary
from agentsec.domain.events import (
    ApprovalDecidedPayload,
    ApprovalRequestedPayload,
    DataExposedPayload,
    PolicyEvaluatedPayload,
    RunFinishedPayload,
    RunStartedPayload,
    SecuritySignalPayload,
    ToolDispatchedPayload,
    ToolRequestedPayload,
    ToolReturnedPayload,
)
from agentsec.domain.execution import ExecutionBinding
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.provenance import DataOrigin
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.domain.taxonomy import (
    DataLabel,
    EnforcementMode,
    EventType,
    PolicyOutcome,
    ReasonCode,
    SecurityCategory,
    Severity,
    TrustClass,
)
from agentsec.domain.tools import ToolDescriptor
from agentsec.identity.authority import authority_failure
from agentsec.identity.static import StaticIdentityProvider
from agentsec.multi_agent.ports import GraphGuard
from agentsec.policy.coverage import coverage_gaps
from agentsec.policy.native import NativePolicyEngine
from agentsec.policy.ports import PolicyEngine
from agentsec.provenance import ProvenanceEngine
from agentsec.runtime.approvals import ApprovalBroker, ApprovalLedger
from agentsec.runtime.budgets import BudgetLedger
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.models import RuntimeFailure, ToolResponse
from agentsec.supply_chain.guard import TrustGuard
from agentsec.supply_chain.inspection import observe
from agentsec.supply_chain.models import Candidate, TrustAssessment


def _approval_presentation(
    tool_name: str,
    capability: str,
    resource: str | None,
    arguments: dict[str, JsonValue],
    display_paths: tuple[tuple[str, ...], ...],
    display_resource: bool,
    digest: str,
) -> str:
    def display(value: JsonValue) -> str:
        if not isinstance(value, (str, bool, int, float)) and value is not None:
            return "[hidden non-scalar value]"
        rendered = canonical_json(value)
        return rendered if len(rendered) <= 160 else rendered[:157] + "..."

    if resource is None:
        resource_display = "[not configured]"
    elif display_resource:
        resource_display = display(resource)
    else:
        resource_display = f"[redacted {content_digest(resource)}]"
    lines = [
        "Review this action. The digest binds the complete action.",
        f"Tool: {tool_name}",
        f"Capability: {capability}",
        f"Resource: {resource_display}",
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
        plan: CompiledSecurityPlan | None = None,
        authority: AuthorityContext | None = None,
        identity_error: str | None = None,
        trust_guard: TrustGuard | None = None,
        graph_guard: GraphGuard | None = None,
    ) -> None:
        self.__trust_guard = trust_guard
        self.__graph_guard = graph_guard
        if graph_guard is not None and (mode != EnforcementMode.ENFORCE or not events.required):
            raise RuntimeFailure("GRAPH_MODE_UNSUPPORTED")
        self._contract = contract.model_copy(deep=True)
        compiled = (
            compile_contract(self._contract, multi_agent=True)
            if graph_guard is not None
            else compile_contract(self._contract)
        )
        if plan is not None and plan != compiled:
            raise RuntimeFailure("STALE_COMPILED_PLAN")
        self._plan = compiled
        self._authority = (
            AuthorityContext.model_validate_json(authority.model_dump_json())
            if authority
            else (
                None
                if identity_error
                else AuthorityContext(
                    schema_version="0.1",
                    credential=StaticIdentityProvider(compiled.principal).verify(
                        None, events.clock()
                    ),
                )
            )
        )
        self._identity_error = identity_error
        failure = (
            None
            if graph_guard is not None
            else authority_failure(
                self._authority,
                compiled.principal,
                compiled.acts_on_behalf_of,
                compiled.task_scope,
                events.clock(),
            )
        )
        if mode == EnforcementMode.ENFORCE and (failure or identity_error):
            raise RuntimeFailure(
                identity_error or (failure.value if failure else "AUTHORITY_INVALID")
            )
        if graph_guard is not None:
            graph_guard.snapshot(events.clock())
        grant = self._authority.delegation if self._authority else None
        summary = AuthoritySummary(
            schema_version="0.1",
            actor=self._authority.credential.principal if self._authority else None,
            assurance=self._authority.credential.assurance if self._authority else None,
            acts_on_behalf_of=compiled.acts_on_behalf_of,
            delegation_id=grant.delegation_id if grant else None,
            delegation_digest=content_digest(grant) if grant else None,
            authority_digest=self._authority.authority_digest if self._authority else None,
            expires_at=self._authority.expires_at if self._authority else None,
            error=identity_error or (failure.value if failure else None),
            enforcement_enabled=mode == EnforcementMode.ENFORCE,
        )
        self.mode, self.events, self.broker = mode, events, broker
        self.policy = policy or NativePolicyEngine(events.clock)
        self.budgets = budgets or BudgetLedger(Budgets(**self._plan.budgets.model_dump()))
        self.approvals = ApprovalLedger(events.clock)
        self._closed = False
        self.provenance = ProvenanceEngine(events.clock)
        if mode == EnforcementMode.ENFORCE and coverage_gaps(self._plan):
            raise RuntimeFailure("UNSUPPORTED_POLICY_SEMANTICS")
        self.events.emit(
            RunStartedPayload(
                kind=EventType.RUN_STARTED,
                contract_id=self._plan.contract_id,
                effective_policy_hash=self._plan.effective_policy_hash,
                plan_identity=self._plan.identity,
                authority_summary=summary,
            )
        )
        if coverage_gaps(self._plan):
            self.signal(SecurityCategory.POLICY_BYPASS, "UNSUPPORTED_POLICY_SEMANTICS")

    @property
    def plan(self) -> CompiledSecurityPlan:
        return self._plan

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

    @property
    def trust_enabled(self) -> bool:
        return self.__trust_guard is not None and self.mode != EnforcementMode.DISABLED

    @property
    def trust_required_candidates(self) -> tuple[str, ...]:
        return self.__trust_guard.required_candidates if self.__trust_guard is not None else ()

    def trust_candidate(
        self,
        tool: ToolDescriptor,
        route: ExecutionBinding | None,
        destination: str | None = None,
        labels: frozenset[DataLabel] | None = None,
    ) -> Candidate:
        return observe(
            tool,
            route,
            classification={"destination": destination, "labels": labels},
            labels_complete=labels is not None
            and (
                tool.side_effect_class.value not in {"EXTERNAL_WRITE", "NETWORK"}
                or destination is not None
            ),
        )

    def admit_trust(self, candidate: Candidate) -> tuple[str | None, TrustAssessment | None]:
        if self.__trust_guard is None or self.mode == EnforcementMode.DISABLED:
            return None, None
        try:
            snapshot, assessment = self.__trust_guard.check(candidate, self.events.clock())
        except RuntimeFailure as exc:
            self.signal(SecurityCategory.SUPPLY_CHAIN_CHANGE, exc.code)
            if self.mode == EnforcementMode.ENFORCE:
                raise
            return None, None
        if not assessment.admitted:
            for code in assessment.reason_codes:
                self.signal(SecurityCategory.SUPPLY_CHAIN_CHANGE, code)
            if self.mode == EnforcementMode.ENFORCE:
                raise RuntimeFailure("TRUST_ADMISSION_REJECTED")
        return snapshot, assessment

    def finish(self) -> None:
        self._closed = True
        if self.__graph_guard is not None:
            self.__graph_guard.close()
        self.events.emit(RunFinishedPayload(kind=EventType.RUN_FINISHED))

    async def call(
        self,
        tool: ToolDescriptor,
        arguments: dict[str, JsonValue],
        resource: str | None,
        dispatch: Callable[[dict[str, JsonValue]], Awaitable[ToolResponse]],
        *,
        bound: bool,
        execution_binding: ExecutionBinding | None = None,
        approval_display_paths: tuple[tuple[str, ...], ...] = (),
        approval_display_resource: bool = False,
        resource_coverage_gap: bool = False,
        data_coverage_gap: bool = False,
        data_destination: str | None = None,
        output_data_labels: frozenset[DataLabel] | None = None,
    ) -> ToolResponse:
        if self._closed:
            raise RuntimeFailure("SESSION_CLOSED")
        graph_binding = (
            self.__graph_guard.snapshot(self.events.clock()) if self.__graph_guard else None
        )
        if self.__graph_guard is not None and graph_binding is not None:
            self.__graph_guard.classifications(graph_binding, data_destination, output_data_labels)
        context = self.provenance.snapshot()
        enforce = self.mode == EnforcementMode.ENFORCE
        if not bound and enforce:
            self.signal(SecurityCategory.UNAUTHORIZED_TOOL_USE, "UNBOUND_TOOL")
            raise RuntimeFailure("UNBOUND_TOOL")
        plan = self._plan
        arguments = deepcopy(arguments)
        tool = tool.model_copy(deep=True)
        capability = next(iter(tool.capabilities))
        if len(tool.capabilities) != 1:
            raise RuntimeFailure("AMBIGUOUS_CAPABILITY")
        candidate = (
            self.trust_candidate(tool, execution_binding, data_destination, output_data_labels)
            if self.trust_enabled
            else None
        )
        # Check before broker/reservation; no caller can omit trust on a guarded gateway.
        trust_snapshot, trust_assessment = (
            self.admit_trust(candidate) if candidate else (None, None)
        )
        action = NormalizedAction(
            graph_binding=graph_binding,
            schema_version="0.1",
            trust_snapshot_digest=trust_snapshot,
            execution_binding_digest=content_digest(execution_binding)
            if execution_binding
            else None,
            principal=self._authority.credential.principal if self._authority else plan.principal,
            delegation_id=self._authority.delegation.delegation_id
            if self._authority and self._authority.delegation
            else None,
            authority_digest=self._authority.authority_digest if self._authority else None,
            agent_id=plan.agent.agent_id,
            environment=plan.environment,
            task_id=plan.scope.task_id if plan.scope else None,
            capability=capability,
            tool_id=tool.tool_id,
            resource=resource,
            data_artifact_refs=context,
            data_destination=data_destination,
            arguments=arguments,
            tool_schema_hash=tool.schema_hash,
            tool_description_hash=tool.description_hash,
            effective_policy_hash=self._plan.effective_policy_hash,
        )
        digest = action_digest(action)
        # Resource values and argument keys can carry secrets: evidence gets only a digest.
        request = PolicyRequest(
            graph_binding=graph_binding,
            schema_version="0.1",
            request_id=str(uuid4()),
            principal=self._authority.credential.principal if self._authority else plan.principal,
            delegation_id=self._authority.delegation.delegation_id
            if self._authority and self._authority.delegation
            else None,
            authority=self._authority,
            agent=plan.agent.request_agent(),
            task_scope=plan.task_scope,
            capability=capability,
            tool_id=tool.tool_id,
            resource=resource,
            data_artifact_refs=context,
            data_destination=data_destination,
            arguments_summary=None,
            environment=plan.environment,
            requested_at=self.events.clock(),
        )
        redacted_fields: frozenset[Literal["resource", "task_scope", "authority"]] = frozenset()
        if request.resource is not None:
            redacted_fields |= frozenset({"resource"})
        if request.task_scope is not None:
            redacted_fields |= frozenset({"task_scope"})
        redact_authority = bool(
            self._authority
            and self._authority.delegation
            and self._authority.delegation.task_scope.resource_scopes is not None
        )
        if redact_authority:
            redacted_fields |= frozenset({"authority"})
        evidence_request = request.model_copy(
            update={
                "resource": None,
                "task_scope": None,
                "authority": None if redact_authority else self._authority,
            }
        )
        self.events.emit(
            ToolRequestedPayload(
                kind=EventType.TOOL_REQUESTED,
                request=evidence_request,
                action_digest=digest,
                trust_snapshot_digest=trust_snapshot,
                trust_assessment=trust_assessment,
                policy_input_digest=content_digest(request),
                authority_digest=self._authority.authority_digest
                if redact_authority and self._authority
                else None,
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
                if self._identity_error:
                    raise RuntimeFailure(self._identity_error)
                if resource_coverage_gap or data_coverage_gap:
                    decision = PolicyDecision(
                        schema_version="0.1",
                        decision_id=str(uuid4()),
                        request_id=request.request_id,
                        outcome=PolicyOutcome.ERROR,
                        reason_codes=frozenset(
                            {
                                ReasonCode.DATA_FLOW_CONTEXT_MISSING
                                if data_coverage_gap
                                else ReasonCode.INVALID_REQUEST
                            }
                        ),
                        human_reason=(
                            "UNSUPPORTED_DATA_COVERAGE"
                            if data_coverage_gap
                            else "UNSUPPORTED_RESOURCE_COVERAGE"
                        ),
                        contract_id=plan.contract_id,
                        effective_policy_hash=self._plan.effective_policy_hash,
                        decided_at=self.events.clock(),
                    )
                else:
                    decision = PolicyDecision.model_validate_json(
                        (
                            self.__graph_guard.decide(request, self.events.clock())
                            if self.__graph_guard
                            else self.policy.decide(request, self._plan)
                        ).model_dump_json()
                    )
                if (
                    decision.request_id != request.request_id
                    or decision.contract_id != plan.contract_id
                    or decision.effective_policy_hash != self._plan.effective_policy_hash
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
                    contract_id=plan.contract_id,
                    effective_policy_hash=self._plan.effective_policy_hash,
                    decided_at=self.events.clock(),
                )
            self.events.emit(
                PolicyEvaluatedPayload(kind=EventType.POLICY_EVALUATED, decision=decision)
            )
            if decision.outcome in {PolicyOutcome.DENY, PolicyOutcome.ERROR} and (
                ReasonCode.DATA_FLOW_DENIED in decision.reason_codes
                or ReasonCode.DATA_FLOW_CONTEXT_MISSING in decision.reason_codes
            ):
                self.signal(
                    SecurityCategory.POLICY_BYPASS,
                    ReasonCode.DATA_FLOW_DENIED.value
                    if ReasonCode.DATA_FLOW_DENIED in decision.reason_codes
                    else ReasonCode.DATA_FLOW_CONTEXT_MISSING.value,
                )
            if enforce and decision.outcome in {PolicyOutcome.DENY, PolicyOutcome.ERROR}:
                raise RuntimeFailure(
                    "POLICY_DENIED"
                    if decision.outcome == PolicyOutcome.DENY
                    else "POLICY_ENGINE_ERROR"
                )
        token: str | None = None
        approval: ApprovalRequest | None = None
        approval_timeout = (
            self.__graph_guard.approval_timeout(graph_binding)
            if self.__graph_guard and graph_binding
            else self._plan.approvals.default_timeout_seconds
        )
        try:
            token, exceeded = self.budgets.reserve(
                tool, enforce=enforce, action_digest=digest, graph_binding=graph_binding
            )
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
                    expires_at=now + timedelta(seconds=approval_timeout),
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
                                approval_display_resource,
                                digest,
                            ),
                        ),
                        timeout=approval_timeout,
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
            if enforce and self.__graph_guard is not None and graph_binding is not None:
                self.__graph_guard.final(graph_binding, self.events.clock(), capability, resource)
            if enforce and self.__graph_guard is None:
                failure = authority_failure(
                    self._authority,
                    plan.principal,
                    plan.acts_on_behalf_of,
                    plan.task_scope,
                    self.events.clock(),
                    capability=capability,
                    resource=resource,
                )
                if failure:
                    self.signal(SecurityCategory.DELEGATION_ESCALATION, failure.value)
                    raise RuntimeFailure(failure.value)
            if (
                self.__trust_guard is not None
                and trust_snapshot is not None
                and candidate is not None
            ):
                try:
                    final = self.__trust_guard.final(candidate, trust_snapshot, self.events.clock())
                    if enforce and not final.admitted:
                        raise RuntimeFailure("TRUST_ADMISSION_REJECTED")
                except RuntimeFailure as exc:
                    self.signal(SecurityCategory.SUPPLY_CHAIN_CHANGE, exc.code)
                    if enforce:
                        raise
            dispatch_id = str(uuid4())
            # No await between final expiry/budget checks, evidence and dispatcher entry.
            self.budgets.commit(token, enforce=enforce)
            try:
                self.events.emit(
                    ToolDispatchedPayload(
                        kind=EventType.TOOL_DISPATCHED,
                        dispatch_id=dispatch_id,
                        execution_binding=execution_binding,
                        trust_snapshot_digest=trust_snapshot,
                        trust_assessment=trust_assessment,
                        request_id=request.request_id,
                        tool_id=tool.tool_id,
                        action_digest=digest,
                        decision_id=decision.decision_id if decision else None,
                        enforcement_mode=self.mode,
                        approval_id=approval.approval_id if approval else None,
                    )
                )
                # An evidence callback is synchronous but may consume time or revoke state.
                if (
                    enforce
                    and self.__trust_guard is not None
                    and trust_snapshot is not None
                    and candidate is not None
                ):
                    final = self.__trust_guard.final(candidate, trust_snapshot, self.events.clock())
                    if enforce and not final.admitted:
                        raise RuntimeFailure("TRUST_ADMISSION_REJECTED")
                self.budgets.validate_commit(token, enforce=enforce)
                if self.__graph_guard is not None and graph_binding is not None:
                    self.__graph_guard.final(
                        graph_binding, self.events.clock(), capability, resource
                    )
            except BaseException:
                self.budgets.refund(token)
                raise
            self.budgets.forget(token)
            token = None
            try:
                response = await dispatch(deepcopy(arguments))
            except asyncio.CancelledError:
                self.signal(
                    SecurityCategory.TRACE_INTEGRITY_FAILURE, "DISPATCH_CANCELLED_EFFECT_UNKNOWN"
                )
                raise
            except RuntimeFailure as exc:
                if self.__graph_guard is not None:
                    self.signal(
                        SecurityCategory.TRACE_INTEGRITY_FAILURE, "DISPATCH_FAILED_EFFECT_UNKNOWN"
                    )
                if exc.code in {
                    "ISOLATION_CLEANUP_UNCONFIRMED",
                    "PROCESS_CLEANUP_UNCONFIRMED",
                }:
                    self.signal(SecurityCategory.TRACE_INTEGRITY_FAILURE, exc.code)
                    raise
                raise RuntimeFailure("UPSTREAM_FAILURE") from exc
            except Exception as exc:
                if self.__graph_guard is not None:
                    self.signal(
                        SecurityCategory.TRACE_INTEGRITY_FAILURE, "DISPATCH_FAILED_EFFECT_UNKNOWN"
                    )
                raise RuntimeFailure("UPSTREAM_FAILURE") from exc
            artifact = self.provenance.derive(
                DataOrigin(
                    origin_type="tool_output",
                    source_id=tool.tool_id,
                    trust_class=TrustClass.TOOL_OUTPUT,
                ),
                parents=context,
                labels=frozenset({DataLabel.TOOL_OUTPUT, DataLabel.UNTRUSTED_CONTENT})
                | (output_data_labels or frozenset()),
                content_hash=content_digest(response.body),
            )
            self.events.emit(
                ToolReturnedPayload(
                    kind=EventType.TOOL_RETURNED,
                    dispatch_id=dispatch_id,
                    request_id=request.request_id,
                    tool_id=tool.tool_id,
                    artifacts=(artifact,),
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
            self.provenance.expose(
                artifact,
                lambda: self.events.emit(
                    DataExposedPayload(
                        kind=EventType.DATA_EXPOSED,
                        dispatch_id=dispatch_id,
                        request_id=request.request_id,
                        tool_id=tool.tool_id,
                        artifact=artifact,
                    )
                ),
            )
            return response
        except RuntimeFailure as exc:
            if exc.code == "BUDGET_EXCEEDED":
                self.signal(SecurityCategory.RESOURCE_EXHAUSTION, exc.code)
            elif exc.code == "INVALID_APPROVAL":
                self.signal(SecurityCategory.APPROVAL_BYPASS, exc.code)
            raise
        finally:
            if token is not None:
                self.budgets.release(token)
            if approval is not None:
                self.approvals.invalidate(approval.approval_id)
