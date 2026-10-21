"""Strict artifacts for content-minimized security replay, never model reproduction."""

from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from agentsec.compiler.models import CompiledSecurityPlan, PlanIdentity
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.authority import AuthorityContext
from agentsec.domain.base import Digest, Identifier, SecurityModel, VersionedModel
from agentsec.domain.events import SecurityEvent
from agentsec.domain.execution import ExecutionBinding
from agentsec.domain.findings import Finding
from agentsec.domain.scenarios import Assertion
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import SecurityCategory, Severity
from agentsec.domain.tools import ToolDescriptor
from agentsec.eval.models import AssertionResult


class ReplayError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SourceBinding(StrEnum):
    EXACT = "EXACT"
    LEGACY_INFERRED = "LEGACY_INFERRED"


class Fidelity(StrEnum):
    POLICY = "POLICY"
    SECURITY_RUNTIME = "SECURITY_RUNTIME"
    BLOCKED = "BLOCKED"


class ReplayAssessment(SecurityModel):
    fidelity: Fidelity
    source_binding: SourceBinding
    blockers: frozenset[Identifier] = frozenset()
    limitations: frozenset[Identifier] = frozenset()


class ReplayProgram(VersionedModel):
    """Ordered requests and metadata-only substitute lifecycles, no executable tools."""

    authority: AuthorityContext | None = None

    @model_serializer(mode="wrap")
    def compatible_wire(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        data: dict[str, object] = handler(self)
        if self.authority is None:
            data.pop("authority", None)
        return data

    events: tuple[SecurityEvent, ...]
    tools: tuple[ToolDescriptor, ...] = ()
    expectations: tuple[Assertion, ...] = ()
    findings: tuple[Finding, ...] = ()

    @field_validator("tools")
    @classmethod
    def canonical_tools(cls, value: tuple[ToolDescriptor, ...]) -> tuple[ToolDescriptor, ...]:
        if len({t.tool_id for t in value}) != len(value):
            raise ReplayError("DUPLICATE_TOOL_ID")
        return tuple(sorted(value, key=lambda t: t.tool_id))

    @field_validator("findings")
    @classmethod
    def canonical_findings(cls, value: tuple[Finding, ...]) -> tuple[Finding, ...]:
        if len({f.finding_id for f in value}) != len(value):
            raise ReplayError("DUPLICATE_FINDING_ID")
        return tuple(sorted(value, key=lambda f: f.finding_id))


class ReplayBundle(VersionedModel):
    source_run_id: Identifier
    source_trace_id: Identifier
    source_evidence_digest: Digest
    source_contract: AgentSecurityContract
    source_plan: CompiledSecurityPlan
    program: ReplayProgram
    assessment: ReplayAssessment
    bundle_digest: Digest

    @model_validator(mode="after")
    def integrity(self) -> Self:
        if content_digest(self.program.events) != self.source_evidence_digest:
            raise ReplayError("SOURCE_EVIDENCE_DIGEST_MISMATCH")
        if content_digest(self.model_dump(exclude={"bundle_digest"}, round_trip=True)) != (
            self.bundle_digest
        ):
            raise ReplayError("BUNDLE_DIGEST_MISMATCH")
        return self


class TraceFact(SecurityModel):
    # JSON is the intentional public projection of already typed event payloads.
    kind: Identifier
    canonical_payload: str


class TraceDifference(SecurityModel):
    index: int
    source: TraceFact | None = None
    replay: TraceFact | None = None


class TraceDiff(VersionedModel):
    """Policy/evidence event-trace diff; route fidelity is reported separately."""

    status: Literal["UNCHANGED", "CHANGED", "INCOMPLETE"]
    differences: tuple[TraceDifference, ...] = ()
    limitations: frozenset[Identifier] = frozenset()


class ExecutionRouteEntry(SecurityModel):
    """Content-free protected route identity for candidate replay comparison."""

    tool_id: Identifier
    execution_binding: ExecutionBinding


class CandidateRouteManifest(VersionedModel):
    """Protected, content-free routes used only for offline route comparison."""

    routes: tuple[ExecutionRouteEntry, ...]

    @model_validator(mode="after")
    def unique_routes(self) -> Self:
        keys = [
            (
                route.tool_id,
                route.execution_binding.adapter_kind,
                route.execution_binding.adapter_id,
                route.execution_binding.adapter_version,
                route.execution_binding.binding_digest,
                route.execution_binding.isolation_digest,
            )
            for route in self.routes
        ]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate candidate route")
        return self


class RouteComparison(SecurityModel):
    """Candidate route fidelity, separate from policy/evidence event projection."""

    status: Literal["UNKNOWN", "UNCHANGED", "CHANGED", "INCOMPLETE"]
    changed_tool_ids: tuple[Identifier, ...] = ()
    missing_source_route_tool_ids: tuple[Identifier, ...] = ()
    missing_candidate_route_tool_ids: tuple[Identifier, ...] = ()


class ReplayResult(VersionedModel):
    replay_id: Identifier
    source_bundle_digest: Digest
    # None means the source did not record a compiled-plan identity. The bundle's
    # freshly compiled source_plan is an interpretation, not historical proof.
    source_identity: PlanIdentity | None
    current_identity: PlanIdentity
    assessment: ReplayAssessment
    authority: AuthorityContext | None = None

    @model_serializer(mode="wrap")
    def compatible_wire(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        data: dict[str, object] = handler(self)
        if self.authority is None:
            data.pop("authority", None)
        if self.trust_comparison is None:
            data.pop("trust_comparison", None)
        if self.route_comparison is None:
            data.pop("route_comparison", None)
        return data

    events: tuple[SecurityEvent, ...]
    diff: TraceDiff
    trust_comparison: Literal["UNKNOWN", "INCOMPLETE", "CHANGED", "UNCHANGED"] | None = None
    route_comparison: RouteComparison | None = Field(
        default=None,
        description="Candidate route fidelity; UNKNOWN when replay receives no route manifest.",
    )
    assertions: tuple[AssertionResult, ...] = ()
    findings: tuple[Finding, ...] = ()
    substituted_dispatch_ids: tuple[Identifier, ...] = ()
    # Verifier facts in source evidence are never emitted as replayed external effects.
    external_effects_performed: Literal[False] = False


class ClassificationBasis(SecurityModel):
    category: SecurityCategory
    rule: Identifier
    severity: Severity | None = None
    event_refs: tuple[Identifier, ...] = ()
    finding_refs: tuple[Identifier, ...] = ()
    assertion_index: int | None = None


class Incident(VersionedModel):
    incident_id: Identifier
    source_bundle_digest: Digest
    categories: frozenset[SecurityCategory]
    classification_basis: tuple[ClassificationBasis, ...]


class RegressionState(StrEnum):
    ACTIVE = "ACTIVE"
    DRAFT = "DRAFT"


class RegressionCase(VersionedModel):
    regression_id: Identifier
    source_incident_id: Identifier
    source_bundle_digest: Digest
    source_evidence_digest: Digest
    state: RegressionState
    reason: Identifier
    plan: CompiledSecurityPlan | None = None
    program: ReplayProgram | None = None
    current_plan: CompiledSecurityPlan | None = None

    @model_validator(mode="after")
    def active_inputs(self) -> Self:
        if self.state == RegressionState.ACTIVE and (
            self.plan is None or self.program is None or not self.program.expectations
        ):
            raise ReplayError("INVALID_ACTIVE_REGRESSION")
        return self
