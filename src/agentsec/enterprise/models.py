"""Strict enterprise-v1 metadata, offline envelopes and bounded workflows."""

from datetime import timedelta
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from agentsec.control_plane.models import Assessment, Revision, TeamId, Version
from agentsec.domain.base import Digest, SecurityModel, Timestamp

Purpose = Literal["federation", "export"]
CaseState = Literal["OPEN", "TRIAGED", "MITIGATING", "RESOLVED", "CLOSED", "DISMISSED"]
Resolution = Literal["MITIGATED", "FALSE_POSITIVE", "DUPLICATE", "ACCEPTED_RISK"]


class EnterpriseModel(SecurityModel):
    schema_version: Literal["enterprise-v1"] = "enterprise-v1"

    @field_validator("*", mode="after")
    @classmethod
    def utc_dates(cls, value: object) -> object:
        from datetime import datetime

        if isinstance(value, datetime) and value.utcoffset() != timedelta(0):
            raise ValueError("UTC_REQUIRED")
        return value


class Pin(EnterpriseModel):
    origin: TeamId
    target: TeamId
    policy_key: TeamId
    local_policy_key: TeamId
    key_id: TeamId
    purpose: Purpose
    public_key_pem: Annotated[str, Field(min_length=1, max_length=512)]
    not_before: Timestamp
    expires_at: Timestamp
    enabled: bool = True

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.not_before >= self.expires_at:
            raise ValueError("WINDOW_INVALID")
        return self


class TrustConfig(EnterpriseModel):
    pins: Annotated[tuple[Pin, ...], Field(max_length=32)] = ()

    @model_validator(mode="after")
    def unique(self) -> Self:
        keys = [(p.origin, p.target, p.policy_key, p.key_id, p.purpose) for p in self.pins]
        if len(keys) != len(set(keys)):
            raise ValueError("DUPLICATE_PIN")
        return self


class FederationPayload(EnterpriseModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    purpose: Literal["federation"] = "federation"
    origin: TeamId
    target: TeamId
    policy_key: TeamId
    local_policy_key: TeamId
    revision_id: TeamId
    key_id: TeamId
    sequence: Annotated[int, Field(ge=1, le=1_000_000_000)]
    issued_at: Timestamp
    expires_at: Timestamp
    compiler_version: Literal["phase6-v1"] = "phase6-v1"
    document_hash: Digest
    effective_policy_hash: Digest
    compiled_plan_digest: Digest
    source: Annotated[str, Field(min_length=1, max_length=65536)]

    @model_validator(mode="after")
    def window(self) -> Self:
        if not timedelta(0) < self.expires_at - self.issued_at <= timedelta(days=7):
            raise ValueError("WINDOW_INVALID")
        if len(self.source.encode()) > 65536:
            raise ValueError("SOURCE_TOO_LARGE")
        return self


class FederatedPolicyBundle(EnterpriseModel):
    payload: FederationPayload
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


class ImportRequest(EnterpriseModel):
    bundle: FederatedPolicyBundle
    local_revision_id: TeamId
    base_generation: Version


class FederationReceipt(EnterpriseModel):
    sequence: Annotated[int, Field(ge=1, le=1_000_000_000)]
    digest: Digest
    actor: TeamId
    request_digest: Digest
    local_revision_id: TeamId
    result: Revision


class CaseInput(EnterpriseModel):
    case_id: TeamId
    category: Literal["POLICY", "IDENTITY", "DATA_FLOW", "SUPPLY_CHAIN", "EVIDENCE"]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assignee: TeamId
    agent_id: TeamId | None = None
    receipt_id: TeamId | None = None


class IncidentCase(CaseInput):
    creator: TeamId
    resolver: TeamId | None = None
    state: CaseState = "OPEN"
    resolution: Resolution | None = None
    version: Version = 1
    created_at: Timestamp
    updated_at: Timestamp

    @model_validator(mode="after")
    def lifecycle(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("TIME_ORDER_INVALID")
        if self.state in {"RESOLVED", "CLOSED", "DISMISSED"} and self.resolution is None:
            raise ValueError("RESOLUTION_REQUIRED")
        if self.state in {"RESOLVED", "CLOSED"} and self.resolver is None:
            raise ValueError("RESOLVER_REQUIRED")
        return self


class CaseTransition(EnterpriseModel):
    action: Literal["triage", "mitigate", "resolve", "close", "reopen", "dismiss"]
    expected_version: Version
    resolution: Resolution | None = None

    @model_validator(mode="after")
    def resolution_required(self) -> Self:
        if (self.action in {"resolve", "dismiss"}) != (self.resolution is not None):
            raise ValueError("RESOLUTION_INVALID")
        return self


class RiskInput(EnterpriseModel):
    risk_id: TeamId
    target_kind: Literal["case", "revision"]
    target_id: TeamId
    target_version: Annotated[int, Field(ge=1, le=1_000_000)]
    reason: Literal["COMPENSATING_CONTROL", "TIME_BOUND_REMEDIATION", "BUSINESS_CONTINUITY"]
    expires_at: Timestamp


class RiskAcceptance(RiskInput):
    requester: TeamId
    approver: TeamId | None = None
    state: Literal["REQUESTED", "APPROVED", "REJECTED", "REVOKED"] = "REQUESTED"
    version: Version = 1
    requested_at: Timestamp
    decided_at: Timestamp | None = None

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if not timedelta(0) < self.expires_at - self.requested_at <= timedelta(days=30):
            raise ValueError("EXPIRY_INVALID")
        if self.state != "REQUESTED" and (
            self.decided_at is None or self.decided_at < self.requested_at
        ):
            raise ValueError("DECISION_TIME_INVALID")
        if self.state == "APPROVED" and (
            self.approver is None
            or self.approver == self.requester
            or self.decided_at is None
            or self.decided_at >= self.expires_at
        ):
            raise ValueError("APPROVER_INVALID")
        return self


class RiskTransition(EnterpriseModel):
    action: Literal["approve", "reject", "revoke"]
    expected_version: Version


class RiskView(EnterpriseModel):
    risk: RiskAcceptance
    disposition: Literal["REQUESTED", "ACTIVE", "REJECTED", "REVOKED", "EXPIRED", "STALE"]


class WorkflowRetry(EnterpriseModel):
    actor: TeamId
    digest: Digest
    result: IncidentCase | RiskAcceptance


class SimulationInput(EnterpriseModel):
    candidate: TeamId
    expected_generation: Version
    agents: Annotated[tuple[TeamId, ...], Field(min_length=1, max_length=100)]

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len(set(self.agents)) != len(self.agents):
            raise ValueError("DUPLICATE_AGENT")
        return self


class AgentComparison(EnterpriseModel):
    agent_id: TeamId
    status: Literal["COMPARED", "UNKNOWN", "INELIGIBLE"]
    reason: Literal["FINITE_EXPECTED_PLAN", "BASELINE_UNKNOWN", "PLAN_MISMATCH", "DISABLED"]


class FleetSimulation(EnterpriseModel):
    candidate: TeamId
    generation: Version
    category: Literal["RESTRICTIVE", "EXPANSIVE", "MIXED", "UNCHANGED", "UNCLASSIFIED"]
    assessment: Assessment
    agents: Annotated[tuple[AgentComparison, ...], Field(max_length=100)]
    assurance: Literal["FINITE_SYNTHETIC_ONLY"] = "FINITE_SYNTHETIC_ONLY"


class ExportCursor(EnterpriseModel):
    org: TeamId
    format: Literal["agentsec-siem-jsonl-v1"] = "agentsec-siem-jsonl-v1"
    after: Annotated[int, Field(ge=0, le=1_000_000_000)] = 0


class SecurityRecord(EnterpriseModel):
    org: TeamId
    sequence: Annotated[int, Field(ge=1, le=1_000_000_000)]
    fingerprint: Digest
    at: Timestamp
    actor: TeamId
    target: TeamId
    action: Literal[
        "bootstrap",
        "member",
        "agent",
        "reporter",
        "draft",
        "submit",
        "approve",
        "reject",
        "publish",
        "withdraw",
        "supersede",
        "report",
        "metadata-purge",
        "federation-import",
        "case-open",
        "case-triage",
        "case-mitigate",
        "case-resolve",
        "case-close",
        "case-reopen",
        "case-dismiss",
        "risk-request",
        "risk-approve",
        "risk-reject",
        "risk-revoke",
    ]
    version: Version
    kind: Literal["GOVERNANCE", "CASE", "RISK", "REPORT"]
    assurance: Literal["GOVERNANCE_RECORD", "REPORTED_UNVERIFIED"]
    observation: Literal["PRESENT", "MISSING"] = "PRESENT"
    case_state: CaseState | None = None
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    risk_disposition: (
        Literal["REQUESTED", "ACTIVE", "REJECTED", "REVOKED", "EXPIRED", "STALE"] | None
    ) = None
    posture_status: Literal["UNKNOWN", "STALE", "BLOCKED", "HEALTHY_REPORTED"] | None = None
    policy_alignment: Literal["UNKNOWN", "REPORTED_MATCH", "MISMATCH"] | None = None
    effect_evidence: Literal["NONE", "REPORTED_UNVERIFIED"] | None = None
    ci: Literal["UNKNOWN", "PASS", "FAIL", "ERROR", "INCONCLUSIVE"] | None = None
    denied: Annotated[int, Field(ge=0, le=1_000_000)] | None = None

    @model_validator(mode="after")
    def assurance_scope(self) -> Self:
        if (self.kind == "REPORT") != (self.assurance == "REPORTED_UNVERIFIED"):
            raise ValueError("ASSURANCE_INVALID")
        if self.kind != "REPORT" and any(
            v is not None
            for v in (
                self.ci,
                self.denied,
                self.posture_status,
                self.policy_alignment,
                self.effect_evidence,
            )
        ):
            raise ValueError("REPORT_FIELDS_INVALID")
        if self.kind != "CASE" and (self.case_state is not None or self.severity is not None):
            raise ValueError("CASE_FIELDS_INVALID")
        if self.kind != "RISK" and self.risk_disposition is not None:
            raise ValueError("RISK_FIELDS_INVALID")
        return self


class ExportPage(EnterpriseModel):
    records: Annotated[tuple[SecurityRecord, ...], Field(max_length=1000)]
    cursor: ExportCursor
    high_water: Annotated[int, Field(ge=0, le=1_000_000_000)]


class ExportManifest(EnterpriseModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    purpose: Literal["export"] = "export"
    origin: TeamId
    target: TeamId
    policy_key: Literal["siem"] = "siem"
    local_policy_key: Literal["siem"] = "siem"
    key_id: TeamId
    format: Literal["agentsec-siem-jsonl-v1"] = "agentsec-siem-jsonl-v1"
    issued_at: Timestamp
    start_after: Annotated[int, Field(ge=0, le=1_000_000_000)]
    end: Annotated[int, Field(ge=0, le=1_000_000_000)]
    high_water: Annotated[int, Field(ge=0, le=1_000_000_000)]
    count: Annotated[int, Field(ge=0, le=1000)]
    byte_length: Annotated[int, Field(ge=0, le=1_048_576)]
    file_digest: Digest

    @model_validator(mode="after")
    def bounds(self) -> Self:
        if self.end < self.start_after or self.high_water < self.end:
            raise ValueError("RANGE_INVALID")
        if self.end - self.start_after != self.count:
            raise ValueError("COUNT_INVALID")
        if self.origin != self.target:
            raise ValueError("EXPORT_SCOPE_INVALID")
        return self


class SignedExport(EnterpriseModel):
    payload: ExportManifest
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]
