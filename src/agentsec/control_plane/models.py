"""Strict, bounded team-v1 governance and minimized telemetry wire models."""

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, StringConstraints, field_serializer, field_validator, model_validator

from agentsec.compiler.diff import SemanticDiff
from agentsec.compiler.reporting import ConformanceReport, CoverageReport
from agentsec.domain.base import Digest, SecurityModel, Timestamp

TeamId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,47}$")]
Counter = Annotated[int, Field(ge=0, le=1_000_000)]
Version = Annotated[int, Field(ge=0, le=1_000_000)]


class TeamModel(SecurityModel):
    schema_version: Literal["team-v1"] = "team-v1"


class Role(StrEnum):
    OWNER = "OWNER"
    EDITOR = "EDITOR"
    REVIEWER = "REVIEWER"
    VIEWER = "VIEWER"


class IdentityKind(StrEnum):
    HUMAN = "HUMAN"
    SERVICE = "SERVICE"
    REPORTER = "REPORTER"


class Key(TeamModel):
    kid: TeamId
    public_key_pem: Annotated[str, Field(min_length=1, max_length=512)]


class Issuer(TeamModel):
    issuer: Annotated[str, Field(min_length=1, max_length=256)]
    audience: Annotated[str, Field(min_length=1, max_length=128)]
    keys: Annotated[tuple[Key, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def unique_keys(self) -> Self:
        if len({k.kid for k in self.keys}) != len(self.keys):
            raise ValueError("DUPLICATE_KEY")
        return self


class TeamConfig(TeamModel):
    issuers: Annotated[tuple[Issuer, ...], Field(min_length=1, max_length=8)]
    skew_seconds: Annotated[int, Field(ge=0, le=60)] = 0
    stale_seconds: Annotated[int, Field(ge=60, le=604800)] = 3600
    retention_seconds: Annotated[int, Field(ge=60, le=31536000)] = 2592000

    @model_validator(mode="after")
    def unique_issuers(self) -> Self:
        if len({i.issuer for i in self.issuers}) != len(self.issuers):
            raise ValueError("DUPLICATE_ISSUER")
        return self


class Binding(TeamModel):
    identity_id: TeamId
    issuer: Annotated[str, Field(min_length=1, max_length=256)]
    subject: Annotated[str, Field(min_length=1, max_length=128)]
    kind: IdentityKind


class Member(TeamModel):
    identity_id: TeamId
    role: Role
    enabled: bool = True
    expected_version: Version = 0


class Agent(TeamModel):
    agent_id: TeamId
    environment: TeamId
    repository: TeamId
    owner_id: TeamId
    policy_revision: TeamId | None = None
    expected_plan: Digest | None = None
    enabled: bool = True
    expected_version: Version = 0


class Reporter(TeamModel):
    identity_id: TeamId
    agent_id: TeamId
    source: Literal["RUNTIME", "CI"]
    enabled: bool = True
    expected_version: Version = 0


class RevisionInput(TeamModel):
    revision_id: TeamId
    policy_key: TeamId
    source: Annotated[str, Field(min_length=1, max_length=65536)]
    upload_source: Literal[True]
    compiler_version: Literal["phase6-v1"] = "phase6-v1"
    base_generation: Version

    @field_validator("upload_source", mode="before")
    @classmethod
    def explicit_source_upload(cls, value: object) -> Literal[True]:
        if value is not True:
            raise ValueError("EXPLICIT_SOURCE_UPLOAD_REQUIRED")
        return True


class Transition(TeamModel):
    action: Literal["submit", "approve", "reject", "publish", "withdraw"]
    expected_version: Version
    acknowledge_initial: bool = False
    acknowledge_expansion: bool = False
    acknowledge_gaps: bool = False
    review_reason: Literal["INITIAL_POLICY", "RESTRICTIVE_CHANGE", "REVIEWED_CHANGE"] | None = None


class Assessment(TeamModel):
    semantic_diff: SemanticDiff | None = None
    conformance_report: ConformanceReport
    coverage_report: CoverageReport
    document_hash: Digest
    effective_policy_hash: Digest
    compiled_plan_digest: Digest
    compiler_version: Literal["phase6-v1"] = "phase6-v1"
    initial: bool
    expansions: bool
    gaps: Counter
    unsupported: Counter
    conformance: Literal["PASS", "FAIL", "UNKNOWN"]
    diff_status: Literal["INITIAL", "COMPARED", "UNKNOWN"]
    change_kinds: Annotated[tuple[Annotated[str, Field(max_length=64)], ...], Field(max_length=64)]


class Revision(TeamModel):
    revision_id: TeamId
    policy_key: TeamId
    author: TeamId
    base_generation: Version
    state: Literal["DRAFT", "IN_REVIEW", "APPROVED", "PUBLISHED", "SUPERSEDED", "WITHDRAWN"]
    version: Version
    reviewer: TeamId | None = None
    review: Transition | None = None
    assessment: Assessment


class Counters(TeamModel):
    requested: Counter = 0
    denied: Counter = 0
    approval_requested: Counter = 0
    approval_decided: Counter = 0
    dispatched: Counter = 0
    returned: Counter = 0
    effect_verified: Counter = 0
    errors: Counter = 0

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if (
            self.denied > self.requested
            or self.dispatched > self.requested
            or self.returned > self.dispatched
            or self.effect_verified > self.dispatched
            or self.approval_requested > self.requested
            or self.approval_decided > self.approval_requested
        ):
            raise ValueError("COUNTER_CONTRADICTION")
        return self


class Metadata(TeamModel):
    run_id: UUID
    agent_id: TeamId
    environment: TeamId
    repository: TeamId
    # Opaque operator-assigned revision label; a reporter claim, never attestation.
    policy_revision: TeamId | None = None
    source: Literal["RUNTIME", "CI"]
    period_start: Timestamp
    period_end: Timestamp
    counters: Counters = Counters()
    completeness: Literal["INCOMPLETE", "REPORTED_COMPLETE"] = "INCOMPLETE"
    coverage: Literal["UNKNOWN", "GAPS", "SYNTHETIC_PASS"] = "UNKNOWN"
    mode: Literal["UNKNOWN", "ENFORCE", "SHADOW", "DISABLED"] = "UNKNOWN"
    ci: Literal["UNKNOWN", "PASS", "FAIL", "ERROR", "INCONCLUSIVE"] = "UNKNOWN"
    regression: Literal["UNKNOWN", "PASS", "FAIL", "ERROR", "DRAFT"] = "UNKNOWN"
    replay: Literal["UNKNOWN", "PASS", "FAIL", "BLOCKED"] = "UNKNOWN"

    @field_serializer("run_id")
    def serialize_run_id(self, value: UUID) -> str:
        return str(value)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        seconds = (self.period_end - self.period_start).total_seconds()
        if seconds < 0 or seconds > 86400:
            raise ValueError("PERIOD_INVALID")
        if self.source == "RUNTIME" and (
            self.ci != "UNKNOWN" or self.regression != "UNKNOWN" or self.replay != "UNKNOWN"
        ):
            raise ValueError("SOURCE_CONTRADICTION")
        if self.source == "CI" and self.mode != "UNKNOWN":
            raise ValueError("SOURCE_CONTRADICTION")
        return self


class Receipt(TeamModel):
    receipt_id: TeamId
    received_at: Timestamp
    assurance: Literal["REPORTED_UNVERIFIED"] = "REPORTED_UNVERIFIED"
    report: Metadata


class AgentPosture(TeamModel):
    agent_id: TeamId
    status: Literal["UNKNOWN", "STALE", "BLOCKED", "HEALTHY_REPORTED"]
    policy_alignment: Literal["UNKNOWN", "REPORTED_MATCH", "MISMATCH"] = "UNKNOWN"
    effect_evidence: Literal["NONE", "REPORTED_UNVERIFIED"] = "NONE"
    flags: tuple[
        Literal[
            "NO_REPORT",
            "STALE",
            "GAPS",
            "CI_FAILURE",
            "INCOMPLETE",
            "DISABLED",
            "POLICY_UNKNOWN",
            "POLICY_MISMATCH",
        ],
        ...,
    ]
    last_report: Receipt | None = None
    last_runtime: Receipt | None = None
    last_ci: Receipt | None = None


class Posture(TeamModel):
    org_id: TeamId
    assurance: Literal["REPORTED_UNVERIFIED"] = "REPORTED_UNVERIFIED"
    agents: tuple[AgentPosture, ...]


class Publication(TeamModel):
    policy_key: TeamId
    generation: Version
    revision_id: TeamId | None = None


class Retry(TeamModel):
    request: Transition
    identity_id: TeamId
    digest: Digest
    result: Revision


class Tombstone(TeamModel):
    digest: Digest
    receipt_id: TeamId


class Page(TeamModel):
    items: tuple[Member | Agent | Reporter | Revision | Receipt, ...]
    offset: Version
    limit: Annotated[int, Field(ge=1, le=100)]
