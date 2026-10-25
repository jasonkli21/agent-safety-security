"""Tenant-scoped enterprise workflows layered on existing team authorization."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta

from agentsec.control_plane.auth import VerifiedIdentity
from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import Agent, Binding, Member, Receipt, Revision
from agentsec.control_plane.policies import assess, verify_fetch
from agentsec.control_plane.service import Permission, TeamService, checked_model, required
from agentsec.control_plane.store import Kind, ScopedStore
from agentsec.domain.serialization import content_digest
from agentsec.enterprise.federation import verify_bundle
from agentsec.enterprise.models import (
    AgentComparison,
    CaseInput,
    CaseTransition,
    ExportCursor,
    ExportPage,
    FederationReceipt,
    FleetSimulation,
    ImportRequest,
    IncidentCase,
    RiskAcceptance,
    RiskInput,
    RiskTransition,
    RiskView,
    SecurityRecord,
    SimulationInput,
    TrustConfig,
    WorkflowRetry,
)


class EnterpriseService:
    def __init__(self, team: TeamService, trust: TrustConfig | None = None) -> None:
        self.team = team
        self.trust = checked_model(TrustConfig, trust or TrustConfig())

    @contextmanager
    def authorized(
        self, identity: VerifiedIdentity, org: str, permission: Permission
    ) -> Iterator[tuple[ScopedStore, Binding]]:
        with self.team.authorized(identity, org, permission) as pair:
            yield pair

    def human_member(self, scope: ScopedStore, identity_id: str, *, owner: bool = False) -> None:
        row = scope.get("member", identity_id)
        if row is None:
            raise TeamError("DENIED")
        member = Member.model_validate_json(row[1])
        if not member.enabled or (owner and member.role != "OWNER"):
            raise TeamError("DENIED")
        if self.team.store.binding_by_id(identity_id).kind != "HUMAN":
            raise TeamError("DENIED")

    def import_bundle(self, identity: VerifiedIdentity, org: str, value: ImportRequest) -> Revision:
        value = checked_model(ImportRequest, value)
        bundle = value.bundle
        payload = bundle.payload
        with self.authorized(identity, org, "draft"):
            if payload.target != org:
                raise TeamError("DENIED")
        # Signature/pin/time before any untrusted policy compilation.
        trust = self.trust
        pin, _ = verify_bundle(bundle, trust, self.team.clock())
        # Stage publication snapshot, then finite assessment outside global write lock.
        with self.authorized(identity, org, "draft") as (scope, _):
            publication = self.team.publication(scope, payload.local_policy_key)
            previous = scope.source(publication.revision_id)[0] if publication.revision_id else None
        assessment = assess(payload.source, previous)
        with self.authorized(identity, org, "draft") as (scope, actor):
            if self.trust != trust or not pin.not_before <= self.team.clock() < pin.expires_at:
                raise TeamError("TRUST_UNAVAILABLE")
            if not payload.issued_at <= self.team.clock() < payload.expires_at:
                raise TeamError("SIGNATURE_INVALID")
            key = content_digest((payload.origin, payload.policy_key))[7:]
            old = scope.get("federation", key)
            if old:
                record = FederationReceipt.model_validate_json(old[1])
                if payload.sequence <= record.sequence:
                    if (record.sequence, record.request_digest, record.actor) == (
                        payload.sequence,
                        content_digest(value),
                        actor.identity_id,
                    ):
                        return record.result
                    raise TeamError("CONFLICT")
            current = self.team.publication(scope, payload.local_policy_key)
            if current != publication or current.generation != value.base_generation:
                raise TeamError("CONFLICT")
            if scope.get("revision", value.local_revision_id):
                raise TeamError("CONFLICT")
            revision = Revision(
                revision_id=value.local_revision_id,
                policy_key=payload.local_policy_key,
                author=actor.identity_id,
                base_generation=current.generation,
                state="DRAFT",
                version=1,
                assessment=assessment,
            )
            scope.put("revision", revision.revision_id, revision.model_dump_json())
            scope.add_source(revision.revision_id, payload.source, assessment.model_dump_json())
            scope.put(
                "federation",
                key,
                FederationReceipt(
                    sequence=payload.sequence,
                    digest=content_digest(bundle),
                    actor=actor.identity_id,
                    request_digest=content_digest(value),
                    local_revision_id=revision.revision_id,
                    result=revision,
                ).model_dump_json(),
                old[0] if old else 0,
            )
            self.team.audit(scope, actor, "federation-import", revision.revision_id, 1)
            return revision

    def open_case(self, identity: VerifiedIdentity, org: str, value: CaseInput) -> IncidentCase:
        value = checked_model(CaseInput, value)
        with self.authorized(identity, org, "draft") as (scope, actor):
            self.human_member(scope, value.assignee)
            if value.agent_id:
                agent = Agent.model_validate_json(required(scope, "agent", value.agent_id)[1])
                if not agent.enabled:
                    raise TeamError("DENIED")
            if value.receipt_id:
                receipt = Receipt.model_validate_json(
                    required(scope, "receipt", value.receipt_id)[1]
                )
                if value.agent_id != receipt.report.agent_id:
                    raise TeamError("DENIED")
            old = scope.get("case", value.case_id)
            if old:
                existing = IncidentCase.model_validate_json(old[1])
                if (
                    existing.creator == actor.identity_id
                    and existing.version == 1
                    and all(getattr(existing, k) == v for k, v in value.model_dump().items())
                ):
                    return existing
                raise TeamError("CONFLICT")
            now = self.team.clock()
            result = IncidentCase(
                **value.model_dump(exclude={"schema_version"}),
                creator=actor.identity_id,
                created_at=now,
                updated_at=now,
            )
            scope.put("case", value.case_id, result.model_dump_json())
            self.team.audit(scope, actor, "case-open", value.case_id, 1)
            return result

    def case(self, identity: VerifiedIdentity, org: str, key: str) -> IncidentCase:
        with self.authorized(identity, org, "read") as (scope, _):
            return IncidentCase.model_validate_json(required(scope, "case", key)[1])

    def transition_case(
        self, identity: VerifiedIdentity, org: str, key: str, value: CaseTransition
    ) -> IncidentCase:
        value = checked_model(CaseTransition, value)
        permissions: dict[str, Permission] = {
            "triage": "draft",
            "mitigate": "draft",
            "resolve": "review",
            "dismiss": "review",
            "close": "manage",
            "reopen": "manage",
        }
        with self.authorized(identity, org, permissions[value.action]) as (scope, actor):
            retry_key = content_digest(("case", key, value.expected_version))[7:]
            retry = self.retry(scope, retry_key, actor, value)
            if retry:
                assert isinstance(retry, IncidentCase)
                return retry
            version, body = required(scope, "case", key)
            case = IncidentCase.model_validate_json(body)
            self.human_member(scope, case.assignee)
            allowed = {
                "triage": {"OPEN"},
                "mitigate": {"TRIAGED"},
                "resolve": {"MITIGATING"},
                "close": {"RESOLVED"},
                "reopen": {"RESOLVED", "CLOSED", "DISMISSED"},
                "dismiss": {"OPEN", "TRIAGED", "MITIGATING"},
            }
            if version != value.expected_version or case.state not in allowed[value.action]:
                raise TeamError("CONFLICT")
            if case.severity in {"HIGH", "CRITICAL"} and value.action in {"close", "dismiss"}:
                if actor.identity_id in {case.creator, case.resolver}:
                    raise TeamError("DENIED")
            states = {
                "triage": "TRIAGED",
                "mitigate": "MITIGATING",
                "resolve": "RESOLVED",
                "close": "CLOSED",
                "reopen": "OPEN",
                "dismiss": "DISMISSED",
            }
            result = IncidentCase.model_validate_json(
                case.model_copy(
                    update={
                        "state": states[value.action],
                        "version": version + 1,
                        "updated_at": self.team.clock(),
                        "resolver": actor.identity_id
                        if value.action == "resolve"
                        else None
                        if value.action == "reopen"
                        else case.resolver,
                        "resolution": None
                        if value.action == "reopen"
                        else value.resolution or case.resolution,
                    }
                ).model_dump_json()
            )
            scope.put("case", key, result.model_dump_json(), version)
            self.save_retry(scope, retry_key, actor, value, result)
            self.team.audit(scope, actor, "case-" + value.action, key, result.version)
            return result

    def retry(
        self, scope: ScopedStore, key: str, actor: Binding, value: CaseTransition | RiskTransition
    ) -> IncidentCase | RiskAcceptance | None:
        row = scope.get("enterprise_retry", key)
        if row:
            retry = WorkflowRetry.model_validate_json(row[1])
            if retry.actor != actor.identity_id or retry.digest != content_digest(value):
                raise TeamError("CONFLICT")
            return retry.result
        return None

    def save_retry(
        self,
        scope: ScopedStore,
        key: str,
        actor: Binding,
        value: CaseTransition | RiskTransition,
        result: IncidentCase | RiskAcceptance,
    ) -> None:
        scope.put(
            "enterprise_retry",
            key,
            WorkflowRetry(
                actor=actor.identity_id, digest=content_digest(value), result=result
            ).model_dump_json(),
        )

    def target_current(self, scope: ScopedStore, value: RiskInput) -> bool:
        row = scope.get(value.target_kind, value.target_id)
        if row is None or row[0] != value.target_version:
            return False
        if value.target_kind == "revision":
            return Revision.model_validate_json(row[1]).state == "PUBLISHED"
        return IncidentCase.model_validate_json(row[1]).state not in {"CLOSED", "DISMISSED"}

    def request_risk(
        self, identity: VerifiedIdentity, org: str, value: RiskInput
    ) -> RiskAcceptance:
        value = checked_model(RiskInput, value)
        with self.authorized(identity, org, "draft") as (scope, actor):
            now = self.team.clock()
            if not now < value.expires_at <= now + timedelta(days=30):
                raise TeamError("INVALID_INPUT")
            if not self.target_current(scope, value):
                raise TeamError("CONFLICT")
            existing = scope.get("risk", value.risk_id)
            if existing:
                old = RiskAcceptance.model_validate_json(existing[1])
                if (
                    old.requester == actor.identity_id
                    and old.version == 1
                    and all(getattr(old, k) == v for k, v in value.model_dump().items())
                ):
                    return old
                raise TeamError("CONFLICT")
            result = RiskAcceptance(
                **value.model_dump(exclude={"schema_version"}),
                requester=actor.identity_id,
                requested_at=now,
            )
            scope.put("risk", value.risk_id, result.model_dump_json())
            self.team.audit(scope, actor, "risk-request", value.risk_id, 1)
            return result

    def risk_view(self, scope: ScopedStore, risk: RiskAcceptance) -> RiskView:
        disposition = {
            "REQUESTED": "REQUESTED",
            "APPROVED": "ACTIVE",
            "REJECTED": "REJECTED",
            "REVOKED": "REVOKED",
        }[risk.state]
        if risk.state in {"REQUESTED", "APPROVED"}:
            if self.team.clock() >= risk.expires_at:
                disposition = "EXPIRED"
            else:
                try:
                    self.human_member(scope, risk.requester)
                    requester = Member.model_validate_json(
                        required(scope, "member", risk.requester)[1]
                    )
                    if requester.role not in {"OWNER", "EDITOR"}:
                        disposition = "STALE"
                    if risk.approver:
                        self.human_member(scope, risk.approver, owner=True)
                    if not self.target_current(scope, risk):
                        disposition = "STALE"
                except TeamError:
                    disposition = "STALE"
        return RiskView.model_validate_json(
            RiskView.model_construct(risk=risk, disposition=disposition).model_dump_json()
        )

    def risk(self, identity: VerifiedIdentity, org: str, key: str) -> RiskView:
        with self.authorized(identity, org, "read") as (scope, _):
            return self.risk_view(
                scope, RiskAcceptance.model_validate_json(required(scope, "risk", key)[1])
            )

    def transition_risk(
        self, identity: VerifiedIdentity, org: str, key: str, value: RiskTransition
    ) -> RiskAcceptance:
        value = checked_model(RiskTransition, value)
        with self.authorized(identity, org, "manage") as (scope, actor):
            retry_key = content_digest(("risk", key, value.expected_version))[7:]
            retry = self.retry(scope, retry_key, actor, value)
            if retry:
                assert isinstance(retry, RiskAcceptance)
                return retry
            version, body = required(scope, "risk", key)
            risk = RiskAcceptance.model_validate_json(body)
            if version != value.expected_version or risk.state != (
                "APPROVED" if value.action == "revoke" else "REQUESTED"
            ):
                raise TeamError("CONFLICT")
            if value.action == "approve":
                if actor.identity_id == risk.requester:
                    raise TeamError("DENIED")
                if self.risk_view(scope, risk).disposition != "REQUESTED":
                    raise TeamError("CONFLICT")
            result = RiskAcceptance.model_validate_json(
                risk.model_copy(
                    update={
                        "state": {"approve": "APPROVED", "reject": "REJECTED", "revoke": "REVOKED"}[
                            value.action
                        ],
                        "version": version + 1,
                        "decided_at": self.team.clock(),
                        "approver": actor.identity_id
                        if value.action == "approve"
                        else risk.approver,
                    }
                ).model_dump_json()
            )
            scope.put("risk", key, result.model_dump_json(), version)
            self.save_retry(scope, retry_key, actor, value, result)
            self.team.audit(scope, actor, "risk-" + value.action, key, result.version)
            return result

    def simulation_snapshot(
        self, scope: ScopedStore, value: SimulationInput
    ) -> tuple[Revision, str, str | None, tuple[tuple[str, int, str], ...], str]:
        revision = Revision.model_validate_json(required(scope, "revision", value.candidate)[1])
        publication = self.team.publication(scope, revision.policy_key)
        if publication.generation != value.expected_generation:
            raise TeamError("CONFLICT")
        source = scope.source(value.candidate)[0]
        previous = scope.source(publication.revision_id)[0] if publication.revision_id else None
        inventory = tuple((key, *required(scope, "agent", key)) for key in value.agents)
        # Bind publication, candidate and baseline workflow state too.
        baseline = (
            scope.get("revision", publication.revision_id) if publication.revision_id else None
        )
        return revision, source, previous, inventory, content_digest((publication, baseline))

    def simulate(
        self, identity: VerifiedIdentity, org: str, value: SimulationInput
    ) -> FleetSimulation:
        value = checked_model(SimulationInput, value)
        with self.authorized(identity, org, "draft") as (scope, _):
            snapshot = self.simulation_snapshot(scope, value)
        revision, source, previous, inventory, _ = snapshot
        assessment = assess(source, previous)
        baseline_assessment = assess(previous, None) if previous else None
        comparable = (
            previous is not None
            and not assessment.unsupported
            and assessment.diff_status == "COMPARED"
            and baseline_assessment is not None
            and not baseline_assessment.unsupported
            and assessment.conformance != "FAIL"
        )
        # Source/hash mismatches are blocked, never silently compared.
        verify_fetch(source, revision.assessment)
        with self.authorized(identity, org, "draft") as (scope, _):
            if snapshot != self.simulation_snapshot(scope, value):
                raise TeamError("CONFLICT")
            publication = self.team.publication(scope, revision.policy_key)
            rows: list[AgentComparison] = []
            for key, _, body in inventory:
                agent = Agent.model_validate_json(body)
                aligned = bool(
                    baseline_assessment
                    and agent.policy_revision == publication.revision_id
                    and agent.expected_plan == baseline_assessment.compiled_plan_digest
                )
                rows.append(
                    AgentComparison(
                        agent_id=key,
                        status="INELIGIBLE"
                        if not agent.enabled
                        else "COMPARED"
                        if comparable and aligned
                        else "UNKNOWN",
                        reason="DISABLED"
                        if not agent.enabled
                        else "BASELINE_UNKNOWN"
                        if not comparable
                        else "FINITE_EXPECTED_PLAN"
                        if aligned
                        else "PLAN_MISMATCH",
                    )
                )
        kinds = set(assessment.change_kinds)
        restrictions = {
            "authority_reduction",
            "data_policy_tightening",
            "budget_tightening",
            "task_scope_narrowing",
        }
        neutral = {"policy_explanation_change", "data_policy_explanation_change"}
        expansive = kinds & {
            "authority_expansion",
            "data_policy_relaxation",
            "budget_relaxation",
            "task_scope_widening",
        }
        # Directionless identity/configuration/timeout changes cannot be ranked as safer.
        unclassified = kinds - restrictions - neutral - expansive - {"approval_boundary"}
        category = (
            "UNCLASSIFIED"
            if not comparable or unclassified
            else "UNCHANGED"
            if not kinds
            else (
                "MIXED"
                if expansive and kinds & restrictions
                else "EXPANSIVE"
                if expansive
                else "RESTRICTIVE"
                if kinds & restrictions
                else "UNCHANGED"
            )
        )
        result = FleetSimulation.model_validate_json(
            FleetSimulation.model_construct(
                candidate=value.candidate,
                generation=value.expected_generation,
                category=category,
                assessment=assessment,
                agents=tuple(rows),
            ).model_dump_json()
        )
        if len(result.model_dump_json().encode("utf-8")) > 1_048_576:
            raise TeamError("TOO_LARGE")
        return result

    def export_page(self, identity: VerifiedIdentity, org: str, cursor: ExportCursor) -> ExportPage:
        cursor = checked_model(ExportCursor, cursor)
        with self.authorized(identity, org, "manage") as (scope, _):
            if cursor.org != org:
                raise TeamError("DENIED")
            audit_version = scope.connection.execute(
                "SELECT max(seq) FROM audit WHERE org=?", (org,)
            ).fetchone()[0]
        posture = self.team.posture(identity, org)
        with self.authorized(identity, org, "manage") as (scope, _):
            if (
                audit_version
                != scope.connection.execute(
                    "SELECT max(seq) FROM audit WHERE org=?", (org,)
                ).fetchone()[0]
            ):
                raise TeamError("CONFLICT")
            postures = {a.agent_id: a for a in posture.agents}
            if cursor.org != org:
                raise TeamError("DENIED")
            # Durable audit never purged; tenant sequence is independent of other tenants.
            high = int(
                scope.connection.execute(
                    "SELECT count(*) FROM audit WHERE org=?", (org,)
                ).fetchone()[0]
            )
            raw = scope.connection.execute(
                "SELECT row_number() OVER (ORDER BY seq),actor,action,target,version,at "
                "FROM audit WHERE org=? ORDER BY seq LIMIT 1000 OFFSET ?",
                (org, cursor.after),
            ).fetchall()
            if cursor.after > high:
                raise TeamError("CONFLICT")
            records: list[SecurityRecord] = []
            for seq, actor, action, target, version, at in raw:
                kind: Kind | None = (
                    "case"
                    if action.startswith("case-")
                    else (
                        "risk"
                        if action.startswith("risk-")
                        else "receipt"
                        if action == "report"
                        else None
                    )
                )
                observed = scope.get(kind, target) if kind else None
                case = (
                    IncidentCase.model_validate_json(observed[1])
                    if observed and kind == "case"
                    else None
                )
                risk = (
                    RiskAcceptance.model_validate_json(observed[1])
                    if observed and kind == "risk"
                    else None
                )
                receipt = (
                    Receipt.model_validate_json(observed[1])
                    if observed and kind == "receipt"
                    else None
                )
                agent_posture = postures.get(receipt.report.agent_id) if receipt else None
                records.append(
                    SecurityRecord.model_validate(
                        {
                            "org": org,
                            "sequence": seq,
                            "actor": actor,
                            "action": action,
                            "target": target,
                            "version": version,
                            "fingerprint": content_digest(
                                (org, seq, actor, action, target, version, at)
                            ),
                            "at": datetime.fromisoformat(at),
                            "kind": "CASE"
                            if kind == "case"
                            else "RISK"
                            if kind == "risk"
                            else "REPORT"
                            if kind == "receipt"
                            else "GOVERNANCE",
                            "assurance": "REPORTED_UNVERIFIED"
                            if kind == "receipt"
                            else "GOVERNANCE_RECORD",
                            "observation": "MISSING" if kind and not observed else "PRESENT",
                            "case_state": case.state if case else None,
                            "severity": case.severity if case else None,
                            "risk_disposition": self.risk_view(scope, risk).disposition
                            if risk
                            else None,
                            "posture_status": agent_posture.status if agent_posture else None,
                            "policy_alignment": agent_posture.policy_alignment
                            if agent_posture
                            else None,
                            "effect_evidence": agent_posture.effect_evidence
                            if agent_posture
                            else None,
                            "ci": receipt.report.ci if receipt else None,
                            "denied": receipt.report.counters.denied if receipt else None,
                        }
                    )
                )
            return ExportPage(
                records=tuple(records),
                high_water=high,
                cursor=ExportCursor(org=org, after=cursor.after + len(records)),
            )
