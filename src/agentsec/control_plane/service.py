"""Authorization and governance transactions; no runtime integration or network calls."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, TypeAdapter

from agentsec.control_plane.auth import VerifiedIdentity
from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import (
    Agent,
    AgentPosture,
    Binding,
    IdentityKind,
    Member,
    Metadata,
    Page,
    Posture,
    Publication,
    Receipt,
    Reporter,
    Retry,
    Revision,
    RevisionInput,
    Role,
    TeamConfig,
    TeamId,
    Tombstone,
    Transition,
)
from agentsec.control_plane.policies import assess
from agentsec.control_plane.store import Kind, ScopedStore, Store
from agentsec.domain.serialization import content_digest

Permission = Literal["read", "draft", "review", "publish", "manage", "report"]
PERMISSIONS: dict[Permission, frozenset[Role]] = {
    "read": frozenset(Role),
    "draft": frozenset({Role.OWNER, Role.EDITOR}),
    "review": frozenset({Role.OWNER, Role.REVIEWER}),
    "publish": frozenset({Role.OWNER}),
    "manage": frozenset({Role.OWNER}),
    "report": frozenset(),
}
ID = TypeAdapter(TeamId)


def checked_model[M: BaseModel](model: type[M], value: M) -> M:
    try:
        return model.model_validate_json(value.model_dump_json())
    except ValueError:
        raise TeamError("INVALID_INPUT") from None


def identifier(value: str) -> str:
    try:
        return ID.validate_python(value, strict=True)
    except ValueError:
        raise TeamError("INVALID_INPUT") from None


def required(scope: ScopedStore, kind: Kind, key: str) -> tuple[int, str]:
    value = scope.get(kind, identifier(key))
    if value is None:
        raise TeamError("NOT_FOUND")
    return value


def newest_report(reports: list[Receipt], source: str | None = None) -> Receipt | None:
    return max(
        (r for r in reports if source is None or r.report.source == source),
        key=lambda r: (r.report.period_end, r.received_at, r.receipt_id),
        default=None,
    )


class TeamService:
    def __init__(
        self, store: Store, config: TeamConfig, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.store = store
        self.config = checked_model(TeamConfig, config)
        self.clock = clock or (lambda: datetime.now(UTC))

    def bootstrap(self, org: str, owner: Binding) -> None:
        """Explicit offline operator operation. Never exposed through HTTP."""
        org = identifier(org)
        owner = checked_model(Binding, owner)
        if owner.kind != IdentityKind.HUMAN:
            raise TeamError("DENIED")
        with self.store.transaction():
            bound = self.store.binding_by_id(owner.identity_id)
            if bound != owner:
                raise TeamError("DENIED")
            self.store.connection.execute("INSERT INTO orgs VALUES (?)", (org,))
            scope = self.store.scoped(org)
            scope.put(
                "member",
                owner.identity_id,
                Member(identity_id=owner.identity_id, role=Role.OWNER).model_dump_json(),
            )
            self.audit(scope, owner, "bootstrap", org, 1)

    def audit(
        self, scope: ScopedStore, actor: Binding, action: str, target: str, version: int
    ) -> None:
        scope.audit(actor.identity_id, action, target, version, self.clock().isoformat())

    @contextmanager
    def authorized(
        self, identity: VerifiedIdentity, org: str, permission: Permission
    ) -> Iterator[tuple[ScopedStore, Binding]]:
        org = identifier(org)
        with self.store.transaction():
            if self.clock().timestamp() >= identity.expires_at:
                raise TeamError("TOKEN_INVALID")
            binding = self.store.binding(identity.issuer, identity.subject)
            scope = self.store.scoped(org)
            if permission == "report":
                if binding.kind != IdentityKind.REPORTER:
                    raise TeamError("DENIED")
                row = scope.get("reporter", binding.identity_id)
                if row is None or not Reporter.model_validate_json(row[1]).enabled:
                    raise TeamError("DENIED")
            else:
                if binding.kind == IdentityKind.REPORTER:
                    raise TeamError("DENIED")
                row = scope.get("member", binding.identity_id)
                if row is None:
                    raise TeamError("DENIED")
                member = Member.model_validate_json(row[1])
                if not member.enabled or member.role not in PERMISSIONS[permission]:
                    raise TeamError("DENIED")
                if binding.kind == IdentityKind.SERVICE and (
                    permission != "read" or member.role != Role.VIEWER
                ):
                    raise TeamError("DENIED")
            yield scope, binding

    def member(self, identity: VerifiedIdentity, org: str, value: Member) -> Member:
        value = checked_model(Member, value)
        with self.authorized(identity, org, "manage") as (scope, actor):
            binding = self.store.binding_by_id(value.identity_id)
            if binding.kind == IdentityKind.REPORTER or (
                binding.kind == IdentityKind.SERVICE and value.role != Role.VIEWER
            ):
                raise TeamError("DENIED")
            # Avoid self-lockout and implicit self-promotion; another owner can revoke.
            if actor.identity_id == value.identity_id:
                raise TeamError("DENIED")
            result = value.model_copy(update={"expected_version": value.expected_version + 1})
            scope.put("member", value.identity_id, result.model_dump_json(), value.expected_version)
            self.audit(scope, actor, "member", value.identity_id, result.expected_version)
            return result

    def agent(self, identity: VerifiedIdentity, org: str, value: Agent) -> Agent:
        value = checked_model(Agent, value)
        with self.authorized(identity, org, "manage") as (scope, actor):
            owner = scope.get("member", value.owner_id)
            if owner is None or not Member.model_validate_json(owner[1]).enabled:
                raise TeamError("DENIED")
            if value.policy_revision is not None:
                revision = Revision.model_validate_json(
                    required(scope, "revision", value.policy_revision)[1]
                )
                if (
                    revision.state != "PUBLISHED"
                    or value.expected_plan != revision.assessment.compiled_plan_digest
                ):
                    raise TeamError("CONFLICT")
            old = scope.get("agent", value.agent_id)
            if old:
                previous = Agent.model_validate_json(old[1])
                if (previous.environment, previous.repository, previous.owner_id) != (
                    value.environment,
                    value.repository,
                    value.owner_id,
                ):
                    raise TeamError("CONFLICT")
            result = value.model_copy(update={"expected_version": value.expected_version + 1})
            scope.put("agent", value.agent_id, result.model_dump_json(), value.expected_version)
            self.audit(scope, actor, "agent", value.agent_id, result.expected_version)
            return result

    def reporter(self, identity: VerifiedIdentity, org: str, value: Reporter) -> Reporter:
        value = checked_model(Reporter, value)
        with self.authorized(identity, org, "manage") as (scope, actor):
            if self.store.binding_by_id(value.identity_id).kind != IdentityKind.REPORTER:
                raise TeamError("DENIED")
            agent = Agent.model_validate_json(required(scope, "agent", value.agent_id)[1])
            if not agent.enabled:
                raise TeamError("DENIED")
            # Reporter binding is one exact tenant/agent/source for its entire lifetime.
            other = self.store.connection.execute(
                "SELECT org,body FROM records WHERE kind='reporter' AND id=?", (value.identity_id,)
            ).fetchall()
            if any(row[0] != org for row in other):
                raise TeamError("DENIED")
            previous = scope.get("reporter", value.identity_id)
            if previous:
                old = Reporter.model_validate_json(previous[1])
                if (old.agent_id, old.source) != (value.agent_id, value.source):
                    raise TeamError("CONFLICT")
            result = value.model_copy(update={"expected_version": value.expected_version + 1})
            scope.put(
                "reporter", value.identity_id, result.model_dump_json(), value.expected_version
            )
            self.audit(scope, actor, "reporter", value.identity_id, result.expected_version)
            return result

    def publication(self, scope: ScopedStore, policy: str) -> Publication:
        row = scope.get("publication", policy)
        return (
            Publication.model_validate_json(row[1])
            if row
            else Publication(policy_key=policy, generation=0)
        )

    def create_revision(
        self, identity: VerifiedIdentity, org: str, value: RevisionInput
    ) -> Revision:
        value = checked_model(RevisionInput, value)
        with self.authorized(identity, org, "draft") as (scope, actor):
            old = scope.get("revision", value.revision_id)
            if old:
                revision = Revision.model_validate_json(old[1])
                if (
                    scope.source(value.revision_id)[0],
                    revision.policy_key,
                    revision.author,
                    revision.base_generation,
                ) == (value.source, value.policy_key, actor.identity_id, value.base_generation):
                    return revision
                raise TeamError("CONFLICT")
            publication = self.publication(scope, value.policy_key)
            if publication.generation != value.base_generation:
                raise TeamError("CONFLICT")
            previous = scope.source(publication.revision_id)[0] if publication.revision_id else None
            assessment = assess(value.source, previous)
            revision = Revision(
                revision_id=value.revision_id,
                policy_key=value.policy_key,
                author=actor.identity_id,
                base_generation=value.base_generation,
                state="DRAFT",
                version=1,
                assessment=assessment,
            )
            scope.put("revision", value.revision_id, revision.model_dump_json())
            scope.add_source(value.revision_id, value.source, assessment.model_dump_json())
            self.audit(scope, actor, "draft", value.revision_id, 1)
            return revision

    def transition(
        self, identity: VerifiedIdentity, org: str, revision_id: str, value: Transition
    ) -> Revision:
        value = checked_model(Transition, value)
        revision_id = identifier(revision_id)
        permission: Permission = {
            "submit": "draft",
            "approve": "review",
            "reject": "review",
            "publish": "publish",
            "withdraw": "publish",
        }[value.action]  # type: ignore[assignment]
        with self.authorized(identity, org, permission) as (scope, actor):
            retry_id = f"{revision_id}-{value.expected_version}"
            digest = content_digest(value)
            retry = scope.get("retry", retry_id)
            if retry:
                record = Retry.model_validate_json(retry[1])
                if record.digest != digest or record.identity_id != actor.identity_id:
                    raise TeamError("CONFLICT")
                return record.result
            version, body = required(scope, "revision", revision_id)
            revision = Revision.model_validate_json(body)
            if version != value.expected_version:
                raise TeamError("CONFLICT")
            transitions = {
                "submit": {"DRAFT"},
                "approve": {"IN_REVIEW"},
                "reject": {"IN_REVIEW"},
                "publish": {"APPROVED"},
                "withdraw": {"DRAFT", "IN_REVIEW", "APPROVED", "PUBLISHED"},
            }
            if revision.state not in transitions[value.action]:
                raise TeamError("CONFLICT")
            if value.action in {"approve", "reject"} and revision.author == actor.identity_id:
                raise TeamError("DENIED")
            publication = self.publication(scope, revision.policy_key)
            if value.action in {"submit", "approve", "publish"}:
                if publication.generation != revision.base_generation:
                    raise TeamError("CONFLICT")
                source, locked = scope.source(revision_id)
                previous = (
                    scope.source(publication.revision_id)[0] if publication.revision_id else None
                )
                assessment = assess(source, previous)
                if assessment.model_dump_json() != locked or assessment != revision.assessment:
                    raise TeamError("POLICY_BLOCKED")
                if (
                    assessment.unsupported
                    or assessment.conformance == "FAIL"
                    or assessment.diff_status == "UNKNOWN"
                ):
                    raise TeamError("POLICY_BLOCKED")
                if value.action == "approve" and (
                    value.review_reason is None
                    or (assessment.initial and not value.acknowledge_initial)
                    or (assessment.expansions and not value.acknowledge_expansion)
                    or (
                        (assessment.gaps or assessment.conformance == "UNKNOWN")
                        and not value.acknowledge_gaps
                    )
                ):
                    raise TeamError("POLICY_BLOCKED")
            if value.action == "publish":
                reviewer = scope.get("member", revision.reviewer or "")
                if reviewer is None:
                    raise TeamError("DENIED")
                reviewed_member = Member.model_validate_json(reviewer[1])
                if (
                    not reviewed_member.enabled
                    or reviewed_member.role not in PERMISSIONS["review"]
                    or self.store.binding_by_id(reviewed_member.identity_id).kind
                    != IdentityKind.HUMAN
                    or revision.reviewer == revision.author
                ):
                    raise TeamError("DENIED")
            states = {
                "submit": "IN_REVIEW",
                "approve": "APPROVED",
                "publish": "PUBLISHED",
                "reject": "WITHDRAWN",
                "withdraw": "WITHDRAWN",
            }
            result = Revision.model_validate_json(
                revision.model_copy(
                    update={
                        "state": states[value.action],
                        "review": value if value.action == "approve" else revision.review,
                        "version": version + 1,
                        "reviewer": actor.identity_id
                        if value.action == "approve"
                        else revision.reviewer,
                    }
                ).model_dump_json()
            )
            if value.action == "publish" or (
                value.action == "withdraw" and revision.state == "PUBLISHED"
            ):
                pubrow = scope.get("publication", revision.policy_key)
                if value.action == "publish" and publication.revision_id:
                    old_version, old_body = required(scope, "revision", publication.revision_id)
                    old_revision = Revision.model_validate_json(old_body).model_copy(
                        update={"state": "SUPERSEDED", "version": old_version + 1}
                    )
                    scope.put(
                        "revision",
                        publication.revision_id,
                        old_revision.model_dump_json(),
                        old_version,
                    )
                    self.audit(scope, actor, "supersede", publication.revision_id, old_version + 1)
                scope.put(
                    "publication",
                    revision.policy_key,
                    Publication(
                        policy_key=revision.policy_key,
                        generation=publication.generation + 1,
                        revision_id=revision_id if value.action == "publish" else None,
                    ).model_dump_json(),
                    pubrow[0] if pubrow else 0,
                )
            scope.put("revision", revision_id, result.model_dump_json(), version)
            scope.put(
                "retry",
                retry_id,
                Retry(
                    request=value, identity_id=actor.identity_id, digest=digest, result=result
                ).model_dump_json(),
            )
            self.audit(scope, actor, value.action, revision_id, result.version)
            return result

    def revision(self, identity: VerifiedIdentity, org: str, key: str) -> Revision:
        with self.authorized(identity, org, "read") as (scope, _):
            return Revision.model_validate_json(required(scope, "revision", key)[1])

    def source(self, identity: VerifiedIdentity, org: str, key: str) -> str:
        with self.authorized(identity, org, "read") as (scope, _):
            required(scope, "revision", key)
            return scope.source(key)[0]

    def list_records(
        self,
        identity: VerifiedIdentity,
        org: str,
        kind: Literal["member", "agent", "reporter", "revision", "receipt"],
        offset: int = 0,
        limit: int = 100,
    ) -> Page:
        models: dict[str, type[Member | Agent | Reporter | Revision | Receipt]] = {
            "member": Member,
            "agent": Agent,
            "reporter": Reporter,
            "revision": Revision,
            "receipt": Receipt,
        }
        with self.authorized(identity, org, "read") as (scope, _):
            return Page(
                items=tuple(
                    models[kind].model_validate_json(body)
                    for _, _, body in scope.rows(kind, offset, limit)
                ),
                offset=offset,
                limit=limit,
            )

    def audit_log(
        self, identity: VerifiedIdentity, org: str, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        with self.authorized(identity, org, "read") as (scope, _):
            return scope.audit_rows(offset, limit)

    def report(self, identity: VerifiedIdentity, org: str, value: Metadata) -> Receipt:
        value = checked_model(Metadata, value)
        with self.authorized(identity, org, "report") as (scope, actor):
            reporter = Reporter.model_validate_json(
                required(scope, "reporter", actor.identity_id)[1]
            )
            agent = Agent.model_validate_json(required(scope, "agent", reporter.agent_id)[1])
            if not agent.enabled or (
                value.agent_id,
                value.environment,
                value.repository,
                value.source,
            ) != (agent.agent_id, agent.environment, agent.repository, reporter.source):
                raise TeamError("DENIED")
            now = self.clock()
            if (value.period_end - now).total_seconds() > self.config.skew_seconds or (
                now - value.period_start
            ).total_seconds() > self.config.retention_seconds:
                raise TeamError("INVALID_INPUT")
            key = content_digest((actor.identity_id, value.source, str(value.run_id)))[7:]
            digest = content_digest(value)
            existing = scope.get("tombstone", key)
            if existing:
                tombstone = Tombstone.model_validate_json(existing[1])
                if tombstone.digest != digest:
                    raise TeamError("CONFLICT")
                receipt_row = scope.get("receipt", tombstone.receipt_id)
                if receipt_row is None:
                    raise TeamError("CONFLICT")
                return Receipt.model_validate_json(receipt_row[1])
            receipt = Receipt(receipt_id="r-" + uuid4().hex, received_at=now, report=value)
            scope.put("receipt", receipt.receipt_id, receipt.model_dump_json())
            scope.put(
                "tombstone",
                key,
                Tombstone(digest=digest, receipt_id=receipt.receipt_id).model_dump_json(),
            )
            self.audit(scope, actor, "report", receipt.receipt_id, 1)
            return receipt

    def own_status(self, identity: VerifiedIdentity, org: str) -> Agent:
        with self.authorized(identity, org, "report") as (scope, actor):
            reporter = Reporter.model_validate_json(
                required(scope, "reporter", actor.identity_id)[1]
            )
            return Agent.model_validate_json(required(scope, "agent", reporter.agent_id)[1])

    def purge(self, identity: VerifiedIdentity, org: str) -> int:
        with self.authorized(identity, org, "manage") as (scope, actor):
            count = 0
            for key, _, body in scope.all_rows("receipt"):
                receipt = Receipt.model_validate_json(body)
                if (
                    self.clock() - receipt.received_at
                ).total_seconds() > self.config.retention_seconds:
                    scope.delete_receipt(key)
                    count += 1
            self.audit(scope, actor, "metadata-purge", org, count)
            return count

    def posture(self, identity: VerifiedIdentity, org: str) -> Posture:
        with self.authorized(identity, org, "read") as (scope, _):
            receipts = [
                Receipt.model_validate_json(body) for _, _, body in scope.all_rows("receipt")
            ]
            rows: list[AgentPosture] = []
            for _, _, body in scope.all_rows("agent"):
                agent = Agent.model_validate_json(body)
                reports = [r for r in receipts if r.report.agent_id == agent.agent_id]

                last = newest_report(reports)
                runtime = newest_report(reports, "RUNTIME")
                ci = newest_report(reports, "CI")
                flags: list[
                    Literal["NO_REPORT", "STALE", "GAPS", "CI_FAILURE", "INCOMPLETE", "DISABLED"]
                ] = []
                if not agent.enabled:
                    flags.append("DISABLED")
                if runtime is None or ci is None:
                    flags.append("NO_REPORT")
                for observed in (runtime, ci):
                    if observed is None:
                        continue
                    value = observed.report
                    if (
                        self.clock() - value.period_end
                    ).total_seconds() > self.config.stale_seconds:
                        flags.append("STALE")
                    if value.completeness != "REPORTED_COMPLETE":
                        flags.append("INCOMPLETE")
                if runtime is not None:
                    if runtime.report.mode in {"SHADOW", "DISABLED"}:
                        flags.append("DISABLED")
                    elif runtime.report.mode == "UNKNOWN":
                        flags.append("GAPS")
                if ci is not None:
                    if (
                        ci.report.replay == "BLOCKED"
                        or ci.report.coverage != "SYNTHETIC_PASS"
                        or ci.report.regression in {"UNKNOWN", "DRAFT"}
                        or ci.report.ci == "UNKNOWN"
                    ):
                        flags.append("GAPS")
                    if ci.report.ci in {
                        "FAIL",
                        "ERROR",
                        "INCONCLUSIVE",
                    } or ci.report.regression in {"FAIL", "ERROR"}:
                        flags.append("CI_FAILURE")
                status: Literal["UNKNOWN", "STALE", "BLOCKED", "HEALTHY_REPORTED"] = (
                    "BLOCKED"
                    if "DISABLED" in flags or "CI_FAILURE" in flags
                    else "STALE"
                    if "STALE" in flags
                    else "UNKNOWN"
                    if flags
                    else "HEALTHY_REPORTED"
                )
                rows.append(
                    AgentPosture(
                        agent_id=agent.agent_id,
                        status=status,
                        flags=tuple(dict.fromkeys(flags)),
                        last_report=last,
                        last_runtime=runtime,
                        last_ci=ci,
                    )
                )
            return Posture(org_id=org, agents=tuple(rows))
