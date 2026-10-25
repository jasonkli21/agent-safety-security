"""Real pinned JWT -> HTTP -> service -> SQLite security matrix, no external network."""

import importlib.util
import json
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest

pytest.importorskip("jwt")
pytest.importorskip("starlette")
from starlette.testclient import TestClient

from agentsec.control_plane.api import create_app
from agentsec.control_plane.auth import TeamVerifier
from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import (
    Agent,
    Binding,
    IdentityKind,
    Member,
    Metadata,
    Reporter,
    RevisionInput,
    Role,
    Transition,
)
from agentsec.control_plane.policies import verify_fetch
from agentsec.control_plane.service import TeamService
from agentsec.control_plane.store import Store

spec = importlib.util.spec_from_file_location("team_fixture", "examples/team/fixture.py")
fixture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)
NOW, CONFIG, token = fixture.NOW, fixture.CONFIG, fixture.token
SOURCE = Path("examples/mcp/contract.yaml").read_text()


@pytest.fixture
def env(tmp_path):
    service = fixture.setup(tmp_path / "team.db")
    client = TestClient(create_app(service))
    yield service, client
    try:
        service.store.close()
    except sqlite3.Error:
        pass


def call(client, who, path, body=None, org="alpha", method=None):
    headers = {"Authorization": "Bearer " + token(who)}
    if body is None:
        return client.request(method or "GET", f"/v1/orgs/{org}/{path}", headers=headers)
    if hasattr(body, "model_dump"):
        body = body.model_dump(mode="json")
    return client.request(method or "POST", f"/v1/orgs/{org}/{path}", headers=headers, json=body)


def draft(client, key="r1", who="editor", source=SOURCE, base=0):
    return call(
        client,
        who,
        "revisions",
        RevisionInput(
            revision_id=key,
            policy_key="policy",
            source=source,
            upload_source=True,
            base_generation=base,
        ),
    )


def transition(client, who, key, action, version, **kwargs):
    return call(
        client,
        who,
        f"revisions/{key}/transitions",
        Transition(action=action, expected_version=version, **kwargs),
    )


def approve(client, key="r1"):
    assert transition(client, "editor", key, "submit", 1).status_code == 200
    return transition(
        client,
        "reviewer",
        key,
        "approve",
        2,
        acknowledge_initial=True,
        acknowledge_expansion=True,
        acknowledge_gaps=True,
        review_reason="INITIAL_POLICY",
    )


def enroll(client):
    assert (
        call(
            client,
            "owner",
            "agents",
            Agent(agent_id="agent", environment="test", repository="repo", owner_id="owner"),
        ).status_code
        == 200
    )
    for name, source in (("reporter", "RUNTIME"), ("ci", "CI")):
        assert (
            call(
                client,
                "owner",
                "reporters",
                Reporter(identity_id=name, agent_id="agent", source=source),
            ).status_code
            == 200
        )


def report(**changes):
    values = dict(
        run_id=UUID(int=1),
        agent_id="agent",
        environment="test",
        repository="repo",
        source="RUNTIME",
        period_start=NOW - timedelta(seconds=5),
        period_end=NOW,
    )
    values.update(changes)
    return Metadata(**values)


@pytest.mark.parametrize(
    "path",
    [
        "members",
        "agents",
        "reporters",
        "revisions",
        "reports",
        "audit",
        "posture",
        "alerts",
        "revisions/r1",
        "revisions/r1/source",
        "agents?offset=1&limit=1",
    ],
)
def test_every_read_tenant_scoped(env, path):
    _, client = env
    assert draft(client).status_code == 200
    denied = call(client, "other", path)
    assert denied.status_code == 403
    assert "mcp-demo" not in denied.text
    assert call(client, "owner", path, org="beta").status_code == 403


@pytest.mark.parametrize(
    "path,payload",
    [
        ("members", Member(identity_id="viewer", role=Role.OWNER)),
        (
            "agents",
            Agent(agent_id="agent", environment="test", repository="repo", owner_id="other"),
        ),
        ("reporters", Reporter(identity_id="reporter", agent_id="agent", source="RUNTIME")),
        (
            "revisions",
            RevisionInput(
                revision_id="r1",
                policy_key="policy",
                source=SOURCE,
                upload_source=True,
                base_generation=0,
            ),
        ),
        ("revisions/r1/transitions", Transition(action="publish", expected_version=3)),
        ("reports", report()),
        ("metadata-purge", {"schema_version": "team-v1"}),
    ],
)
def test_every_write_tenant_scoped(env, path, payload):
    _, client = env
    assert call(client, "other", path, payload).status_code == 403


def test_multiple_memberships_explicit_org_no_union(env):
    _, client = env
    assert draft(client).status_code == 200
    assert call(client, "both", "revisions").json()["items"]
    assert call(client, "both", "revisions", org="beta").json()["items"] == []
    assert call(client, "both", "revisions/r1", org="beta").status_code == 404
    assert call(client, "both", "revisions?offset=100&limit=1").json()["items"] == []


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://evil.invalid"},
        {"aud": "other"},
        {"sub": "missing"},
        {"exp": NOW.timestamp()},
        {"nbf": NOW.timestamp() + 61},
        {"exp": "123"},
        {"nbf": True},
        {"aud": ["team-test"]},
        {"sub": "reporter"},
    ],
)
def test_bad_identity_never_authorizes(env, claims):
    _, client = env
    response = client.get(
        "/v1/orgs/alpha/posture", headers={"Authorization": "Bearer " + token("owner", **claims)}
    )
    assert response.status_code in {401, 403}
    assert "synthetic.invalid" not in response.text


@pytest.mark.parametrize(
    "headers",
    [
        {"kid": "wrong"},
        {"jku": "https://evil.invalid"},
        {"x5u": "https://evil.invalid"},
        {"crit": ["none"]},
        {"typ": "unexpected"},
    ],
)
def test_header_confusion(env, headers):
    import jwt

    _, client = env
    claims = jwt.decode(token("owner"), options={"verify_signature": False})
    encoded = jwt.encode(
        claims, fixture.TEST_KEY, algorithm="EdDSA", headers={"kid": "test", **headers}
    )
    response = client.get("/v1/orgs/alpha/posture", headers={"Authorization": "Bearer " + encoded})
    assert response.status_code == 401


@pytest.mark.parametrize("algorithm", ["none", "HS256", "EdDSA"])
def test_forgery(env, algorithm):
    import jwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _, client = env
    claims = jwt.decode(token("owner"), options={"verify_signature": False})
    key = (
        None
        if algorithm == "none"
        else "known-secret-for-symmetric-forgery-test"
        if algorithm == "HS256"
        else Ed25519PrivateKey.from_private_bytes(bytes([42]) * 32)
    )
    encoded = jwt.encode(claims, key, algorithm=algorithm, headers={"kid": "test"})
    assert (
        client.get(
            "/v1/orgs/alpha/posture", headers={"Authorization": "Bearer " + encoded}
        ).status_code
        == 401
    )


def test_missing_token_role_claim_and_membership_revocation(env):
    _, client = env
    assert client.get("/v1/orgs/alpha/posture").json()["error"] == "TOKEN_MISSING"
    assert (
        client.post(
            "/v1/orgs/alpha/members",
            headers={"Authorization": "Bearer " + token("viewer", role="OWNER")},
            json=Member(identity_id="editor", role=Role.OWNER).model_dump(mode="json"),
        ).status_code
        == 403
    )
    result = call(
        client,
        "owner",
        "members",
        Member(identity_id="viewer", role=Role.VIEWER, enabled=False, expected_version=1),
    )
    assert result.status_code == 200
    assert call(client, "viewer", "posture").status_code == 403
    assert call(client, "service", "posture").status_code == 200
    assert draft(client, who="service").status_code == 403


def test_immutable_review_publish_fetch_and_restart(env, tmp_path):
    service, client = env
    draft_response = draft(client)
    assert draft_response.status_code == 200, draft_response.text
    assessment = service.revision(
        TeamVerifier(CONFIG).verify(token("viewer"), NOW), "alpha", "r1"
    ).assessment
    assert assessment.gaps > 0
    assert approve(client).status_code == 200
    published = transition(client, "owner", "r1", "publish", 3)
    assert published.status_code == 200
    assert published.json()["state"] == "PUBLISHED"
    assert published.json()["review"]["acknowledge_gaps"] is True
    assert published.json()["review"]["review_reason"] == "INITIAL_POLICY"
    assert transition(client, "owner", "r1", "publish", 3).json() == published.json()
    assert draft(client, source=SOURCE + "\n# changed bytes").status_code == 409
    source = call(client, "viewer", "revisions/r1/source").json()["source"]
    verify_fetch(source, assessment)
    with pytest.raises(TeamError):
        verify_fetch(source.replace("decision: ALLOW", "decision: DENY"), assessment)
    with pytest.raises(sqlite3.IntegrityError):
        service.store.connection.execute("UPDATE sources SET source='changed'")
    service.store.close()
    reopened = Store(tmp_path / "team.db")
    second = TeamService(reopened, CONFIG, lambda: NOW)
    viewer = TeamVerifier(CONFIG).verify(token("viewer"), NOW)
    assert second.revision(viewer, "alpha", "r1").state == "PUBLISHED"
    assert any(row["action"] == "publish" for row in second.audit_log(viewer, "alpha"))
    reopened.close()


def test_self_review_and_exact_acknowledgement(env):
    _, client = env
    assert draft(client, who="owner").status_code == 200
    assert transition(client, "owner", "r1", "submit", 1).status_code == 200
    assert transition(client, "owner", "r1", "approve", 2).status_code == 403
    assert transition(client, "reviewer", "r1", "approve", 2).status_code == 422
    assert (
        transition(
            client,
            "reviewer",
            "r1",
            "approve",
            1,
            acknowledge_initial=True,
            acknowledge_gaps=True,
            review_reason="INITIAL_POLICY",
        ).status_code
        == 409
    )
    assert (
        transition(
            client,
            "reviewer",
            "r1",
            "approve",
            2,
            acknowledge_initial=True,
            acknowledge_gaps=True,
            review_reason="INITIAL_POLICY",
        ).status_code
        == 200
    )
    assert (
        transition(client, "reviewer", "r1", "approve", 2, acknowledge_initial=False).status_code
        == 409
    )


def test_sibling_publication_cas_race_and_rollback(env):
    service, client = env
    for key in ("r1", "r2"):
        assert draft(client, key).status_code == 200
        assert approve(client, key).status_code == 200
    identity = TeamVerifier(CONFIG).verify(token("owner"), NOW)

    def publish(key):
        try:
            return service.transition(
                identity, "alpha", key, Transition(action="publish", expected_version=3)
            ).state
        except TeamError as exc:
            return exc.code

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(publish, ("r1", "r2")))
    assert sorted(results) == ["CONFLICT", "PUBLISHED"]
    assert (
        sum(
            r[2].count('"state":"PUBLISHED"')
            for r in service.store.scoped("alpha").all_rows("revision")
        )
        == 1
    )
    assert sum(r["action"] == "publish" for r in service.audit_log(identity, "alpha")) == 1


def test_reject_new_draft_and_withdrawal_generation(env):
    _, client = env
    assert draft(client).status_code == 200
    assert transition(client, "editor", "r1", "submit", 1).status_code == 200
    assert transition(client, "reviewer", "r1", "reject", 2).json()["state"] == "WITHDRAWN"
    assert transition(client, "editor", "r1", "submit", 3).status_code == 409
    assert draft(client, "r2").status_code == 200
    assert approve(client, "r2").status_code == 200
    assert transition(client, "owner", "r2", "publish", 3).status_code == 200
    assert transition(client, "owner", "r2", "withdraw", 4).status_code == 200
    assert draft(client, "r3", base=0).status_code == 409
    assert draft(client, "r3", base=2).status_code == 200


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace('"0.1"', '"999"'),
        SOURCE + "\nextra: true\n",
        "a: &x {}\nb: *x",
        "x: 1\nx: 2",
        "!!python/object:evil {}",
    ],
)
def test_invalid_source_blocked_no_persistence(env, source):
    service, client = env
    assert draft(client, source=source).status_code == 422
    assert service.store.scoped("alpha").all_rows("revision") == []


def test_unsupported_compiler_and_intent(env):
    _, client = env
    payload = RevisionInput(
        revision_id="r1", policy_key="policy", source=SOURCE, upload_source=True, base_generation=0
    ).model_dump(mode="json")
    payload["compiler_version"] = "phase9-v1"
    assert call(client, "editor", "revisions", payload).status_code == 422
    response = draft(
        client,
        source=SOURCE.replace("max_tool_calls: 3", "max_model_calls: 1\n  max_tool_calls: 3"),
    )
    assert response.status_code == 200
    assert response.json()["assessment"]["unsupported"] > 0
    assert transition(client, "editor", "r1", "submit", 1).status_code == 422


def test_report_scope_idempotency_revocation_and_privacy(env, tmp_path):
    service, client = env
    enroll(client)
    payload = report()
    accepted = call(client, "reporter", "reports", payload)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["assurance"] == "REPORTED_UNVERIFIED"
    assert call(client, "reporter", "reports", payload).json() == accepted.json()
    assert call(client, "reporter", "reports", report(mode="SHADOW")).status_code == 409
    assert call(client, "owner", "reports", payload).status_code == 403
    assert call(client, "ci", "reports", payload).status_code == 403
    assert call(client, "reporter", "reports", report(agent_id="other-agent")).status_code == 403
    assert call(client, "reporter", "reports", report(environment="prod")).status_code == 403
    assert call(client, "reporter", "reports", report(repository="another")).status_code == 403
    assert call(client, "reporter", "own-status").status_code == 200
    assert call(client, "reporter", "posture").status_code == 403
    canary = "CANARY_SECRET_DO_NOT_STORE"
    raw = payload.model_dump(mode="json")
    raw["arguments"] = {"secret": canary}
    assert call(client, "reporter", "reports", raw).status_code == 422
    assert canary not in " ".join(service.store.connection.iterdump())
    assert token("reporter") not in " ".join(service.store.connection.iterdump())
    assert (
        call(
            client,
            "owner",
            "reporters",
            Reporter(
                identity_id="reporter",
                agent_id="agent",
                source="RUNTIME",
                enabled=False,
                expected_version=1,
            ),
        ).status_code
        == 200
    )
    assert call(client, "reporter", "reports", payload).status_code == 403


@pytest.mark.parametrize(
    "change",
    [
        {"counters": {"requested": 1, "dispatched": 2}},
        {"counters": {"requested": True}},
        {"mode": "VERIFIED"},
        {"period_end": "2026-10-24T14:00:00Z"},
        {"period_start": "2026-10-22T12:00:00Z"},
        {"run_id": "secret@example.invalid"},
        {"schema_version": "0.1"},
        {"source": "CI", "mode": "ENFORCE"},
        {"raw_events": []},
        {"agent_id": "x" * 49},
    ],
)
def test_bad_reports_rejected_before_persistence(env, change):
    service, client = env
    enroll(client)
    payload = report().model_dump(mode="json")
    payload.update(change)
    assert call(client, "reporter", "reports", payload).status_code == 422
    assert not service.store.scoped("alpha").all_rows("receipt")


def test_retention_tombstone_and_tenant_purge(env):
    service, client = env
    enroll(client)
    assert call(client, "reporter", "reports", report()).status_code == 200
    assert (
        call(
            client,
            "other",
            "agents",
            Agent(agent_id="agent", environment="test", repository="repo", owner_id="other"),
            org="beta",
        ).status_code
        == 200
    )
    assert (
        call(
            client,
            "other",
            "reporters",
            Reporter(identity_id="beta-reporter", agent_id="agent", source="RUNTIME"),
            org="beta",
        ).status_code
        == 200
    )
    assert call(client, "beta-reporter", "reports", report(), org="beta").status_code == 200
    service.clock = lambda: NOW + timedelta(days=31)
    # fresh tokens are required after clock advances, service tests use verified current context.
    from agentsec.control_plane.auth import VerifiedIdentity

    identity = VerifiedIdentity(CONFIG.issuers[0].issuer, "owner", service.clock().timestamp() + 10)
    assert service.purge(identity, "alpha") == 1
    assert len(service.store.scoped("alpha").all_rows("tombstone")) == 1
    assert len(service.store.scoped("beta").all_rows("receipt")) == 1
    service.clock = lambda: NOW
    assert call(client, "reporter", "reports", report()).status_code == 409


def test_posture_unknown_shadow_draft_stale(env):
    service, client = env
    enroll(client)
    assert call(client, "viewer", "posture").json()["agents"][0]["status"] == "UNKNOWN"
    assert call(client, "reporter", "reports", report(mode="SHADOW")).status_code == 200
    assert call(client, "viewer", "posture").json()["agents"][0]["status"] == "BLOCKED"
    assert (
        call(
            client,
            "ci",
            "reports",
            report(run_id=UUID(int=2), source="CI", ci="PASS", regression="DRAFT"),
        ).status_code
        == 200
    )
    row = call(client, "viewer", "posture").json()["agents"][0]
    assert row["status"] != "HEALTHY_REPORTED"
    assert row["last_ci"]["report"]["regression"] == "DRAFT"
    service.clock = lambda: NOW + timedelta(seconds=4000)
    assert call(client, "viewer", "posture").json()["agents"][0]["status"] in {"STALE", "BLOCKED"}


def test_safe_http_errors_and_store_outage(env):
    service, client = env
    assert call(client, "viewer", "agents?limit=101").status_code == 422
    assert call(client, "viewer", "agents?offset=-1").status_code == 422
    assert call(client, "viewer", "agents?limit=1&limit=2").status_code == 422
    headers = {"Authorization": "Bearer " + token("owner"), "Content-Type": "application/json"}
    assert (
        client.post(
            "/v1/orgs/alpha/members",
            headers=headers,
            content='{"identity_id":"a","identity_id":"b"}',
        ).status_code
        == 422
    )
    assert (
        client.post("/v1/orgs/alpha/members", headers=headers, content="x" * 131073).status_code
        == 413
    )
    assert (
        client.post(
            "/v1/orgs/alpha/members",
            headers={"Authorization": headers["Authorization"]},
            content="x",
        ).status_code
        == 415
    )
    service.store.close()
    assert call(client, "viewer", "posture").json() == {
        "schema_version": "team-v1",
        "error": "STORE_UNAVAILABLE",
    }


def test_duplicate_bindings_migrations_corruption_and_rollback(tmp_path):
    service = fixture.setup(tmp_path / "team.db")
    with pytest.raises(TeamError, match="CONFLICT"):
        service.store.provision(
            Binding(
                identity_id="new",
                issuer=CONFIG.issuers[0].issuer,
                subject="owner",
                kind=IdentityKind.HUMAN,
            )
        )
    before = service.store.scoped("alpha").all_rows("agent")
    with pytest.raises(RuntimeError), service.store.transaction():
        service.store.scoped("alpha").put("agent", "broken", "{}")
        raise RuntimeError
    assert service.store.scoped("alpha").all_rows("agent") == before
    service.store.connection.execute("PRAGMA user_version=9")
    service.store.close()
    with pytest.raises(TeamError, match="STORE_UNAVAILABLE"):
        Store(tmp_path / "team.db")
    (tmp_path / "bad.db").write_text("corrupt")
    with pytest.raises(TeamError, match="STORE_UNAVAILABLE"):
        Store(tmp_path / "bad.db")


def test_outage_local_runtime_and_graph_stay_offline(env, monkeypatch):
    import runpy
    import socket

    service, _ = env
    service.store.close()

    def deny_network(*args, **kwargs):
        raise AssertionError("unexpected network")

    monkeypatch.setattr(socket, "create_connection", deny_network)
    # Real existing three-agent RuntimeGateway example executes after the team store is gone.
    runpy.run_path("examples/multi_agent/local_session.py", run_name="__main__")


def test_revoked_reviewer_cannot_leave_publishable_vote(env):
    _, client = env
    assert draft(client).status_code == 200
    assert approve(client).status_code == 200
    assert (
        call(
            client,
            "owner",
            "members",
            Member(identity_id="reviewer", role=Role.REVIEWER, enabled=False, expected_version=1),
        ).status_code
        == 200
    )
    assert transition(client, "owner", "r1", "publish", 3).status_code == 403
    assert call(client, "viewer", "revisions/r1").json()["state"] == "APPROVED"


def test_expansion_requires_fielded_acknowledgement_and_supersedes(env):
    _, client = env
    assert draft(client).status_code == 200
    assert approve(client).status_code == 200
    assert transition(client, "owner", "r1", "publish", 3).status_code == 200
    assert (
        draft(
            client, "r2", source=SOURCE.replace("decision: DENY", "decision: ALLOW"), base=1
        ).status_code
        == 200
    )
    assert transition(client, "editor", "r2", "submit", 1).status_code == 200
    assert (
        transition(
            client,
            "reviewer",
            "r2",
            "approve",
            2,
            acknowledge_gaps=True,
            review_reason="REVIEWED_CHANGE",
        ).status_code
        == 422
    )
    assert (
        transition(
            client,
            "reviewer",
            "r2",
            "approve",
            2,
            acknowledge_expansion=True,
            acknowledge_gaps=True,
            review_reason="REVIEWED_CHANGE",
        ).status_code
        == 200
    )
    assert transition(client, "owner", "r2", "publish", 3).status_code == 200
    assert call(client, "viewer", "revisions/r1").json()["state"] == "SUPERSEDED"


def test_concurrent_report_retries_one_receipt(env):
    service, client = env
    enroll(client)
    identity = TeamVerifier(CONFIG).verify(token("reporter"), NOW)
    with ThreadPoolExecutor(4) as pool:
        results = list(
            pool.map(lambda _: service.report(identity, "alpha", report()).receipt_id, range(4))
        )
    assert len(set(results)) == 1
    assert len(service.store.scoped("alpha").all_rows("receipt")) == 1


def test_reporter_cannot_rebind_or_cross_tenant_enroll(env):
    _, client = env
    enroll(client)
    assert (
        call(
            client,
            "other",
            "agents",
            Agent(agent_id="agent", environment="test", repository="repo", owner_id="other"),
            org="beta",
        ).status_code
        == 200
    )
    assert (
        call(
            client,
            "other",
            "reporters",
            Reporter(identity_id="reporter", agent_id="agent", source="RUNTIME"),
            org="beta",
        ).status_code
        == 403
    )
    assert (
        call(
            client,
            "owner",
            "reporters",
            Reporter(identity_id="reporter", agent_id="agent", source="CI", expected_version=1),
        ).status_code
        == 409
    )
    assert (
        call(
            client,
            "owner",
            "agents",
            Agent(
                agent_id="agent",
                environment="prod",
                repository="repo",
                owner_id="owner",
                expected_version=1,
            ),
        ).status_code
        == 409
    )


def test_duplicate_signed_claims_and_missing_nbf(env):
    import base64

    import jwt

    _, client = env
    claims = jwt.decode(token("owner"), options={"verify_signature": False})
    del claims["nbf"]
    encoded = jwt.encode(claims, fixture.TEST_KEY, algorithm="EdDSA", headers={"kid": "test"})
    assert (
        client.get(
            "/v1/orgs/alpha/posture", headers={"Authorization": "Bearer " + encoded}
        ).status_code
        == 401
    )

    def b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=")

    header = b64(b'{"alg":"EdDSA","kid":"test"}')
    payload = b64(
        json.dumps({**claims, "nbf": NOW.timestamp() - 1}).encode()[:-1] + b',"sub":"viewer"}'
    )
    message = header + b"." + payload
    signed = (message + b"." + b64(fixture.TEST_KEY.sign(message))).decode()
    assert (
        client.get(
            "/v1/orgs/alpha/posture", headers={"Authorization": "Bearer " + signed}
        ).status_code
        == 401
    )


def test_transaction_failure_after_publish_rolls_back_all_records(env, monkeypatch):
    from agentsec.control_plane.store import ScopedStore

    service, client = env
    assert draft(client).status_code == 200
    assert approve(client).status_code == 200
    original = ScopedStore.audit

    def fail_publish(self, actor, action, target, version, at):
        if action == "publish":
            raise sqlite3.OperationalError("synthetic store failure")
        original(self, actor, action, target, version, at)

    monkeypatch.setattr(ScopedStore, "audit", fail_publish)
    assert transition(client, "owner", "r1", "publish", 3).status_code == 503
    assert service.store.scoped("alpha").get("publication", "policy") is None
    assert call(client, "viewer", "revisions/r1").json()["state"] == "APPROVED"
    monkeypatch.setattr(ScopedStore, "audit", original)
    assert transition(client, "owner", "r1", "publish", 3).status_code == 200


def test_config_rejects_private_and_wrong_key_types():
    from cryptography.hazmat.primitives import serialization

    from agentsec.control_plane.models import Issuer, Key, TeamConfig

    private = fixture.TEST_KEY.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    with pytest.raises(TeamError, match="INVALID_INPUT"):
        TeamVerifier(
            TeamConfig(
                issuers=(
                    Issuer(
                        issuer="issuer",
                        audience="audience",
                        keys=(Key(kid="test", public_key_pem=private),),
                    ),
                )
            )
        )


def test_unknown_hash_upload_opt_in_and_oversized_source(env):
    _, client = env
    payload = RevisionInput(
        revision_id="r1", policy_key="policy", source=SOURCE, upload_source=True, base_generation=0
    ).model_dump(mode="json")
    payload["document_hash"] = "sha256:" + "0" * 64
    assert call(client, "editor", "revisions", payload).status_code == 422
    del payload["document_hash"]
    payload["upload_source"] = False
    assert call(client, "editor", "revisions", payload).status_code == 422
    payload["upload_source"] = 1
    assert call(client, "editor", "revisions", payload).status_code == 422
    payload["upload_source"] = True
    payload["source"] = "a" * 65537
    assert call(client, "editor", "revisions", payload).status_code == 422


def test_publication_cas_across_two_connections(env, tmp_path):
    service, client = env
    for key in ("r1", "r2"):
        assert draft(client, key).status_code == 200
        assert approve(client, key).status_code == 200
    second_store = Store(tmp_path / "team.db")
    second = TeamService(second_store, CONFIG, lambda: NOW)
    identity = TeamVerifier(CONFIG).verify(token("owner"), NOW)

    def publish(pair):
        current, key = pair
        try:
            current.transition(
                identity, "alpha", key, Transition(action="publish", expected_version=3)
            )
            return "PUBLISHED"
        except TeamError as exc:
            return exc.code

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(publish, ((service, "r1"), (second, "r2")))) == [
            "CONFLICT",
            "PUBLISHED",
        ]
    second_store.close()


def test_audit_sequence_does_not_disclose_other_tenant_volume(env):
    _, client = env
    before = call(client, "viewer", "audit").json()
    assert (
        call(
            client, "other", "members", Member(identity_id="viewer", role=Role.VIEWER), org="beta"
        ).status_code
        == 200
    )
    assert call(client, "viewer", "audit").json() == before
    assert draft(client).status_code == 200
    after = call(client, "viewer", "audit").json()
    assert [row["sequence"] for row in after] == list(range(1, len(after) + 1))


def test_same_revision_id_is_independent_in_each_tenant(env):
    _, client = env
    assert draft(client).status_code == 200
    beta_source = SOURCE.replace("Synthetic protected tools", "Beta private description")
    beta = call(
        client,
        "beta-editor",
        "revisions",
        RevisionInput(
            revision_id="r1",
            policy_key="policy",
            source=beta_source,
            upload_source=True,
            base_generation=0,
        ),
        org="beta",
    )
    assert beta.status_code == 200
    for who, action, version in (
        ("beta-editor", "submit", 1),
        ("beta-reviewer", "approve", 2),
        ("other", "publish", 3),
    ):
        assert (
            call(
                client,
                who,
                "revisions/r1/transitions",
                Transition(
                    action=action,
                    expected_version=version,
                    acknowledge_initial=True,
                    acknowledge_gaps=True,
                    review_reason="INITIAL_POLICY",
                ),
                org="beta",
            ).status_code
            == 200
        )
    assert call(client, "both", "revisions/r1").json()["state"] == "DRAFT"
    assert call(client, "both", "revisions/r1", org="beta").json()["state"] == "PUBLISHED"
    assert "Beta private" not in call(client, "both", "revisions/r1/source").text
    assert "Beta private" in call(client, "both", "revisions/r1/source", org="beta").text
