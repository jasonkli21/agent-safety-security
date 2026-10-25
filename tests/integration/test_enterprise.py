"""Real tenant transactions, pinned signatures, privacy and concurrency negatives."""

import importlib.util
import json
import os
import sqlite3
import sys
from datetime import timedelta
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("jwt")
pytest.importorskip("starlette")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient

from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import parse_document, validate_data
from agentsec.control_plane.api import create_app
from agentsec.control_plane.auth import TeamVerifier
from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import Agent, Member, RevisionInput, Role, Transition
from agentsec.control_plane.policies import assess
from agentsec.control_plane.store import Store
from agentsec.enterprise.exports import jsonl_bytes, sign_export, verify_export, write_export
from agentsec.enterprise.files import atomic_private_write, backup_database
from agentsec.enterprise.models import (
    CaseInput,
    CaseTransition,
    ExportCursor,
    ExportManifest,
    FederatedPolicyBundle,
    FederationPayload,
    ImportRequest,
    Pin,
    RiskInput,
    RiskTransition,
    SignedExport,
    SimulationInput,
    TrustConfig,
)
from agentsec.enterprise.service import EnterpriseService
from agentsec.enterprise.signatures import sign, signing_bytes, verify

spec = importlib.util.spec_from_file_location("enterprise_fixture", "examples/team/fixture.py")
fixture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)
NOW = fixture.NOW
SOURCE = Path("examples/mcp/contract.yaml").read_text()
KEY = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
PUBLIC = (
    KEY.public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)


def identity(name):
    return TeamVerifier(fixture.CONFIG).verify(fixture.token(name), NOW)


def pin(purpose="federation", **changes):
    values = dict(
        origin="alpha",
        target="beta",
        policy_key="policy",
        local_policy_key="policy",
        key_id="peer",
        purpose=purpose,
        public_key_pem=PUBLIC,
        not_before=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=90),
    )
    values.update(changes)
    return Pin(**values)


@pytest.fixture
def env(tmp_path):
    tmp_path.chmod(0o700)
    team = fixture.setup(tmp_path / "team.db")
    key = tmp_path / "key.pem"
    key.write_bytes(
        KEY.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key.chmod(0o600)
    service = EnterpriseService(team, TrustConfig(pins=(pin(),)))
    yield service, key
    team.store.close()


def bundle(key, **changes):
    a = assess(SOURCE, None)
    values = dict(
        origin="alpha",
        target="beta",
        policy_key="policy",
        local_policy_key="policy",
        revision_id="origin",
        key_id="peer",
        sequence=1,
        issued_at=NOW,
        expires_at=NOW + timedelta(days=1),
        source=SOURCE,
        document_hash=a.document_hash,
        effective_policy_hash=a.effective_policy_hash,
        compiled_plan_digest=a.compiled_plan_digest,
    )
    values.update(changes)
    payload = FederationPayload(**values)
    return FederatedPolicyBundle(payload=payload, signature=sign(payload, key))


def draft(service, key="candidate", base=0, source=SOURCE):
    return service.team.create_revision(
        identity("editor"),
        "alpha",
        RevisionInput(
            revision_id=key,
            policy_key="policy",
            source=source,
            upload_source=True,
            base_generation=base,
        ),
    )


def publish(service, key="candidate"):
    team = service.team
    team.transition(
        identity("editor"), "alpha", key, Transition(action="submit", expected_version=1)
    )
    team.transition(
        identity("reviewer"),
        "alpha",
        key,
        Transition(
            action="approve",
            expected_version=2,
            acknowledge_initial=True,
            acknowledge_expansion=True,
            acknowledge_gaps=True,
            review_reason="INITIAL_POLICY",
        ),
    )
    return team.transition(
        identity("owner"), "alpha", key, Transition(action="publish", expected_version=3)
    )


def open_case(service, who="editor", severity="HIGH", key="case"):
    return service.open_case(
        identity(who),
        "alpha",
        CaseInput(case_id=key, category="POLICY", severity=severity, assignee="editor"),
    )


def request_risk(service, who="editor", key="risk"):
    return service.request_risk(
        identity(who),
        "alpha",
        RiskInput(
            risk_id=key,
            target_kind="case",
            target_id="case",
            target_version=1,
            reason="TIME_BOUND_REMEDIATION",
            expires_at=NOW + timedelta(hours=1),
        ),
    )


def test_federation_draft_retry_rotation_and_review(env):
    service, key = env
    b = bundle(key)
    request = ImportRequest(bundle=b, local_revision_id="imported", base_generation=0)
    result = service.import_bundle(identity("beta-editor"), "beta", request)
    assert result.state == "DRAFT" and result.author == "beta-editor"
    assert service.import_bundle(identity("beta-editor"), "beta", request) == result
    with pytest.raises(TeamError, match="DENIED"):
        service.import_bundle(identity("viewer"), "alpha", request)
    # New key must not reset peer/policy high water.
    service.trust = TrustConfig(pins=(pin(key_id="rotated"),))
    rotated = bundle(key, key_id="rotated")
    with pytest.raises(TeamError, match="CONFLICT"):
        service.import_bundle(
            identity("beta-editor"),
            "beta",
            ImportRequest(bundle=rotated, local_revision_id="other-import", base_generation=0),
        )
    service.trust = TrustConfig(pins=(pin(),))
    newer = ImportRequest(
        bundle=bundle(key, sequence=2), local_revision_id="newer", base_generation=0
    )
    service.import_bundle(identity("beta-editor"), "beta", newer)
    with pytest.raises(TeamError, match="CONFLICT"):
        service.import_bundle(identity("beta-editor"), "beta", request)
    team = service.team
    team.transition(
        identity("beta-editor"), "beta", "imported", Transition(action="submit", expected_version=1)
    )
    # Origin signature grants no recipient review privilege.
    with pytest.raises(TeamError, match="DENIED"):
        team.transition(
            identity("beta-editor"),
            "beta",
            "imported",
            Transition(action="approve", expected_version=2),
        )
    assert team.publication(team.store.scoped("beta"), "policy").generation == 0


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"origin": "gamma"}, "TRUST_UNAVAILABLE"),
        ({"target": "gamma"}, "DENIED"),
        ({"policy_key": "other"}, "TRUST_UNAVAILABLE"),
        ({"local_policy_key": "other"}, "TRUST_UNAVAILABLE"),
        ({"key_id": "unknown"}, "TRUST_UNAVAILABLE"),
        ({"issued_at": NOW + timedelta(seconds=1)}, "SIGNATURE_INVALID"),
        ({"issued_at": NOW - timedelta(days=2), "expires_at": NOW}, "SIGNATURE_INVALID"),
        ({"compiled_plan_digest": "sha256:" + "0" * 64}, "POLICY_BLOCKED"),
    ],
)
def test_federation_scope_time_and_identity_fail_closed(env, changes, code):
    service, key = env
    with pytest.raises(TeamError, match=code):
        service.import_bundle(
            identity("beta-editor"),
            "beta",
            ImportRequest(
                bundle=bundle(key, **changes), local_revision_id="imported", base_generation=0
            ),
        )
    assert not service.team.store.scoped("beta").all_rows("revision")


def test_federation_tamper_before_parse_and_revoked_pin(env, monkeypatch):
    service, key = env
    original = bundle(key)
    tampered = original.model_copy(
        update={"payload": original.payload.model_copy(update={"source": "secret"})}
    )
    monkeypatch.setattr(
        "agentsec.enterprise.service.assess", lambda *args: pytest.fail("parsed before signature")
    )
    with pytest.raises(TeamError, match="SIGNATURE_INVALID"):
        service.import_bundle(
            identity("beta-editor"),
            "beta",
            ImportRequest(bundle=tampered, local_revision_id="imported", base_generation=0),
        )
    service.trust = TrustConfig(pins=(pin(enabled=False),))
    with pytest.raises(TeamError, match="TRUST_UNAVAILABLE"):
        verify(original.payload, original.signature, service.trust, NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("algorithm", "HS256"),
        ("purpose", "export"),
        ("compiler_version", "phase9-v1"),
        ("schema_version", "enterprise-v2"),
        ("sequence", True),
        ("sequence", "1"),
        ("issued_at", "2026-10-24T12:00:00"),
        ("issued_at", "2026-10-24T13:00:00+01:00"),
        ("document_hash", "invalid"),
        ("unknown", "secret"),
    ],
)
def test_federation_strict_wire(env, field, value):
    _, key = env
    data = bundle(key).payload.model_dump(mode="json")
    data[field] = value
    with pytest.raises(ArtifactValidationError):
        validate_data(FederationPayload, data)


def test_duplicate_json_and_duplicate_pins(env):
    with pytest.raises(ArtifactValidationError):
        parse_document(
            '{"schema_version":"enterprise-v1","schema_version":"enterprise-v1"}', format="json"
        )
    with pytest.raises(ValueError):
        TrustConfig(pins=(pin(), pin()))


def test_case_lifecycle_cas_retry_independent_severe_closure(env):
    service, _ = env
    open_case(service, "owner")
    for action, who, version in [
        ("triage", "editor", 1),
        ("mitigate", "editor", 2),
        ("resolve", "reviewer", 3),
    ]:
        transition = CaseTransition(
            action=action,
            expected_version=version,
            resolution="MITIGATED" if action == "resolve" else None,
        )
        result = service.transition_case(identity(who), "alpha", "case", transition)
        assert service.transition_case(identity(who), "alpha", "case", transition) == result
    with pytest.raises(TeamError, match="DENIED"):
        service.transition_case(
            identity("owner"), "alpha", "case", CaseTransition(action="close", expected_version=4)
        )
    assert service.case(identity("viewer"), "alpha", "case").state == "RESOLVED"
    with pytest.raises(TeamError, match="CONFLICT"):
        service.transition_case(
            identity("editor"),
            "alpha",
            "case",
            CaseTransition(action="mitigate", expected_version=1),
        )
    service.team.member(identity("owner"), "alpha", Member(identity_id="other", role=Role.OWNER))
    assert (
        service.transition_case(
            identity("other"), "alpha", "case", CaseTransition(action="close", expected_version=4)
        ).state
        == "CLOSED"
    )
    assert (
        service.transition_case(
            identity("other"), "alpha", "case", CaseTransition(action="reopen", expected_version=5)
        ).state
        == "OPEN"
    )


def test_case_audit_failure_rolls_back(env, monkeypatch):
    service, _ = env
    open_case(service)

    def fail(*args):
        raise RuntimeError("injected")

    monkeypatch.setattr(service.team, "audit", fail)
    with pytest.raises(RuntimeError):
        service.transition_case(
            identity("editor"), "alpha", "case", CaseTransition(action="triage", expected_version=1)
        )
    assert service.case(identity("viewer"), "alpha", "case").version == 1
    assert service.team.store.scoped("alpha").all_rows("enterprise_retry") == []


def test_risk_independence_exact_expiry_stale_and_revocation(env):
    service, _ = env
    open_case(service)
    request_risk(service, "owner")
    with pytest.raises(TeamError, match="DENIED"):
        service.transition_risk(
            identity("owner"), "alpha", "risk", RiskTransition(action="approve", expected_version=1)
        )
    request_risk(service, key="independent")
    transition = RiskTransition(action="approve", expected_version=1)
    approved = service.transition_risk(identity("owner"), "alpha", "independent", transition)
    assert (
        service.transition_risk(identity("owner"), "alpha", "independent", transition) == approved
    )
    assert service.risk(identity("viewer"), "alpha", "independent").disposition == "ACTIVE"
    before = service.team.posture(identity("viewer"), "alpha")
    assert before == service.team.posture(identity("viewer"), "alpha")
    service.team.clock = lambda: NOW + timedelta(hours=1)
    assert service.risk(identity("viewer"), "alpha", "independent").disposition == "EXPIRED"
    service.team.clock = lambda: NOW
    service.transition_case(
        identity("editor"), "alpha", "case", CaseTransition(action="triage", expected_version=1)
    )
    assert service.risk(identity("viewer"), "alpha", "independent").disposition == "STALE"
    assert (
        service.transition_risk(
            identity("owner"),
            "alpha",
            "independent",
            RiskTransition(action="revoke", expected_version=2),
        ).state
        == "REVOKED"
    )


@pytest.mark.parametrize("days", [0, 31])
def test_risk_expiry_bounds(env, days):
    service, _ = env
    open_case(service)
    with pytest.raises(TeamError, match="INVALID_INPUT"):
        service.request_risk(
            identity("editor"),
            "alpha",
            RiskInput(
                risk_id="risk",
                target_kind="case",
                target_id="case",
                target_version=1,
                reason="BUSINESS_CONTINUITY",
                expires_at=NOW + timedelta(days=days),
            ),
        )


@pytest.mark.parametrize("who", ["viewer", "service", "reporter", "beta-editor", "reviewer"])
def test_enterprise_mutation_role_and_tenant_denial(env, who):
    service, _ = env
    with pytest.raises(TeamError, match="DENIED"):
        open_case(service, who)
    with pytest.raises(TeamError, match="DENIED"):
        service.export_page(identity(who), "alpha", ExportCursor(org="alpha"))


def test_revoked_role_on_exact_retry_and_assignee(env):
    service, _ = env
    open_case(service)
    transition = CaseTransition(action="triage", expected_version=1)
    service.transition_case(identity("editor"), "alpha", "case", transition)
    service.team.member(
        identity("owner"),
        "alpha",
        Member(identity_id="editor", role=Role.EDITOR, enabled=False, expected_version=1),
    )
    with pytest.raises(TeamError, match="DENIED"):
        service.transition_case(identity("editor"), "alpha", "case", transition)
    with pytest.raises(TeamError, match="DENIED"):
        service.transition_case(
            identity("owner"),
            "alpha",
            "case",
            CaseTransition(action="mitigate", expected_version=2),
        )


def enroll(service, key="agent", revision=None, plan=None, enabled=True):
    return service.team.agent(
        identity("owner"),
        "alpha",
        Agent(
            agent_id=key,
            environment="test",
            repository="repo",
            owner_id="owner",
            policy_revision=revision,
            expected_plan=plan,
            enabled=enabled,
        ),
    )


def test_simulation_missing_baseline_then_finite_and_unknown(env):
    service, _ = env
    revision = draft(service)
    enroll(service)
    value = SimulationInput(candidate="candidate", expected_generation=0, agents=("agent",))
    result = service.simulate(identity("editor"), "alpha", value)
    assert result.category == "UNCLASSIFIED" and result.agents[0].status == "UNKNOWN"
    published = publish(service)
    draft(service, "next", base=1)
    enroll(service, "aligned", "candidate", published.assessment.compiled_plan_digest)
    enroll(service, "disabled", enabled=False)
    result = service.simulate(
        identity("editor"),
        "alpha",
        SimulationInput(
            candidate="next", expected_generation=1, agents=("aligned", "agent", "disabled")
        ),
    )
    assert [r.status for r in result.agents] == ["COMPARED", "UNKNOWN", "INELIGIBLE"]
    assert result.category == "UNCHANGED"
    assert result.assessment.compiled_plan_digest == revision.assessment.compiled_plan_digest


@pytest.mark.parametrize("mutation", ["role", "inventory", "publication"])
def test_simulation_snapshot_race_and_outside_lock(env, monkeypatch, mutation):
    service, _ = env
    draft(service)
    enroll(service)
    original = assess

    def staged(*args):
        assert not service.team.store.connection.in_transaction
        if mutation == "role":
            service.team.member(
                identity("owner"),
                "alpha",
                Member(identity_id="editor", role=Role.EDITOR, enabled=False, expected_version=1),
            )
        elif mutation == "inventory":
            service.team.agent(
                identity("owner"),
                "alpha",
                Agent(
                    agent_id="agent",
                    environment="test",
                    repository="repo",
                    owner_id="owner",
                    enabled=False,
                    expected_version=1,
                ),
            )
        else:
            with service.team.store.transaction():
                from agentsec.control_plane.models import Publication

                service.team.store.scoped("alpha").put(
                    "publication",
                    "policy",
                    Publication(policy_key="policy", generation=1).model_dump_json(),
                )
        return original(*args)

    monkeypatch.setattr("agentsec.enterprise.service.assess", staged)
    with pytest.raises(TeamError, match="DENIED" if mutation == "role" else "CONFLICT"):
        service.simulate(
            identity("editor"),
            "alpha",
            SimulationInput(candidate="candidate", expected_generation=0, agents=("agent",)),
        )


def test_simulation_bad_cohort_and_cross_tenant(env):
    service, _ = env
    draft(service)
    with pytest.raises(ValueError):
        SimulationInput(candidate="candidate", expected_generation=0, agents=("same", "same"))
    with pytest.raises(ValueError):
        SimulationInput(
            candidate="candidate", expected_generation=0, agents=tuple(f"a{i}" for i in range(101))
        )
    with pytest.raises(TeamError, match="NOT_FOUND"):
        service.simulate(
            identity("editor"),
            "alpha",
            SimulationInput(candidate="candidate", expected_generation=0, agents=("foreign",)),
        )


def test_export_scope_privacy_and_exact_byte_signature(env, tmp_path):
    service, key = env
    # Policy-source canary never enters audit/export.
    draft(service, source=SOURCE + "\n# secret-source-canary\n")
    open_case(service)
    request_risk(service)
    service.transition_risk(
        identity("owner"), "alpha", "risk", RiskTransition(action="approve", expected_version=1)
    )
    page = service.export_page(identity("owner"), "alpha", ExportCursor(org="alpha"))
    data, manifest = sign_export(page, "exporter", key, NOW)
    trust = TrustConfig(
        pins=(
            pin(
                "export",
                target="alpha",
                policy_key="siem",
                local_policy_key="siem",
                key_id="exporter",
            ),
        )
    )
    verify_export(data, manifest, trust, NOW)
    assert (
        b"secret-source-canary" not in data and b"source" not in data and b"beta-editor" not in data
    )
    assert data == jsonl_bytes(
        service.export_page(identity("owner"), "alpha", ExportCursor(org="alpha"))
    )
    for tampered in (
        data[:-1],
        data + b"\n",
        b"\n".join(reversed(data.splitlines())) + b"\n",
        data.replace(b"bootstrap", b"bootstrax"),
    ):
        with pytest.raises(TeamError, match="SIGNATURE_INVALID"):
            verify_export(tampered, manifest, trust, NOW)
    with pytest.raises(TeamError, match="DENIED"):
        service.export_page(identity("owner"), "alpha", ExportCursor(org="beta"))
    with pytest.raises(TeamError, match="CONFLICT"):
        service.export_page(
            identity("owner"), "alpha", ExportCursor(org="alpha", after=page.high_water + 1)
        )
    assert not service.export_page(identity("owner"), "alpha", page.cursor).records
    write_export(tmp_path / "out.jsonl", tmp_path / "manifest.json", data, manifest)
    assert (tmp_path / "out.jsonl").stat().st_mode & 0o777 == 0o600
    with pytest.raises(TeamError):
        write_export(tmp_path / "out.jsonl", tmp_path / "manifest.json", data, manifest)


def test_signature_domain_separation_and_pinned_key(env):
    _, key = env
    b = bundle(key)
    with pytest.raises(TeamError, match="TRUST_UNAVAILABLE"):
        verify(b.payload, b.signature, TrustConfig(pins=(pin("export"),)), NOW)
    wrong = (
        Ed25519PrivateKey.from_private_bytes(bytes(32))
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with pytest.raises(TeamError, match="SIGNATURE_INVALID"):
        verify(b.payload, b.signature, TrustConfig(pins=(pin(public_key_pem=wrong),)), NOW)


def test_protected_key_and_interrupted_export(env, tmp_path, monkeypatch):
    _, key = env
    payload = bundle(key).payload
    key.chmod(0o644)
    with pytest.raises(TeamError, match="TRUST_UNAVAILABLE"):
        sign(payload, key)
    key.chmod(0o600)
    link = tmp_path / "key-link"
    link.symlink_to(key)
    with pytest.raises(TeamError, match="TRUST_UNAVAILABLE"):
        sign(payload, link)
    output = tmp_path / "out"

    def fail(*args):
        raise OSError("injected")

    monkeypatch.setattr(os, "link", fail)
    with pytest.raises(TeamError):
        atomic_private_write(output, b"safe")
    assert not output.exists() and not list(tmp_path.glob(".agentsec-*"))


def test_backup_restore_retains_enterprise_and_unsafe_wal(env, tmp_path):
    service, _ = env
    open_case(service)
    destination = tmp_path / "backup.db"
    backup_database(tmp_path / "team.db", destination)
    restored = Store(destination)
    assert restored.connection.execute("PRAGMA user_version").fetchone()[0] == 1
    assert restored.scoped("alpha").get("case", "case")
    restored.close()
    with pytest.raises(TeamError):
        backup_database(tmp_path / "team.db", destination)
    wal = Path(str(destination) + "-wal")
    wal.symlink_to(tmp_path / "key.pem")
    with pytest.raises(TeamError, match="STORE_UNAVAILABLE"):
        Store(destination)


def test_enterprise_api_strict_input_and_roles(env):
    service, _ = env
    client = TestClient(create_app(service.team))
    data = CaseInput(
        case_id="case", category="POLICY", severity="HIGH", assignee="editor"
    ).model_dump(mode="json")

    def post(who, data, org="alpha"):
        return client.post(
            f"/v1/orgs/{org}/enterprise/cases",
            json=data,
            headers={"Authorization": "Bearer " + fixture.token(who)},
        )

    assert post("editor", data).status_code == 200
    assert post("viewer", data).status_code == 403
    assert post("beta-editor", data).status_code == 403
    assert post("editor", {**data, "notes": "secret-canary"}).status_code == 422
    response = client.get(
        "/v1/orgs/beta/enterprise/cases/case",
        headers={"Authorization": "Bearer " + fixture.token("beta-editor")},
    )
    assert response.status_code == 404
    duplicate = client.post(
        "/v1/orgs/alpha/enterprise/cases",
        content='{"case_id":"a","case_id":"b"}',
        headers={
            "Authorization": "Bearer " + fixture.token("editor"),
            "Content-Type": "application/json",
        },
    )
    assert duplicate.status_code == 422 and "secret-canary" not in duplicate.text


def test_fixed_canonical_export_vector(env):
    _, key = env
    payload = ExportManifest(
        origin="alpha",
        target="alpha",
        key_id="exporter",
        issued_at=NOW,
        start_after=0,
        end=0,
        high_water=0,
        count=0,
        byte_length=0,
        file_digest="sha256:" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    vector = json.loads(Path("tests/fixtures/enterprise-signature-vector.json").read_text())
    assert signing_bytes(payload).decode() == vector["bytes"]
    assert sign(payload, key) == vector["signature"]
    KEY.public_key().verify(bytes.fromhex(vector["signature"]), vector["bytes"].encode())


def test_risk_does_not_suppress_runtime_deny_or_ci_failure(env):
    from uuid import UUID

    from agentsec.compiler import compile_contract
    from agentsec.compiler.probes import synthetic_authority
    from agentsec.contracts.loader import load_contract
    from agentsec.control_plane.models import Metadata, Reporter
    from agentsec.domain.policy import PolicyRequest
    from agentsec.policy.native import NativePolicyEngine

    service, _ = env
    open_case(service)
    enroll(service)
    service.team.reporter(
        identity("owner"), "alpha", Reporter(identity_id="ci", agent_id="agent", source="CI")
    )
    service.team.report(
        identity("ci"),
        "alpha",
        Metadata(
            run_id=UUID(int=1),
            agent_id="agent",
            environment="test",
            repository="repo",
            source="CI",
            period_start=NOW,
            period_end=NOW,
            ci="FAIL",
            regression="FAIL",
            replay="FAIL",
        ),
    )
    request_risk(service)
    before = service.team.posture(identity("viewer"), "alpha")
    service.transition_risk(
        identity("owner"), "alpha", "risk", RiskTransition(action="approve", expected_version=1)
    )
    after = service.team.posture(identity("viewer"), "alpha")
    assert before == after and after.agents[0].status == "BLOCKED"
    contract = load_contract(Path("examples/mcp/contract.yaml"))
    plan = compile_contract(contract)
    request = PolicyRequest(
        schema_version="0.1",
        request_id="denied",
        authority=synthetic_authority(plan),
        principal=contract.identity.principal,
        agent=contract.agent,
        task_scope=contract.task_scope,
        capability="filesystem.write",
        tool_id="tool",
        environment=contract.environment.mode,
        requested_at=NOW,
    )
    assert NativePolicyEngine(lambda: NOW).decide(request, plan).outcome == "DENY"
    page = service.export_page(identity("owner"), "alpha", ExportCursor(org="alpha"))
    report = next(r for r in page.records if r.kind == "REPORT")
    assert report.ci == "FAIL" and report.posture_status == "BLOCKED"
    assert report.assurance == "REPORTED_UNVERIFIED"
    with service.team.store.transaction():
        service.team.store.scoped("alpha").delete_receipt(
            next(r.target for r in page.records if r.kind == "REPORT")
        )
    page = service.export_page(identity("owner"), "alpha", ExportCursor(org="alpha"))
    assert next(r for r in page.records if r.kind == "REPORT").observation == "MISSING"


@pytest.mark.parametrize(
    "change,category",
    [
        (lambda s: s.replace("max_tool_calls: 3", "max_tool_calls: 2"), "RESTRICTIVE"),
        (lambda s: s.replace("max_tool_calls: 3", "max_tool_calls: 4"), "EXPANSIVE"),
        (lambda s: s.replace("decision: DENY", "decision: ALLOW"), "EXPANSIVE"),
        (lambda s: s.replace("decision: ALLOW", "decision: DENY"), "RESTRICTIVE"),
        (lambda s: s.replace("decision: REQUIRE_APPROVAL", "decision: ALLOW"), "EXPANSIVE"),
        (
            lambda s: s.replace("principal_id: local-user", "principal_id: different-user"),
            "UNCLASSIFIED",
        ),
        (
            lambda s: s.replace("name: Synthetic protected tools", "name: Cosmetic change"),
            "UNCHANGED",
        ),
        (lambda s: s + "\napprovals:\n  default_timeout_seconds: 10\n", "UNCLASSIFIED"),
    ],
)
def test_simulation_finite_categories(env, change, category):
    service, _ = env
    draft(service)
    baseline = publish(service)
    enroll(service, revision="candidate", plan=baseline.assessment.compiled_plan_digest)
    draft(service, "next", base=1, source=change(SOURCE))
    result = service.simulate(
        identity("editor"),
        "alpha",
        SimulationInput(candidate="next", expected_generation=1, agents=("agent",)),
    )
    assert result.category == category
    assert result.agents[0].status == "COMPARED"
    if category == "UNCHANGED":
        assert result.assessment.document_hash != baseline.assessment.document_hash
        assert result.assessment.effective_policy_hash == baseline.assessment.effective_policy_hash


def test_simulation_unsupported_draft_is_unknown(env):
    service, _ = env
    draft(service)
    baseline = publish(service)
    enroll(service, revision="candidate", plan=baseline.assessment.compiled_plan_digest)
    draft(
        service,
        "unsupported",
        base=1,
        source=SOURCE.replace("max_tool_calls: 3", "max_tool_calls: 3\n  max_model_calls: 1"),
    )
    result = service.simulate(
        identity("editor"),
        "alpha",
        SimulationInput(candidate="unsupported", expected_generation=1, agents=("agent",)),
    )
    assert result.category == "UNCLASSIFIED" and result.agents[0].status == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["role", "trust", "publication"])
def test_federation_revocation_during_assessment(env, monkeypatch, mutation):
    service, key = env
    original = assess
    request = ImportRequest(bundle=bundle(key), local_revision_id="imported", base_generation=0)
    calls = 0

    def staged(*args):
        nonlocal calls
        calls += 1
        assert not service.team.store.connection.in_transaction
        if calls == 2:
            if mutation == "role":
                service.team.member(
                    identity("other"),
                    "beta",
                    Member(
                        identity_id="beta-editor",
                        role=Role.EDITOR,
                        enabled=False,
                        expected_version=1,
                    ),
                )
            elif mutation == "trust":
                service.trust = TrustConfig()
            else:
                from agentsec.control_plane.models import Publication

                with service.team.store.transaction():
                    service.team.store.scoped("beta").put(
                        "publication",
                        "policy",
                        Publication(policy_key="policy", generation=1).model_dump_json(),
                    )
        return original(*args)

    monkeypatch.setattr("agentsec.enterprise.service.assess", staged)
    monkeypatch.setattr("agentsec.enterprise.federation.assess", staged)
    with pytest.raises(
        TeamError,
        match={"role": "DENIED", "trust": "TRUST_UNAVAILABLE", "publication": "CONFLICT"}[mutation],
    ):
        service.import_bundle(identity("beta-editor"), "beta", request)
    assert not service.team.store.scoped("beta").all_rows("revision")


@pytest.mark.parametrize("who,org", [("other", "beta"), ("beta-editor", "beta")])
def test_cross_tenant_case_risk_references(env, who, org):
    service, _ = env
    open_case(service)
    with pytest.raises(TeamError, match="CONFLICT"):
        service.request_risk(
            identity(who),
            org,
            RiskInput(
                risk_id="risk",
                target_kind="case",
                target_id="case",
                target_version=1,
                reason="BUSINESS_CONTINUITY",
                expires_at=NOW + timedelta(days=1),
            ),
        )
    with pytest.raises(TeamError, match="DENIED"):
        service.open_case(
            identity(who),
            org,
            CaseInput(case_id="case", category="EVIDENCE", severity="LOW", assignee="editor"),
        )


def test_key_path_missing_public_parent_and_unknown_db_version(env, tmp_path):
    service, key = env
    payload = bundle(key).payload
    with pytest.raises(TeamError, match="TRUST_UNAVAILABLE"):
        sign(payload, tmp_path / "missing")
    parent = tmp_path / "unsafe"
    parent.mkdir(mode=0o755)
    with pytest.raises(TeamError):
        atomic_private_write(parent / "output", b"safe")
    bad = tmp_path / "unknown.db"
    backup_database(tmp_path / "team.db", bad)
    connection = sqlite3.connect(bad)
    connection.execute("PRAGMA user_version=42")
    connection.close()
    with pytest.raises(TeamError, match="STORE_UNAVAILABLE"):
        Store(bad)
    assert service.team.store.connection.execute("PRAGMA user_version").fetchone()[0] == 1


def test_backup_failure_removes_only_new_output(env, tmp_path, monkeypatch):
    service, _ = env

    class BrokenConnection(sqlite3.Connection):
        def backup(self, *args, **kwargs):
            raise sqlite3.OperationalError("injected")

    broken = sqlite3.connect(tmp_path / "team.db", factory=BrokenConnection)
    # Inject after source admission; never touch production files.
    from agentsec.enterprise import files

    class BrokenStore:
        connection = broken

        def close(self):
            broken.close()

    monkeypatch.setattr(files, "Store", lambda path: BrokenStore())
    with pytest.raises(TeamError, match="STORE_UNAVAILABLE"):
        backup_database(tmp_path / "team.db", tmp_path / "partial.db")
    assert not (tmp_path / "partial.db").exists()
    assert service.team.store.scoped("alpha").get("member", "owner")


def test_signed_export_wrong_manifest_and_embedded_key(env):
    service, key = env
    page = service.export_page(identity("owner"), "alpha", ExportCursor(org="alpha"))
    data, manifest = sign_export(page, "exporter", key, NOW)
    trust = TrustConfig(
        pins=(
            pin(
                "export",
                target="alpha",
                policy_key="siem",
                local_policy_key="siem",
                key_id="exporter",
            ),
        )
    )
    wrong = manifest.model_copy(
        update={"payload": manifest.payload.model_copy(update={"key_id": "unknown"})}
    )
    with pytest.raises(TeamError, match="TRUST_UNAVAILABLE"):
        verify_export(data, wrong, trust, NOW)
    changed = manifest.model_copy(
        update={
            "payload": manifest.payload.model_copy(update={"issued_at": NOW - timedelta(seconds=1)})
        }
    )
    with pytest.raises(TeamError, match="SIGNATURE_INVALID"):
        verify_export(data, changed, trust, NOW)
    raw = manifest.model_dump(mode="json")
    raw["public_key_pem"] = PUBLIC
    with pytest.raises(ArtifactValidationError):
        validate_data(SignedExport, raw)


def test_two_connections_workflow_cas(env, tmp_path):
    from agentsec.control_plane.service import TeamService

    service, _ = env
    open_case(service)
    second = Store(tmp_path / "team.db")
    try:
        competing = EnterpriseService(TeamService(second, fixture.CONFIG, lambda: NOW))
        action = CaseTransition(action="triage", expected_version=1)
        service.transition_case(identity("editor"), "alpha", "case", action)
        # Different actor cannot reuse first actor's receipt with stale version.
        with pytest.raises(TeamError, match="CONFLICT"):
            competing.transition_case(identity("owner"), "alpha", "case", action)
    finally:
        second.close()


def test_offline_cli_round_trip_and_sanitized_errors(env, tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from agentsec.cli import enterprise as cli
    from agentsec.cli.main import app
    from agentsec.control_plane.service import TeamService

    service, key = env
    draft(service)
    config = tmp_path / "config.json"
    config.write_text(fixture.CONFIG.model_dump_json())
    credential = tmp_path / "token"
    credential.write_text(fixture.token("owner"))
    credential.chmod(0o600)
    monkeypatch.setattr(
        cli, "TeamService", lambda store, config: TeamService(store, config, lambda: NOW)
    )

    class FixedDateTime(type(NOW)):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(cli, "datetime", FixedDateTime)
    runner = CliRunner()
    common = [str(tmp_path / "team.db"), str(config), str(credential), "alpha"]
    output, manifest = tmp_path / "cli.jsonl", tmp_path / "cli-manifest.json"
    result = runner.invoke(
        app,
        [
            "team",
            "enterprise",
            "export-siem",
            *common,
            "exporter",
            str(key),
            str(output),
            str(manifest),
        ],
    )
    assert result.exit_code == 0, result.output
    trust = tmp_path / "trust.json"
    trust.write_text(
        TrustConfig(
            pins=(
                pin(
                    "export",
                    target="alpha",
                    policy_key="siem",
                    local_policy_key="siem",
                    key_id="exporter",
                ),
            )
        ).model_dump_json()
    )
    trust.chmod(0o600)
    result = runner.invoke(
        app, ["team", "enterprise", "verify-export", str(output), str(manifest), str(trust)]
    )
    assert result.exit_code == 0 and "VERIFIED_EXPORT_ORIGIN" in result.output
    source_output = tmp_path / "bundle.json"
    result = runner.invoke(
        app,
        [
            "team",
            "enterprise",
            "federation-export",
            *common,
            "candidate",
            "beta",
            "policy",
            "1",
            "peer",
            str(key),
            str(source_output),
        ],
    )
    assert result.exit_code == 0, result.output
    trust.write_text(TrustConfig(pins=(pin(),)).model_dump_json())
    result = runner.invoke(
        app, ["team", "enterprise", "verify-federation", str(source_output), str(trust)]
    )
    assert result.exit_code == 0, result.output
    key.chmod(0o644)
    result = runner.invoke(
        app,
        [
            "team",
            "enterprise",
            "federation-export",
            *common,
            "candidate",
            "beta",
            "policy",
            "2",
            "peer",
            str(key),
            str(tmp_path / "bad.json"),
        ],
    )
    assert result.exit_code == 1 and result.output.strip() == "TRUST_UNAVAILABLE"
    assert not (tmp_path / "bad.json").exists()
    assert service.team.store.scoped("alpha").get("revision", "candidate")


def test_enterprise_no_network_dispatch(env, monkeypatch):
    import socket

    service, key = env

    def forbidden(*args, **kwargs):
        pytest.fail("network attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    draft(service)
    enroll(service)
    service.simulate(
        identity("editor"),
        "alpha",
        SimulationInput(candidate="candidate", expected_generation=0, agents=("agent",)),
    )
    service.import_bundle(
        identity("beta-editor"),
        "beta",
        ImportRequest(bundle=bundle(key), local_revision_id="candidate", base_generation=0),
    )
    open_case(service)
    request_risk(service)
    service.export_page(identity("owner"), "alpha", ExportCursor(org="alpha"))


def test_export_snapshot_reauthorizes_revoked_owner(env, monkeypatch):
    service, _ = env
    service.team.member(identity("owner"), "alpha", Member(identity_id="other", role=Role.OWNER))
    original = service.team.posture

    def staged(*args):
        result = original(*args)
        service.team.member(
            identity("other"),
            "alpha",
            Member(identity_id="owner", role=Role.VIEWER, expected_version=1),
        )
        return result

    monkeypatch.setattr(service.team, "posture", staged)
    with pytest.raises(TeamError, match="DENIED"):
        service.export_page(identity("owner"), "alpha", ExportCursor(org="alpha"))


def test_risk_revision_supersession_and_approver_revocation(env):
    service, _ = env
    draft(service)
    baseline = publish(service)
    service.request_risk(
        identity("editor"),
        "alpha",
        RiskInput(
            risk_id="revision-risk",
            target_kind="revision",
            target_id="candidate",
            target_version=baseline.version,
            reason="COMPENSATING_CONTROL",
            expires_at=NOW + timedelta(days=1),
        ),
    )
    service.transition_risk(
        identity("owner"),
        "alpha",
        "revision-risk",
        RiskTransition(action="approve", expected_version=1),
    )
    draft(service, "next", base=1)
    publish(service, "next")
    assert service.risk(identity("viewer"), "alpha", "revision-risk").disposition == "STALE"
    open_case(service)
    request_risk(service)
    service.transition_risk(
        identity("owner"), "alpha", "risk", RiskTransition(action="approve", expected_version=1)
    )
    service.team.member(identity("owner"), "alpha", Member(identity_id="other", role=Role.OWNER))
    service.team.member(
        identity("other"),
        "alpha",
        Member(identity_id="owner", role=Role.VIEWER, expected_version=1),
    )
    assert service.risk(identity("viewer"), "alpha", "risk").disposition == "STALE"
