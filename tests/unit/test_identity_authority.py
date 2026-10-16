"""Phase 6 restrictive authority, real local JWT proof, approval and offline replay."""

import asyncio
import json
from datetime import timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError
from test_runtime_policy import NOW, contract_with, request_for
from test_runtime_state import Broker, tool

from agentsec.adapters.identity.jwt import JwtIdentityProvider
from agentsec.compiler import compile_contract
from agentsec.compiler.reporting import run_conformance
from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import validate_data
from agentsec.domain.approvals import NormalizedAction, action_digest
from agentsec.domain.authority import AuthorityContext
from agentsec.domain.events import ToolDispatchedPayload, ToolRequestedPayload
from agentsec.domain.identity import Delegation, PrincipalRef, TaskScope
from agentsec.domain.replay import RegressionState, ReplayError
from agentsec.domain.scenarios import ToolNotCalled
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.domain.taxonomy import EnforcementMode, PolicyOutcome, PrincipalType, ReasonCode
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.identity.authority import intersect_scopes
from agentsec.identity.config import JwtIdentityConfig
from agentsec.identity.ingress import read_credential
from agentsec.identity.ports import IdentityError
from agentsec.identity.static import StaticIdentityProvider
from agentsec.incident.classify import classify
from agentsec.incident.promote import promote
from agentsec.policy.native import NativePolicyEngine
from agentsec.regression.runner import run_case
from agentsec.replay.bundle import create_bundle
from agentsec.replay.engine import replay
from agentsec.runtime.approvals import ApprovalLedger
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure, ToolResponse

READ, WRITE = "web.search", "filesystem.write"
USER = PrincipalRef(principal_id="user", principal_type=PrincipalType.USER)
OTHER = PrincipalRef(principal_id="other", principal_type=PrincipalType.AGENT)


def contract(obo=True, decision="ALLOW"):
    c = contract_with(
        budgets={},
        task_scope=None,
        tools={
            "rules": [
                {"rule_id": "read", "capability": READ, "decision": decision},
                {"rule_id": "write", "capability": WRITE, "decision": "ALLOW"},
            ]
        },
    )
    return c.model_copy(
        update={
            "identity": c.identity.model_copy(update={"acts_on_behalf_of": USER if obo else None})
        }
    )


def context(c=None, caps=frozenset({READ}), *, resources=None, **grant_changes):
    c = c or contract()
    scope = TaskScope(task_id="task", description="protected", resource_scopes=resources)
    grant = Delegation(
        schema_version="0.1",
        delegation_id="grant",
        delegator=USER,
        delegate=c.identity.principal,
        task_scope=scope,
        capability_scope=caps,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=10),
    )
    grant = grant.model_copy(update=grant_changes)
    return AuthorityContext(
        schema_version="0.1",
        credential=StaticIdentityProvider(c.identity.principal).verify(None, NOW),
        delegation_json=canonical_json(grant),
    )


def decide(c, authority, cap=READ, resource=None):
    r = request_for(c, cap, resource)
    grant = authority.delegation if authority else None
    r = r.model_copy(
        update={"authority": authority, "delegation_id": grant.delegation_id if grant else None}
    )
    return NativePolicyEngine(lambda: NOW).decide(r, compile_contract(c))


@pytest.mark.parametrize(
    "left,right,expected",
    [
        (None, None, None),
        (None, frozenset(), frozenset()),
        (frozenset({READ, WRITE}), frozenset({READ}), frozenset({READ})),
        (frozenset({READ}), frozenset({WRITE}), frozenset()),
    ],
)
def test_capability_intersection_null_empty(left, right, expected):
    a = TaskScope(task_id="t", description="a", requested_capabilities=left)
    b = TaskScope(task_id="t", description="b", requested_capabilities=right)
    assert intersect_scopes(a, b).requested_capabilities == expected
    assert intersect_scopes(None, a) == a
    with pytest.raises(ValueError, match="TASK_ID_MISMATCH"):
        intersect_scopes(a, b.model_copy(update={"task_id": "other"}))


def test_resource_intersection_and_defensive_maps():
    a = TaskScope(task_id="t", description="a", resource_scopes={READ: frozenset({"a", "b"})})
    b = TaskScope(
        task_id="t",
        description="b",
        resource_scopes={READ: frozenset({"b", "c"}), WRITE: frozenset()},
    )
    assert intersect_scopes(a, b).resource_scopes == {READ: frozenset({"b"}), WRITE: frozenset()}
    auth = context(resources={READ: frozenset({"a"})})
    digest = auth.authority_digest
    auth.delegation.task_scope.resource_scopes[READ] = frozenset({"evil"})
    assert auth.authority_digest == digest
    assert auth.delegation.task_scope.resource_scopes[READ] == {"a"}
    assert context(resources={READ: frozenset({"b"})}).authority_digest != digest


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"delegator": OTHER}, ReasonCode.INVALID_DELEGATION),
        ({"delegate": OTHER}, ReasonCode.INVALID_DELEGATION),
        ({"expires_at": None}, ReasonCode.INVALID_DELEGATION),
        ({"parent_delegation_id": "parent"}, ReasonCode.INVALID_DELEGATION),
        ({"expires_at": NOW}, ReasonCode.AUTHORITY_EXPIRED),
        ({"issued_at": NOW + timedelta(seconds=1)}, ReasonCode.AUTHORITY_EXPIRED),
        (
            {
                "task_scope": TaskScope(
                    task_id="t", description="bad", requested_capabilities=frozenset({WRITE})
                )
            },
            ReasonCode.INVALID_DELEGATION,
        ),
        (
            {
                "task_scope": TaskScope(
                    task_id="t", description="bad", resource_scopes={WRITE: frozenset({"x"})}
                )
            },
            ReasonCode.INVALID_DELEGATION,
        ),
    ],
)
def test_invalid_direct_grants(change, reason):
    c = contract()
    assert decide(c, context(c, **change)).reason_codes == {reason}


def test_no_identity_or_delegation_grants_contract_permission():
    c = contract()
    auth = context(c)
    assert decide(c, auth).outcome == PolicyOutcome.ALLOW
    assert decide(c, auth, WRITE).reason_codes == {ReasonCode.OUTSIDE_AUTHORITY_SCOPE}
    assert decide(c, None).reason_codes == {ReasonCode.DELEGATION_REQUIRED}
    assert decide(contract(False), auth).reason_codes == {ReasonCode.INVALID_DELEGATION}
    broad = context(c, frozenset({READ, WRITE}))
    assert decide(contract(decision="DENY"), broad).reason_codes == {ReasonCode.EXPLICIT_DENY}
    empty = c.model_copy(update={"tools": c.tools.model_copy(update={"rules": ()})})
    assert decide(empty, broad).reason_codes == {ReasonCode.DEFAULT_DENY}
    assert (
        decide(contract(decision="REQUIRE_APPROVAL"), auth).outcome
        == PolicyOutcome.REQUIRE_APPROVAL
    )
    narrow = auth.model_copy(
        update={
            "credential": auth.credential.model_copy(update={"capability_ceiling": frozenset()})
        }
    )
    assert decide(c, narrow).reason_codes == {ReasonCode.OUTSIDE_AUTHORITY_SCOPE}
    mismatch = auth.model_copy(
        update={"credential": auth.credential.model_copy(update={"principal": OTHER})}
    )
    assert decide(c, mismatch).reason_codes == {ReasonCode.IDENTITY_MISMATCH}
    scoped = c.model_copy(update={"task_scope": TaskScope(task_id="other", description="task")})
    assert decide(scoped, auth).reason_codes == {ReasonCode.INVALID_DELEGATION}


def test_direct_phase6_requires_trusted_authority():
    c = contract(False)
    assert decide(c, None).outcome == PolicyOutcome.DENY
    assert decide(c, None).reason_codes == {ReasonCode.AUTHORITY_REQUIRED}

    static_authority = AuthorityContext(
        schema_version="0.1",
        credential=StaticIdentityProvider(c.identity.principal).verify(None, NOW),
    )
    assert decide(c, static_authority).outcome == PolicyOutcome.ALLOW


def test_resource_narrowing_and_data_flow_clamp():
    c = contract()
    auth = context(c, resources={READ: frozenset({"private"})})
    assert decide(c, auth, resource="private").outcome == PolicyOutcome.ALLOW
    assert decide(c, auth, resource="elsewhere").reason_codes == {
        ReasonCode.OUTSIDE_AUTHORITY_SCOPE
    }
    from agentsec.compiler.probes import synthetic_artifacts
    from agentsec.domain.taxonomy import DataLabel

    c = validate_data(
        type(c),
        {
            **c.model_dump(mode="json"),
            "data": {
                "rules": [{"rule_id": "secret", "label": "SECRET", "denied_capabilities": [READ]}]
            },
        },
    )
    request = request_for(c).model_copy(
        update={
            "authority": context(c),
            "delegation_id": "grant",
            "data_artifact_refs": synthetic_artifacts(frozenset({DataLabel.SECRET})),
        }
    )
    assert NativePolicyEngine(lambda: NOW).decide(request, c).reason_codes == {
        ReasonCode.DATA_FLOW_DENIED
    }


def gateway(c, auth, now, broker=None, mode=EnforcementMode.ENFORCE, **kwargs):
    sink = InMemoryEventSink()
    runtime = RuntimeGateway(
        c, mode, RuntimeEvents(sink, lambda: now[0]), broker or Broker(), authority=auth, **kwargs
    )
    return runtime, sink


def test_expiry_during_approval_never_dispatches():
    c, now = contract(decision="REQUIRE_APPROVAL"), [NOW]

    class WaitingBroker(Broker):
        async def decide(self, request, presentation):
            now[0] += timedelta(seconds=10)
            return (await super().decide(request, presentation)).model_copy(
                update={"decided_at": now[0]}
            )

    runtime, sink = gateway(c, context(c), now, WaitingBroker())

    async def dispatch(_):
        pytest.fail("expired authority dispatched")

    with pytest.raises(RuntimeFailure, match="AUTHORITY_EXPIRED"):
        asyncio.run(runtime.call(tool(), {}, None, dispatch, bound=True))
    assert not any(isinstance(e.payload, ToolDispatchedPayload) for e in sink.events)


def test_action_digest_binds_changed_grant_not_only_id():
    c = contract()
    a, b = context(c), context(c, frozenset({READ, WRITE}))
    args = dict(
        schema_version="0.1",
        principal=c.identity.principal,
        agent_id=c.agent.agent_id,
        environment=c.environment.mode,
        capability=READ,
        tool_id="tool",
        arguments={},
        delegation_id="grant",
        tool_schema_hash=content_digest({}),
        tool_description_hash=content_digest("tool"),
        effective_policy_hash=compile_contract(c).effective_policy_hash,
    )
    first = NormalizedAction(**args, authority_digest=a.authority_digest)
    second = NormalizedAction(**args, authority_digest=b.authority_digest)
    assert action_digest(first) != action_digest(second)
    from test_runtime_state import approval

    ledger = ApprovalLedger(lambda: NOW)
    approval_request = approval().model_copy(update={"action_digest": action_digest(first)})
    ledger.create(approval_request)
    ledger.record(asyncio.run(Broker().decide(approval_request, "safe")))
    with pytest.raises(RuntimeFailure, match="INVALID_APPROVAL"):
        ledger.redeem(approval_request.approval_id, action_digest(second))


def test_end_to_end_read_only_concurrent_no_argument_injection_and_replay():
    c, auth = contract(), context()
    runtime, sink = gateway(c, auth, [NOW])
    calls = []

    async def dispatch(args):
        calls.append(args)
        return ToolResponse(body={"content": []}, success=True)

    async def run():
        await asyncio.gather(
            *(
                runtime.call(
                    tool(), {"principal": "other", "scope": WRITE}, None, dispatch, bound=True
                )
                for _ in range(3)
            )
        )
        write = tool().model_copy(update={"capabilities": frozenset({WRITE}), "tool_id": "write"})
        with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
            await runtime.call(write, {}, None, dispatch, bound=True)
        runtime.finish()
        return write

    write = asyncio.run(run())
    assert len(calls) == 3
    assert runtime._authority == auth
    b = create_bundle(
        tuple(sink.events),
        c,
        tools=(tool(), write),
        expectations=(ToolNotCalled(type="TOOL_NOT_CALLED", tool_id="write"),),
    )
    result = replay(b)
    assert len(result.substituted_dispatch_ids) == 3
    assert result.diff.status == "UNCHANGED"
    case = promote(b, classify(b))
    assert case.state == RegressionState.ACTIVE
    assert run_case(case) == "PASS"


@pytest.mark.parametrize("mode", list(EnforcementMode))
def test_identity_failure_modes_truthful(mode):
    c = contract(False)
    sink = InMemoryEventSink()
    if mode == EnforcementMode.ENFORCE:
        with pytest.raises(RuntimeFailure, match="IDENTITY_CREDENTIAL_INVALID"):
            RuntimeGateway(
                c,
                mode,
                RuntimeEvents(sink, lambda: NOW),
                Broker(),
                identity_error="IDENTITY_CREDENTIAL_INVALID",
            )
        return
    runtime = RuntimeGateway(
        c,
        mode,
        RuntimeEvents(sink, lambda: NOW),
        Broker(),
        identity_error="IDENTITY_CREDENTIAL_INVALID",
    )

    async def dispatch(_):
        return ToolResponse(body={}, success=True)

    asyncio.run(runtime.call(tool(), {}, None, dispatch, bound=True))
    summary = sink.events[0].payload.authority_summary
    assert summary.actor is None and summary.assurance is None
    assert not summary.enforcement_enabled
    assert summary.error == "IDENTITY_CREDENTIAL_INVALID"


def test_conformance_direct_and_obo():
    for c in (contract(False), contract()):
        report = run_conformance(compile_contract(c))
        assert all(p.status == "PASS" for p in report.probes)
        assert any(p.obligation_kind == "authority_credential_ceiling" for p in report.probes)
    assert any(p.obligation_kind == "authority_missing_delegation" for p in report.probes)
    direct = run_conformance(compile_contract(contract(False)))
    assert any(p.obligation_kind == "authority_missing_authority" for p in direct.probes)
    assert all(p.status == "PASS" for p in direct.probes)


@pytest.fixture(scope="module")
def jwt_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    cfg = validate_data(
        JwtIdentityConfig,
        {
            "provider": "signed_jwt",
            "issuer": "issuer",
            "audience": "audience",
            "keys": [{"kid": "key", "algorithm": "RS256", "public_key_pem": public}],
            "subjects": [
                {
                    "subject": "workload",
                    "principal": contract(False).identity.principal.model_dump(mode="json"),
                }
            ],
            "scope_mapping": {"read": READ},
        },
    )
    return private, cfg


def signed(material, changes=None, headers=None):
    private, _ = material
    claims = {
        "iss": "issuer",
        "aud": "audience",
        "sub": "workload",
        "nbf": int(NOW.timestamp()) - 1,
        "exp": int(NOW.timestamp()) + 10,
        "scope": "read unknown",
    }
    claims.update(changes or {})
    return jwt.encode(claims, private, algorithm="RS256", headers=headers or {"kid": "key"})


def test_local_signed_jwt_flow(jwt_material):
    provider = JwtIdentityProvider(jwt_material[1])
    raw = signed(jwt_material)
    verified = provider.verify(raw, NOW)
    assert verified.assurance == "SIGNED_JWT"
    assert verified.capability_ceiling == {READ}
    assert (
        provider.verify(signed(jwt_material, {"scope": "unknown"}), NOW).capability_ceiling
        == frozenset()
    )
    authority = AuthorityContext(schema_version="0.1", credential=verified)
    c = contract(False)
    assert decide(c, authority).outcome == PolicyOutcome.ALLOW
    assert decide(c, authority, WRITE).outcome == PolicyOutcome.DENY
    runtime, sink = gateway(c, authority, [NOW])

    async def dispatch(_):
        return ToolResponse(body={}, success=True)

    asyncio.run(runtime.call(tool(), {}, None, dispatch, bound=True))
    runtime.finish()
    encoded = canonical_json(create_bundle(tuple(sink.events), c, tools=(tool(),)))
    assert raw not in encoded and "workload" not in encoded


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "wrong"},
        {"aud": "wrong"},
        {"sub": "unmapped"},
        {"sub": None},
        {"exp": None},
        {"exp": int(NOW.timestamp())},
        {"nbf": int(NOW.timestamp()) + 20},
        {"exp": "99999999999"},
        {"exp": True},
        {"nbf": False},
        {"scope": ["read"]},
    ],
)
def test_jwt_invalid_claims_and_no_leak(jwt_material, change):
    raw = signed(jwt_material, change)
    with pytest.raises(IdentityError) as caught:
        JwtIdentityProvider(jwt_material[1]).verify(raw, NOW)
    assert str(caught.value) == "IDENTITY_CREDENTIAL_INVALID"
    assert raw not in str(caught.value) and caught.value.__suppress_context__


@pytest.mark.parametrize(
    "header",
    [
        {"kid": "unknown"},
        {"kid": "key", "jku": "https://invalid"},
        {"kid": "key", "jwk": {}},
        {"kid": "key", "x5u": "https://invalid"},
        {"kid": "key", "crit": ["x"]},
    ],
)
def test_jwt_untrusted_key_selection(jwt_material, header):
    with pytest.raises(IdentityError):
        JwtIdentityProvider(jwt_material[1]).verify(signed(jwt_material, headers=header), NOW)


def test_jwt_algorithms_signature_size_missing_and_keys(jwt_material):
    provider = JwtIdentityProvider(jwt_material[1])
    bad = [
        None,
        "x" * 16385,
        jwt.encode({"sub": "x"}, "", algorithm="none"),
        jwt.encode(
            {"sub": "x"},
            "test-secret-with-at-least-thirty-two-characters",
            algorithm="HS256",
            headers={"kid": "key"},
        ),
        signed((rsa.generate_private_key(public_exponent=65537, key_size=2048), None)),
    ]
    for token in bad:
        with pytest.raises(IdentityError):
            provider.verify(token, NOW)
    cfg = jwt_material[1].model_dump(mode="json")
    cfg["keys"] *= 2
    with pytest.raises(ArtifactValidationError):
        validate_data(JwtIdentityConfig, cfg)
    cfg = jwt_material[1].model_dump(mode="json")
    cfg["subjects"] *= 2
    with pytest.raises(ArtifactValidationError):
        validate_data(JwtIdentityConfig, cfg)
    cfg = jwt_material[1].model_dump(mode="json")
    cfg["clock_skew_seconds"] = 61
    with pytest.raises(ArtifactValidationError):
        validate_data(JwtIdentityConfig, cfg)


def test_protected_credential_file(tmp_path):
    path = tmp_path / "token"
    path.write_text("synthetic-token")
    path.chmod(0o600)
    assert read_credential(path) == "synthetic-token"
    path.chmod(0o644)
    with pytest.raises(IdentityError):
        read_credential(path)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(IdentityError):
        read_credential(link)
    path.write_text("x" * 16385)
    with pytest.raises(IdentityError):
        read_credential(path)


def test_material_authority_redaction_and_missing_context():
    c, auth = contract(), context(resources={READ: frozenset({"secret-resource"})})
    runtime, sink = gateway(c, auth, [NOW])

    async def dispatch(_):
        return ToolResponse(body={}, success=True)

    asyncio.run(runtime.call(tool(), {}, "secret-resource", dispatch, bound=True))
    runtime.finish()
    encoded = canonical_json(sink.events)
    assert "secret-resource" not in encoded
    b = create_bundle(tuple(sink.events), c, tools=(tool(),))
    assert "MISSING_AUTHORITY_CONTEXT" in b.assessment.blockers
    b = create_bundle(tuple(sink.events), c, tools=(tool(),), authority=auth)
    assert "MISSING_AUTHORITY_CONTEXT" not in b.assessment.blockers
    # Resource redaction remains material even when trusted authority is supplied.
    assert "MATERIAL_REDACTION" in b.assessment.blockers
    with pytest.raises(ReplayError, match="AUTHORITY_DIGEST_MISMATCH"):
        create_bundle(tuple(sink.events), c, tools=(tool(),), authority=context())


def test_historical_compiler_canonical_identity_and_current_missing_authority(root):
    from agentsec.contracts.loader import load_artifact, load_contract
    from agentsec.domain.replay import ReplayBundle

    # Actual checked-in Phase 5 artifact must retain its digest and interpretation.
    c = load_contract(root / "examples/replay/source-contract.json")
    old = compile_contract(c, historical=True)
    assert old.compiler_version == "phase4-v1"
    assert "acts_on_behalf_of" not in old.model_dump()
    assert compile_contract(c).compiler_version == "phase6-v1"
    files = list((root / "examples").rglob("*bundle*.json"))
    for path in files:
        b = load_artifact(path, ReplayBundle)
        if b.source_plan.compiler_version != "phase4-v1":
            continue
        assert b.source_plan.identity.compiler_version == "phase4-v1"
        result = replay(b, c)
        assert "MISSING_AUTHORITY_CONTEXT" in result.assessment.blockers


def test_expiry_after_startup_and_before_call_blocks():
    c, now = contract(), [NOW]
    runtime, sink = gateway(c, context(c), now)
    now[0] += timedelta(seconds=10)

    async def dispatch(_):
        pytest.fail("expired authority dispatched")

    with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
        asyncio.run(runtime.call(tool(), {}, None, dispatch, bound=True))
    assert not any(isinstance(e.payload, ToolDispatchedPayload) for e in sink.events)
    with pytest.raises(RuntimeFailure, match="AUTHORITY_EXPIRED"):
        gateway(c, context(c), now)


def test_current_replay_missing_authority_and_session_binding():
    c = contract(False)
    auth = AuthorityContext(
        schema_version="0.1",
        credential=StaticIdentityProvider(c.identity.principal).verify(None, NOW),
    )
    runtime, sink = gateway(c, auth, [NOW])

    async def dispatch(_):
        return ToolResponse(body={}, success=True)

    asyncio.run(runtime.call(tool(), {}, None, dispatch, bound=True))
    runtime.finish()
    events = list(sink.events)
    # Absence is incomplete, never an invented principal/credential.
    events[0] = events[0].model_copy(
        update={"payload": events[0].payload.model_copy(update={"authority_summary": None})}
    )
    p = events[1].payload
    request = p.request.model_copy(update={"authority": None})
    events[1] = events[1].model_copy(
        update={
            "payload": p.model_copy(
                update={"request": request, "policy_input_digest": content_digest(request)}
            )
        }
    )
    b = create_bundle(tuple(events), c, tools=(tool(),))
    assert "MISSING_AUTHORITY_CONTEXT" in replay(b).assessment.blockers
    events[0] = sink.events[0]
    with pytest.raises(ReplayError, match="SESSION_AUTHORITY_MISMATCH"):
        create_bundle(tuple(events), c, tools=(tool(),))


def test_strict_authority_artifacts_and_digest_stability():
    auth = context()
    assert AuthorityContext.model_validate_json(auth.model_dump_json()) == auth
    for change in (
        {"schema_version": "9"},
        {"unexpected": True},
        {"delegation_json": "{}"},
        {"delegation_json": " " + auth.delegation_json},
    ):
        data = auth.model_dump(mode="json")
        data.update(change)
        with pytest.raises(ValidationError):
            AuthorityContext.model_validate_json(json.dumps(data))
    for change in (
        {"schema_version": "9"},
        {"unexpected": True},
        {"assurance": "UNVERIFIED"},
        {"expires_at": auth.credential.valid_from.isoformat()},
        {"assurance": "SIGNED_JWT", "expires_at": None},
    ):
        from agentsec.domain.authority import VerifiedCredential

        data = auth.credential.model_dump(mode="json")
        data.update(change)
        with pytest.raises(ValidationError):
            VerifiedCredential.model_validate_json(json.dumps(data))
    assert (
        context(caps=frozenset({READ, WRITE})).authority_digest
        == context(caps=frozenset({WRITE, READ})).authority_digest
    )


def test_cli_jwt_check_without_token_and_secret_safe_failure(jwt_material, tmp_path, root):
    from typer.testing import CliRunner

    from agentsec.adapters.mcp.config import McpGatewayConfig
    from agentsec.cli.main import app
    from agentsec.contracts.loader import load_artifact

    c = contract(False)
    cfg = load_artifact(root / "examples/mcp/gateway.yaml", McpGatewayConfig).model_copy(
        update={"identity": jwt_material[1]}
    )
    cpath, gpath = tmp_path / "contract.json", tmp_path / "gateway.json"
    cpath.write_text(c.model_dump_json())
    gpath.write_text(cfg.model_dump_json())
    runner = CliRunner()
    args = ["protect", "mcp", "--contract", str(cpath), "--config", str(gpath)]
    result = runner.invoke(app, [*args, "--check", "--credential-file", str(tmp_path / "absent")])
    assert result.exit_code == 0, result.output
    credential = tmp_path / "credential"
    raw = "credential-leak-canary-invalid.jwt"
    credential.write_text(raw)
    credential.chmod(0o600)
    result = runner.invoke(app, [*args, "--credential-file", str(credential)])
    assert result.exit_code == 1
    assert "IDENTITY_CREDENTIAL_INVALID" in result.output
    assert raw not in result.output


def test_jwt_bounded_skew_and_identity_only(jwt_material):
    from agentsec.identity.config import JwtKey

    cfg = jwt_material[1].model_copy(update={"clock_skew_seconds": 5, "scope_mapping": None})
    # With no nbf, recent expiry can still be within explicitly configured bounded skew.
    private = jwt_material[0]
    raw = jwt.encode(
        {"iss": "issuer", "aud": "audience", "sub": "workload", "exp": int(NOW.timestamp()) - 1},
        private,
        algorithm="RS256",
        headers={"kid": "key"},
    )
    verified = JwtIdentityProvider(cfg).verify(raw, NOW)
    assert verified.capability_ceiling is None
    assert verified.expires_at == NOW + timedelta(seconds=4)
    with pytest.raises(IdentityError):
        JwtIdentityProvider(cfg).verify(raw, NOW + timedelta(seconds=4))
    for algorithm in ("ES256", "EdDSA"):
        key = JwtKey(kid="key", algorithm=algorithm, public_key_pem=cfg.keys[0].public_key_pem)
        with pytest.raises(IdentityError, match="CONFIGURATION_INVALID"):
            JwtIdentityProvider(cfg.model_copy(update={"keys": (key,)}))


def test_jwt_other_pinned_asymmetric_algorithms(jwt_material):
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    from agentsec.identity.config import JwtKey

    for algorithm, key in (
        ("ES256", ec.generate_private_key(ec.SECP256R1())),
        ("EdDSA", ed25519.Ed25519PrivateKey.generate()),
    ):
        public = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        cfg = jwt_material[1].model_copy(
            update={"keys": (JwtKey(kid="key", algorithm=algorithm, public_key_pem=public),)}
        )
        raw = jwt.encode(
            {
                "iss": "issuer",
                "aud": "audience",
                "sub": "workload",
                "exp": int(NOW.timestamp()) + 10,
            },
            key,
            algorithm=algorithm,
            headers={"kid": "key"},
        )
        assert JwtIdentityProvider(cfg).verify(raw, NOW).assurance == "SIGNED_JWT"


def test_approval_replay_rechecks_authority_at_recorded_dispatch():
    c = contract(decision="REQUIRE_APPROVAL")
    runtime, sink = gateway(c, context(c), [NOW])

    async def dispatch(_):
        return ToolResponse(body={}, success=True)

    asyncio.run(runtime.call(tool(), {}, None, dispatch, bound=True))
    runtime.finish()
    events = []
    delayed = False
    for event in sink.events:
        delayed |= isinstance(event.payload, ToolDispatchedPayload)
        events.append(
            event.model_copy(update={"occurred_at": NOW + timedelta(seconds=11)})
            if delayed
            else event
        )
    result = replay(create_bundle(tuple(events), c, tools=(tool(),)))
    assert not result.substituted_dispatch_ids


def test_conformance_evidence_records_actual_authority_input():
    from agentsec.compiler.probes import generate_probes
    from agentsec.eval.contract_cases import ContractTarget, case_scenario
    from agentsec.eval.ports import EvaluationContext
    from agentsec.eval.runner import evaluate

    c = contract()
    plan = compile_contract(c)
    probe = next(p for p in generate_probes(plan) if p.obligation_kind == "authority_valid")
    recorder = EvaluationContext()
    result = evaluate(
        contract=c,
        scenario=case_scenario(plan, probe),
        target=ContractTarget(plan, probe),
        context=recorder,
    )
    assert result.overall_status.value == "PASS"
    requests = [
        e.payload for e in recorder.recorder.events if isinstance(e.payload, ToolRequestedPayload)
    ]
    assert requests and requests[0].request.authority == probe.request(plan).authority
    assert requests[0].request.delegation_id == "synthetic-direct"
    assert requests[0].policy_input_digest == content_digest(requests[0].request)
