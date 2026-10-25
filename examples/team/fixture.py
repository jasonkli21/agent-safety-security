"""SYNTHETIC TEST ONLY issuer. Fixed public test seed; never use for real identities."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentsec.control_plane.auth import TeamVerifier
from agentsec.control_plane.models import (
    Binding,
    IdentityKind,
    Issuer,
    Key,
    Member,
    Role,
    TeamConfig,
)
from agentsec.control_plane.service import TeamService
from agentsec.control_plane.store import Store

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)
# Publicly known deterministic fixture seed, with no authority outside temporary test DBs.
TEST_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = (
    TEST_KEY.public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)
CONFIG = TeamConfig(
    issuers=(
        Issuer(
            issuer="https://synthetic.invalid",
            audience="team-test",
            keys=(Key(kid="test", public_key_pem=PUBLIC_KEY),),
        ),
    )
)


def token(subject: str, **changes: object) -> str:
    claims = {
        "iss": "https://synthetic.invalid",
        "aud": "team-test",
        "sub": subject,
        "exp": (NOW + timedelta(hours=2)).timestamp(),
        "nbf": (NOW - timedelta(seconds=1)).timestamp(),
    }
    claims.update(changes)
    return jwt.encode(claims, TEST_KEY, algorithm="EdDSA", headers={"kid": "test"})


def setup(path: Path) -> TeamService:
    store = Store(path, initialize=True)
    service = TeamService(store, CONFIG, lambda: NOW)
    verifier = TeamVerifier(CONFIG)
    for name, kind in (
        ("owner", IdentityKind.HUMAN),
        ("other", IdentityKind.HUMAN),
        ("editor", IdentityKind.HUMAN),
        ("reviewer", IdentityKind.HUMAN),
        ("viewer", IdentityKind.HUMAN),
        ("both", IdentityKind.HUMAN),
        ("reporter", IdentityKind.REPORTER),
        ("ci", IdentityKind.REPORTER),
        ("service", IdentityKind.SERVICE),
        ("beta-editor", IdentityKind.HUMAN),
        ("beta-reviewer", IdentityKind.HUMAN),
        ("beta-reporter", IdentityKind.REPORTER),
    ):
        store.provision(
            Binding(identity_id=name, issuer=CONFIG.issuers[0].issuer, subject=name, kind=kind)
        )
    service.bootstrap("alpha", store.binding_by_id("owner"))
    service.bootstrap("beta", store.binding_by_id("other"))
    owner = verifier.verify(token("owner"), NOW)
    other = verifier.verify(token("other"), NOW)
    for name, role in (
        ("editor", Role.EDITOR),
        ("reviewer", Role.REVIEWER),
        ("viewer", Role.VIEWER),
        ("both", Role.VIEWER),
        ("service", Role.VIEWER),
    ):
        service.member(owner, "alpha", Member(identity_id=name, role=role))
    service.member(other, "beta", Member(identity_id="both", role=Role.VIEWER))
    service.member(other, "beta", Member(identity_id="beta-editor", role=Role.EDITOR))
    service.member(other, "beta", Member(identity_id="beta-reviewer", role=Role.REVIEWER))
    return service
