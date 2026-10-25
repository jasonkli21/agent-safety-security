"""Offline domain-separated Ed25519 signatures with independently provisioned pins."""

import os
from datetime import datetime
from pathlib import Path

from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.store import Store
from agentsec.domain.serialization import canonical_json
from agentsec.enterprise.models import ExportManifest, FederationPayload, Pin, TrustConfig

Payload = FederationPayload | ExportManifest


def signing_bytes(payload: Payload) -> bytes:
    return f"agentsec:enterprise-v1:{payload.purpose}\n".encode() + canonical_json(payload).encode(
        "utf-8"
    )


def private_bytes(path: Path, maximum: int = 1_048_576) -> bytes:
    """Protected parent directories remain an operator prerequisite."""
    try:
        if os.name != "posix":
            raise ValueError
        Store._check_private_file(path, required=True)
        if path.stat().st_size > maximum:
            raise ValueError
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError
        return data
    except (OSError, ValueError):
        raise TeamError("TRUST_UNAVAILABLE") from None


def sign(payload: Payload, private_key: Path) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        key = load_pem_private_key(private_bytes(private_key, 4096), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError
        return key.sign(signing_bytes(payload)).hex()
    except (ValueError, TypeError):
        raise TeamError("SIGNATURE_INVALID") from None


def verify(payload: Payload, signature: str, trust: TrustConfig, now: datetime) -> Pin:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    matches = [
        p
        for p in trust.pins
        if p.enabled
        and p.not_before <= now < p.expires_at
        and (p.origin, p.target, p.policy_key, p.local_policy_key, p.key_id, p.purpose)
        == (
            payload.origin,
            payload.target,
            payload.policy_key,
            payload.local_policy_key,
            payload.key_id,
            payload.purpose,
        )
    ]
    if len(matches) != 1:
        raise TeamError("TRUST_UNAVAILABLE")
    pin = matches[0]
    try:
        key = load_pem_public_key(pin.public_key_pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError
        key.verify(bytes.fromhex(signature), signing_bytes(payload))
    except (ValueError, TypeError, InvalidSignature):
        raise TeamError("SIGNATURE_INVALID") from None
    if payload.issued_at > now or payload.issued_at < pin.not_before:
        raise TeamError("SIGNATURE_INVALID")
    if isinstance(payload, FederationPayload) and now >= payload.expires_at:
        raise TeamError("SIGNATURE_INVALID")
    return pin
