"""Pure restrictive verification with independently pinned Ed25519 public keys."""

from datetime import datetime
from typing import Literal, Protocol

from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.supply_chain.models import Candidate, Signature, TrustAssessment, TrustLock

SignatureStatus = Literal["VERIFIED", "INVALID", "UNSUPPORTED"]


class SignatureVerifier(Protocol):
    def verify(self, public_key: bytes, subject: bytes, signature: bytes) -> SignatureStatus: ...


class Ed25519Verifier:
    """Only pinned raw public keys; no certificates, key URLs or candidate-supplied roots."""

    def verify(self, public_key: bytes, subject: bytes, signature: bytes) -> SignatureStatus:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            return "UNSUPPORTED"
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, subject)
            return "VERIFIED"
        except (InvalidSignature, ValueError):
            return "INVALID"


def signed_bytes(proof: Signature) -> bytes:
    return canonical_json(
        {
            "domain": "agentsec.supply-chain-signature.v1",
            "schema_version": "0.1",
            "candidate_id": proof.candidate_id,
            "subject_digest": proof.subject_digest,
            "key_id": proof.key_id,
            "algorithm": proof.algorithm,
            "issued_at": proof.issued_at,
            "expires_at": proof.expires_at,
        }
    ).encode("utf-8")


def assess(
    candidate: Candidate,
    lock: TrustLock,
    now: datetime,
    proof: Signature | None = None,
    *,
    verifier: SignatureVerifier | None = None,
) -> TrustAssessment:
    reasons = []
    pin = next((p for p in lock.pins if p.candidate_id == candidate.candidate_id), None)
    signature: str = "NOT_CHECKED"
    matched = "UNKNOWN"
    if lock.status != "REVIEWED":
        reasons.append("TRUST_LOCK_UNREVIEWED")
    if pin is None:
        reasons.append("TRUST_TOOL_UNLISTED")
    else:
        matched = "MATCH" if pin.fingerprint == candidate.fingerprint else "MISMATCH"
        if matched == "MISMATCH":
            reasons.append("TRUST_PIN_MISMATCH")
        if pin.require_artifact:
            if candidate.artifact_digest is None:
                reasons.append("TRUST_ARTIFACT_UNOBSERVED")
            # A candidate-ID-to-path mapping proves only that some bytes were observed.
            # No supported adapter binds those bytes to its executing callable/process.
            reasons.append("TRUST_ARTIFACT_ASSOCIATION_UNVERIFIABLE")
        if pin.require_dependencies:
            # A manifest digest never proves complete resolved dependency bytes.
            reasons.append("TRUST_DEPENDENCY_COVERAGE_INCOMPLETE")
        if pin.require_runtime_attestation:
            reasons.append("TRUST_RUNTIME_FRESHNESS_UNVERIFIABLE")
        if pin.required_signer:
            key = next(k for k in lock.keys if k.key_id == pin.required_signer)
            signature = "INVALID"
            if (
                proof is None
                or proof.key_id != key.key_id
                or proof.candidate_id != candidate.candidate_id
                or proof.subject_digest != candidate.fingerprint
            ):
                reasons.append("TRUST_SIGNATURE_INVALID")
            elif not proof.issued_at <= now < proof.expires_at:
                reasons.append("TRUST_SIGNATURE_STALE")
            else:
                signature = (verifier or Ed25519Verifier()).verify(
                    bytes.fromhex(key.public_key_hex),
                    signed_bytes(proof),
                    bytes.fromhex(proof.signature_hex),
                )
                if signature != "VERIFIED":
                    reasons.append(
                        "TRUST_SIGNATURE_UNSUPPORTED"
                        if signature == "UNSUPPORTED"
                        else "TRUST_SIGNATURE_INVALID"
                    )
    return TrustAssessment.model_validate(
        dict(
            schema_version="0.1",
            candidate_id=candidate.candidate_id,
            fingerprint=candidate.fingerprint,
            lock_digest=content_digest(lock),
            admitted=not reasons,
            metadata_pin=matched,
            artifact=candidate.implementation_proof,
            signature=signature,
            completeness="INCOMPLETE" if reasons else "COMPLETE_FOR_REQUIREMENTS",
            reason_codes=tuple(sorted(reasons)),
        )
    )
