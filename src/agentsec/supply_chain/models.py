"""Content-free, immutable supply-chain facts; none of these facts grants authority."""

from typing import Literal, Self

from pydantic import Field, model_validator

from agentsec.domain.base import Digest, Identifier, Timestamp, VersionedModel
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import SideEffectClass


class Dependency(VersionedModel):
    name: Identifier
    declaration_digest: Digest
    provenance: Literal["declared", "resolved", "artifact_hashed"] = "declared"
    artifact_digest: Digest | None = None

    @model_validator(mode="after")
    def truthful(self) -> Self:
        if (self.provenance == "artifact_hashed") != (self.artifact_digest is not None):
            raise ValueError("TRUST_DEPENDENCY_PROOF_INVALID")
        return self


class DependencyManifest(VersionedModel):
    source: Literal["local_pyproject", "operator_declaration"]
    dependencies: tuple[Dependency, ...] = Field(default=(), max_length=2048)
    completeness: Literal["DECLARED_ONLY", "INCOMPLETE"] = "DECLARED_ONLY"

    @model_validator(mode="after")
    def ordered(self) -> Self:
        names = [d.name for d in self.dependencies]
        if len(names) != len(set(names)):
            raise ValueError("TRUST_DUPLICATE_DEPENDENCY")
        object.__setattr__(
            self, "dependencies", tuple(sorted(self.dependencies, key=lambda d: d.name))
        )
        return self


class Candidate(VersionedModel):
    candidate_id: Digest
    source: Literal["mcp_discovery", "protected_registration"]
    schema_digest: Digest
    description_digest: Digest
    metadata_digest: Digest
    route_digest: Digest
    classification_digest: Digest
    dependency_digest: Digest | None = None
    artifact_digest: Digest | None = None
    side_effect: SideEffectClass
    labels_complete: bool
    injection_marker: bool = False
    # These are observations/claims, never proof of loaded or remote running code.
    implementation_proof: Literal["UNOBSERVED", "LOCAL_BYTES"] = "UNOBSERVED"

    @model_validator(mode="after")
    def truthful(self) -> Self:
        if (self.implementation_proof == "LOCAL_BYTES") != (self.artifact_digest is not None):
            raise ValueError("TRUST_ARTIFACT_PROOF_INVALID")
        return self

    @property
    def fingerprint(self) -> str:
        return content_digest({"domain": "agentsec.candidate.v1", "candidate": self})


class Signature(VersionedModel):
    candidate_id: Digest
    subject_digest: Digest
    key_id: Identifier
    algorithm: Literal["Ed25519"]
    issued_at: Timestamp
    expires_at: Timestamp
    signature_hex: str = Field(pattern=r"^[0-9a-f]{128}$")

    @model_validator(mode="after")
    def valid_window(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("TRUST_SIGNATURE_WINDOW_INVALID")
        return self


class Inventory(VersionedModel):
    candidates: tuple[Candidate, ...] = Field(max_length=2048)
    signatures: tuple[Signature, ...] = Field(default=(), max_length=2048)

    @model_validator(mode="after")
    def unique(self) -> Self:
        proof_ids = [p.candidate_id for p in self.signatures]
        if len(proof_ids) != len(set(proof_ids)):
            raise ValueError("TRUST_SIGNATURE_DUPLICATE")
        object.__setattr__(
            self, "signatures", tuple(sorted(self.signatures, key=lambda p: p.candidate_id))
        )
        ids = [c.candidate_id for c in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("TRUST_DUPLICATE_CANDIDATE")
        object.__setattr__(
            self, "candidates", tuple(sorted(self.candidates, key=lambda c: c.candidate_id))
        )
        return self


class TrustedKey(VersionedModel):
    key_id: Identifier
    public_key_hex: str = Field(pattern=r"^[0-9a-f]{64}$")


class TrustPin(VersionedModel):
    candidate_id: Digest
    fingerprint: Digest
    require_artifact: bool = False
    require_dependencies: bool = False
    required_signer: Identifier | None = None
    require_runtime_attestation: bool = False


class TrustLock(VersionedModel):
    status: Literal["PROPOSED", "REVIEWED"]
    generation: Identifier
    pins: tuple[TrustPin, ...] = Field(max_length=2048)
    keys: tuple[TrustedKey, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def unique(self) -> Self:
        ids = [p.candidate_id for p in self.pins]
        keys = [k.key_id for k in self.keys]
        if len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
            raise ValueError("TRUST_LOCK_DUPLICATE")
        if any(p.required_signer not in keys for p in self.pins if p.required_signer):
            raise ValueError("TRUST_SIGNER_UNCONFIGURED")
        object.__setattr__(self, "pins", tuple(sorted(self.pins, key=lambda p: p.candidate_id)))
        object.__setattr__(self, "keys", tuple(sorted(self.keys, key=lambda k: k.key_id)))
        return self


class TrustAssessment(VersionedModel):
    candidate_id: Digest
    fingerprint: Digest
    lock_digest: Digest
    admitted: bool
    metadata_pin: Literal["MATCH", "MISMATCH", "UNKNOWN"]
    artifact: Literal["LOCAL_BYTES", "UNOBSERVED"]
    signature: Literal["VERIFIED", "INVALID", "UNSUPPORTED", "NOT_CHECKED"]
    completeness: Literal["COMPLETE_FOR_REQUIREMENTS", "INCOMPLETE"]
    reason_codes: tuple[Identifier, ...]


class Change(VersionedModel):
    target: Digest
    status: Literal["ADDED", "REMOVED", "CHANGED", "INCOMPLETE"]
    fields: tuple[Identifier, ...] = ()


class InventoryDiff(VersionedModel):
    changes: tuple[Change, ...]


class RiskFinding(VersionedModel):
    rule_id: Identifier
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    target: Digest
    field_path: Identifier
    rationale: Identifier
    evidence_digest: Digest


class ScanReport(VersionedModel):
    findings: tuple[RiskFinding, ...]


class ArtifactInput(VersionedModel):
    candidate_id: Digest
    # Protected local input, never copied into inventory/evidence/diagnostics.
    path: str = Field(min_length=1, max_length=8192)

    @model_validator(mode="after")
    def valid_path(self) -> Self:
        from pathlib import Path

        if (
            not Path(self.path).is_absolute()
            or ".." in Path(self.path).parts
            or "\x00" in self.path
        ):
            raise ValueError("TRUST_PATH_INVALID")
        return self


class TrustInputs(VersionedModel):
    signatures: tuple[Signature, ...] = Field(default=(), max_length=2048)
    artifacts: tuple[ArtifactInput, ...] = Field(default=(), max_length=2048)
    dependencies: DependencyManifest | None = None

    @model_validator(mode="after")
    def unique(self) -> Self:
        for items in (self.signatures, self.artifacts):
            ids = [item.candidate_id for item in items]
            if len(ids) != len(set(ids)):
                raise ValueError("TRUST_INPUT_DUPLICATE")
        return self
