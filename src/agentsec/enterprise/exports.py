"""Deterministic minimized JSONL and exact-byte signed offline verification."""

import hashlib
from datetime import datetime
from pathlib import Path

from agentsec.contracts.loader import parse_document, validate_data
from agentsec.control_plane.errors import TeamError
from agentsec.domain.serialization import canonical_json
from agentsec.enterprise.files import atomic_private_write
from agentsec.enterprise.models import (
    ExportManifest,
    ExportPage,
    SecurityRecord,
    SignedExport,
    TrustConfig,
)
from agentsec.enterprise.signatures import sign, verify, verify_archival_export


def file_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def jsonl_bytes(page: ExportPage) -> bytes:
    data = b"".join(canonical_json(r).encode("utf-8") + b"\n" for r in page.records)
    if len(data) > 1_048_576:
        raise TeamError("TOO_LARGE")
    return data


def sign_export(
    page: ExportPage, key_id: str, key: Path, now: datetime
) -> tuple[bytes, SignedExport]:
    data = jsonl_bytes(page)
    payload = ExportManifest(
        origin=page.cursor.org,
        target=page.cursor.org,
        key_id=key_id,
        issued_at=now,
        start_after=page.cursor.after - len(page.records),
        end=page.cursor.after,
        high_water=page.high_water,
        count=len(page.records),
        byte_length=len(data),
        file_digest=file_digest(data),
    )
    return data, SignedExport(payload=payload, signature=sign(payload, key))


def write_export(path: Path, manifest_path: Path, data: bytes, manifest: SignedExport) -> None:
    # A partial pair is never valid: the manifest is the completion marker.
    atomic_private_write(path, data)
    atomic_private_write(manifest_path, (canonical_json(manifest) + "\n").encode())


def verify_export(
    data: bytes,
    manifest: SignedExport,
    trust: TrustConfig,
    now: datetime,
    *,
    archival: bool = False,
) -> None:
    manifest = validate_data(
        SignedExport, parse_document(manifest.model_dump_json(), format="json")
    )
    if archival:
        verify_archival_export(manifest.payload, manifest.signature, trust, now)
    else:
        verify(manifest.payload, manifest.signature, trust, now)
    payload = manifest.payload
    if (
        len(data) != payload.byte_length
        or file_digest(data) != payload.file_digest
        or data.count(b"\n") != payload.count
    ):
        raise TeamError("SIGNATURE_INVALID")
    try:
        lines = data.decode("utf-8").splitlines()
        for expected, line in enumerate(lines, start=payload.start_after + 1):
            record = validate_data(SecurityRecord, parse_document(line, format="json"))
            if record.org != payload.origin or record.sequence != expected:
                raise ValueError
            if canonical_json(record) != line:
                raise ValueError
    except Exception:
        raise TeamError("SIGNATURE_INVALID") from None
