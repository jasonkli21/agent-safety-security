"""Bounded offline observations: no invocation, import, resolution or key fetching."""

import hashlib
import os
import stat
import tomllib
from pathlib import Path

from agentsec.domain.execution import ExecutionBinding
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import SideEffectClass
from agentsec.domain.tools import ToolDescriptor
from agentsec.runtime.models import RuntimeFailure
from agentsec.supply_chain.models import (
    Candidate,
    Change,
    Dependency,
    DependencyManifest,
    Inventory,
    InventoryDiff,
    RiskFinding,
    ScanReport,
    TrustLock,
    TrustPin,
)

MAX_BYTES = 1024 * 1024


def read_local(path: Path, limit: int = MAX_BYTES) -> bytes:
    """Reject every symlink component and non-regular file; bound read and safe diagnostics.

    Parent-directory replacement by a privileged concurrent writer is outside this local
    inspection guarantee. These bytes are never described as executed-code attestation.
    """
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeFailure("TRUST_PATH_INVALID")
    try:
        for parent in (*reversed(path.parents), path):
            if parent.is_symlink():
                raise RuntimeFailure("TRUST_PATH_INVALID")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise RuntimeFailure("TRUST_INPUT_INVALID")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if len(data) > limit or (before.st_size, before.st_mtime_ns) != (
                after.st_size,
                after.st_mtime_ns,
            ):
                raise RuntimeFailure("TRUST_INPUT_CHANGED")
            return data
    except OSError as exc:
        raise RuntimeFailure("TRUST_INPUT_UNAVAILABLE") from exc


def artifact_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(read_local(path)).hexdigest()


def observe(
    tool: ToolDescriptor,
    route: ExecutionBinding | None,
    *,
    classification: object,
    labels_complete: bool,
) -> Candidate:
    """Hash full observed material without retaining raw description, paths or credentials."""
    if len(tool.model_dump_json(round_trip=True).encode()) > MAX_BYTES:
        raise RuntimeFailure("TRUST_INPUT_INVALID")
    return Candidate(
        schema_version="0.1",
        candidate_id=content_digest(
            {
                "domain": "agentsec.qualified-tool.v1",
                "namespace": tool.namespace,
                "server": tool.server_id,
                "tool": tool.tool_id,
                "adapter_kind": route.adapter_kind if route else None,
                "adapter_id": route.adapter_id if route else None,
            }
        ),
        source="mcp_discovery" if tool.protocol == "mcp" else "protected_registration",
        schema_digest=tool.schema_hash,
        description_digest=tool.description_hash,
        metadata_digest=content_digest({"domain": "agentsec.metadata.v1", "tool": tool}),
        route_digest=content_digest({"domain": "agentsec.route.v1", "route": route}),
        classification_digest=content_digest(
            {"domain": "agentsec.classification.v1", "classification": classification}
        ),
        side_effect=tool.side_effect_class,
        labels_complete=labels_complete,
        injection_marker=any(
            marker in tool.description.casefold()
            for marker in ("ignore previous instructions", "override security", "reveal secrets")
        ),
    )


def declared_dependencies(path: Path) -> DependencyManifest:
    try:
        data = tomllib.loads(read_local(path).decode("utf-8"))
        declarations = data.get("project", {}).get("dependencies", [])
        optional = data.get("project", {}).get("optional-dependencies", {})
        if (
            not isinstance(declarations, list)
            or not isinstance(optional, dict)
            or any(not isinstance(group, list) for group in optional.values())
        ):
            raise ValueError
        declarations = [*declarations, *(d for group in optional.values() for d in group)]
        if len(declarations) > 2048 or any(not isinstance(d, str) for d in declarations):
            raise ValueError
        # Opaque declaration identities avoid parsing requirements incompletely or leaking URLs.
        dependencies = tuple(
            Dependency(
                schema_version="0.1",
                name="decl-" + content_digest(d)[7:],
                declaration_digest=content_digest(d),
            )
            for d in sorted(set(declarations))
        )
        return DependencyManifest(
            schema_version="0.1", source="local_pyproject", dependencies=dependencies
        )
    except (ValueError, TypeError, AttributeError, UnicodeError) as exc:
        raise RuntimeFailure("TRUST_DEPENDENCIES_INVALID") from exc


def propose(inventory: Inventory, generation: str) -> TrustLock:
    return TrustLock(
        schema_version="0.1",
        status="PROPOSED",
        generation=generation,
        pins=tuple(
            TrustPin(schema_version="0.1", candidate_id=c.candidate_id, fingerprint=c.fingerprint)
            for c in inventory.candidates
        ),
    )


def diff(before: Inventory, after: Inventory) -> InventoryDiff:
    left = {c.candidate_id: c for c in before.candidates}
    right = {c.candidate_id: c for c in after.candidates}
    changes = []
    for target in sorted(left.keys() | right.keys()):
        if target not in left or target not in right:
            changes.append(
                Change(
                    schema_version="0.1",
                    target=target,
                    status="ADDED" if target in right else "REMOVED",
                )
            )
            continue
        a, b = left[target], right[target]
        fields = tuple(
            field for field in Candidate.model_fields if getattr(a, field) != getattr(b, field)
        )
        if fields:
            changes.append(
                Change(schema_version="0.1", target=target, status="CHANGED", fields=fields)
            )
        elif b.artifact_digest is None or b.dependency_digest is None:
            changes.append(Change(schema_version="0.1", target=target, status="INCOMPLETE"))
    before_proofs = {p.candidate_id: content_digest(p) for p in before.signatures}
    after_proofs = {p.candidate_id: content_digest(p) for p in after.signatures}
    for target in sorted(before_proofs.keys() | after_proofs.keys()):
        if before_proofs.get(target) != after_proofs.get(target):
            changes.append(
                Change(
                    schema_version="0.1",
                    target=target,
                    status="CHANGED",
                    fields=("signature_provenance",),
                )
            )
    return InventoryDiff(schema_version="0.1", changes=tuple(changes))


def scan(inventory: Inventory, baseline: TrustLock | None = None) -> ScanReport:
    findings = []
    for c in inventory.candidates:
        rules = [
            (
                c.side_effect != SideEffectClass.NONE,
                "SC001",
                "HIGH",
                "side_effect",
                "PRIVILEGED_ACTION",
            ),
            (
                not c.labels_complete,
                "SC002",
                "MEDIUM",
                "labels_complete",
                "CLASSIFICATION_INCOMPLETE",
            ),
            (
                c.artifact_digest is None,
                "SC003",
                "MEDIUM",
                "artifact_digest",
                "IMPLEMENTATION_UNOBSERVED",
            ),
            (
                c.dependency_digest is None,
                "SC004",
                "LOW",
                "dependency_digest",
                "DEPENDENCIES_UNOBSERVED",
            ),
            (c.injection_marker, "SC005", "HIGH", "metadata_digest", "INSTRUCTION_MARKER"),
        ]
        if baseline is not None:
            pin = next((p for p in baseline.pins if p.candidate_id == c.candidate_id), None)
            rules.extend(
                [
                    (pin is None, "SC006", "HIGH", "candidate_id", "CANDIDATE_UNPINNED"),
                    (
                        pin is not None and pin.fingerprint != c.fingerprint,
                        "SC007",
                        "HIGH",
                        "route_digest",
                        "REVIEWED_MATERIAL_DRIFT",
                    ),
                ]
            )
        for active, rule, severity, field, rationale in rules:
            if active:
                findings.append(
                    RiskFinding.model_validate(
                        dict(
                            schema_version="0.1",
                            rule_id=rule,
                            severity=severity,
                            target=c.candidate_id,
                            field_path=field,
                            rationale=rationale,
                            evidence_digest=c.fingerprint,
                        )
                    )
                )
    return ScanReport(schema_version="0.1", findings=tuple(findings))
