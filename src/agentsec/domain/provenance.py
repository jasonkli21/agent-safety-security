"""Content-free provenance references; immutable references for tracked provenance."""

from agentsec.domain.base import Digest, Identifier, SecurityModel, Timestamp, VersionedModel
from agentsec.domain.taxonomy import DataLabel, TrustClass


class DataOrigin(SecurityModel):
    origin_type: Identifier
    source_id: Identifier | None = None
    trust_class: TrustClass


class DataArtifactRef(VersionedModel):
    artifact_id: Identifier
    labels: frozenset[DataLabel]
    origin: DataOrigin
    parent_artifact_ids: frozenset[Identifier] = frozenset()
    content_hash: Digest | None = None
    created_at: Timestamp | None = None


def canonical_artifacts(value: tuple[DataArtifactRef, ...]) -> tuple[DataArtifactRef, ...]:
    """Artifact identity is unique within one trusted policy/action context."""
    if len({ref.artifact_id for ref in value}) != len(value):
        raise ValueError("DUPLICATE_ARTIFACT_ID")
    return tuple(sorted(value, key=lambda ref: ref.artifact_id))
