"""Content-free provenance references; propagation is deliberately deferred."""

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
