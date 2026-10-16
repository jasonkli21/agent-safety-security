"""Immutable lineage and causally compacted exposed-context frontier.

Synchronous locked operations never hold a lock across async/network/human I/O.
The release callback records critical evidence before the frontier commits.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from threading import RLock
from uuid import uuid4

from agentsec.domain.provenance import DataArtifactRef, DataOrigin
from agentsec.domain.taxonomy import DataLabel


class ProvenanceError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ProvenanceEngine:
    def __init__(
        self,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        id_factory: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        self._clock, self._id_factory = clock, id_factory
        self._nodes: dict[str, DataArtifactRef] = {}
        self._frontier: set[str] = set()
        self._exposed: set[str] = set()
        self._lock = RLock()

    def register(self, artifact: DataArtifactRef) -> DataArtifactRef:
        # Revalidate even models copied with unchecked model_copy(update=...).
        artifact = DataArtifactRef.model_validate_json(artifact.model_dump_json())
        with self._lock:
            if artifact.artifact_id in self._nodes:
                raise ProvenanceError("DUPLICATE_ARTIFACT_ID")
            parents = self._parents(artifact.parent_artifact_ids)
            if not frozenset(label for p in parents for label in p.labels) <= artifact.labels:
                raise ProvenanceError("NON_MONOTONIC_LABELS")
            self._nodes[artifact.artifact_id] = artifact
            return artifact

    def _parents(self, ids: frozenset[str]) -> tuple[DataArtifactRef, ...]:
        if not ids <= self._nodes.keys():
            raise ProvenanceError("UNKNOWN_PARENT_ARTIFACT")
        return tuple(self._nodes[id] for id in sorted(ids))

    def derive(
        self,
        origin: DataOrigin,
        *,
        parents: tuple[DataArtifactRef, ...] = (),
        labels: frozenset[DataLabel] = frozenset(),
        content_hash: str | None = None,
    ) -> DataArtifactRef:
        with self._lock:
            if any(self._nodes.get(p.artifact_id) != p for p in parents):
                raise ProvenanceError("UNTRUSTED_PARENT_ARTIFACT")
            return self.register(
                DataArtifactRef(
                    schema_version="0.1",
                    artifact_id=self._id_factory(),
                    origin=origin,
                    parent_artifact_ids=frozenset(p.artifact_id for p in parents),
                    labels=labels | frozenset(label for p in parents for label in p.labels),
                    content_hash=content_hash,
                    created_at=self._clock(),
                )
            )

    def get(self, artifact_id: str) -> DataArtifactRef:
        with self._lock:
            if artifact_id not in self._nodes:
                raise ProvenanceError("UNKNOWN_ARTIFACT")
            return self._nodes[artifact_id]

    def lineage(self, artifact_id: str) -> tuple[DataArtifactRef, ...]:
        with self._lock:
            pending = list(self.get(artifact_id).parent_artifact_ids)
            seen: set[str] = set()
            while pending:
                id = pending.pop()
                if id not in seen:
                    seen.add(id)
                    pending.extend(self._nodes[id].parent_artifact_ids)
            return tuple(self._nodes[id] for id in sorted(seen))

    def snapshot(self) -> tuple[DataArtifactRef, ...]:
        with self._lock:
            return tuple(self._nodes[id] for id in sorted(self._frontier))

    def expose(self, artifact: DataArtifactRef, record: Callable[[], None] = lambda: None) -> None:
        with self._lock:
            if self._nodes.get(artifact.artifact_id) != artifact:
                raise ProvenanceError("UNKNOWN_ARTIFACT")
            if artifact.artifact_id in self._exposed:
                raise ProvenanceError("DUPLICATE_EXPOSURE")
            record()
            # Only supersede this response's parents; concurrent branches survive.
            self._frontier.difference_update(artifact.parent_artifact_ids)
            self._frontier.add(artifact.artifact_id)
            self._exposed.add(artifact.artifact_id)
