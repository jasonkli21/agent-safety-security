"""Operator-owned admission and synchronous final freshness. No authorization logic."""

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from threading import get_ident

from agentsec.domain.serialization import content_digest
from agentsec.runtime.models import RuntimeFailure
from agentsec.supply_chain.inspection import artifact_digest
from agentsec.supply_chain.models import (
    Candidate,
    DependencyManifest,
    Signature,
    TrustAssessment,
    TrustLock,
)
from agentsec.supply_chain.verification import assess


class TrustGuard:
    def __init__(
        self,
        lock: TrustLock,
        *,
        signatures: tuple[Signature, ...] = (),
        artifacts: Mapping[str, Path] | None = None,
        dependencies: DependencyManifest | None = None,
    ) -> None:
        self.__owner = get_ident()
        self.__lock = TrustLock.model_validate_json(lock.model_dump_json())
        if len({s.candidate_id for s in signatures}) != len(signatures):
            raise RuntimeFailure("TRUST_SIGNATURE_DUPLICATE")
        self.__signatures = tuple(
            Signature.model_validate_json(s.model_dump_json()) for s in signatures
        )
        self.__artifacts = dict(artifacts or {})
        self.__dependencies = (
            DependencyManifest.model_validate_json(dependencies.model_dump_json())
            if dependencies
            else None
        )
        self.__epoch = 0

    def replace_lock(self, lock: TrustLock) -> None:
        """Protected operator operation, never exposed to tools or candidate discovery."""
        self.__assert_owner()
        self.__lock = TrustLock.model_validate_json(lock.model_dump_json())
        self.__epoch += 1

    @property
    def required_candidates(self) -> tuple[str, ...]:
        self.__assert_owner()
        return self.__lock.required_candidates

    def __assert_owner(self) -> None:
        if get_ident() != self.__owner:
            raise RuntimeFailure("TRUST_THREAD_MISMATCH")

    def observe(self, candidate: Candidate) -> Candidate:
        self.__assert_owner()
        path = self.__artifacts.get(candidate.candidate_id)
        updates: dict[str, object] = {}
        if path is not None:
            updates.update(
                artifact_digest=artifact_digest(path), implementation_proof="LOCAL_BYTES"
            )
        if self.__dependencies is not None:
            updates["dependency_digest"] = content_digest(self.__dependencies)
        return Candidate.model_validate(candidate.model_dump() | updates)

    def check(self, candidate: Candidate, now: datetime) -> tuple[str, TrustAssessment]:
        candidate = self.observe(candidate)
        proof = next(
            (p for p in self.__signatures if p.candidate_id == candidate.candidate_id), None
        )
        result = assess(candidate, self.__lock, now, proof)
        snapshot = content_digest(
            {
                "domain": "agentsec.trust-snapshot.v1",
                "epoch": self.__epoch,
                "assessment": result,
                "signature": proof,
            }
        )
        return snapshot, result

    def final(self, candidate: Candidate, snapshot: str, now: datetime) -> TrustAssessment:
        current, assessment = self.check(candidate, now)
        if current != snapshot:
            raise RuntimeFailure("TRUST_REGISTRY_STALE")
        return assessment
