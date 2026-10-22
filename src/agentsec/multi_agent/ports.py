"""Runtime graph guard port, implemented only by protected session wiring."""

from datetime import datetime
from typing import Protocol

from agentsec.domain.graph import GraphBinding
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.taxonomy import DataLabel


class GraphGuard(Protocol):
    def snapshot(self, now: datetime) -> GraphBinding: ...
    def final(
        self, binding: GraphBinding, now: datetime, capability: str, resource: str | None
    ) -> None: ...
    def decide(self, request: PolicyRequest, now: datetime) -> PolicyDecision: ...
    def classifications(
        self,
        binding: GraphBinding,
        destination: str | None,
        labels: frozenset[DataLabel] | None,
    ) -> None: ...
    def approval_timeout(self, binding: GraphBinding) -> int: ...
    def close(self) -> None: ...
