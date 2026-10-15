"""Narrow synchronous target boundary with injectable infrastructure."""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol
from uuid import uuid4

from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.scenarios import Scenario
from agentsec.eval.observations import EvaluationObservation
from agentsec.evidence.memory import InMemoryEventSink


def utc_now() -> datetime:
    return datetime.now(UTC)


def random_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


@dataclass
class EvaluationContext:
    clock: Callable[[], datetime] = utc_now
    new_id: Callable[[str], str] = random_id
    recorder: InMemoryEventSink = field(default_factory=InMemoryEventSink)
    run_id: str = ""
    trace_id: str = ""


class AgentTarget(Protocol):
    def run(
        self, *, contract: AgentSecurityContract, scenario: Scenario, context: EvaluationContext
    ) -> EvaluationObservation: ...
