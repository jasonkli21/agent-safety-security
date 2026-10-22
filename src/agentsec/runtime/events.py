"""Ordered evidence; sink failure poisons enforcing sessions."""

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from agentsec.domain.events import EventPayload, SecurityEvent
from agentsec.evidence.ports import EventSink
from agentsec.runtime.models import RuntimeFailure


class RuntimeEvents:
    def __init__(
        self,
        sink: EventSink,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        *,
        required: bool = True,
        on_failure: Callable[[], None] = lambda: None,
    ) -> None:
        self.sink, self.clock, self.required = sink, clock, required
        self.run_id, self.trace_id = str(uuid4()), str(uuid4())
        self.last_event: SecurityEvent | None = None
        self.sequence = 0
        self.failed = False
        self.on_failure = on_failure

    def emit(self, payload: EventPayload) -> None:
        if self.failed and self.required:
            raise RuntimeFailure("EVIDENCE_WRITE_FAILURE")
        event = SecurityEvent(
            schema_version="0.1",
            event_id=str(uuid4()),
            event_type=payload.kind,
            occurred_at=self.clock(),
            run_id=self.run_id,
            trace_id=self.trace_id,
            sequence=self.sequence,
            payload=payload,
        )
        self.sequence += 1
        try:
            self.sink.append(event)
            self.last_event = event
        except Exception as exc:
            self.failed = True
            try:
                self.on_failure()
            except Exception:
                # Failure notification is best-effort and cannot mask recorder poisoning.
                pass
            if self.required:
                raise RuntimeFailure("EVIDENCE_WRITE_FAILURE") from exc
