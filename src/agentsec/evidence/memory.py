"""Copy-safe ordered in-memory capture."""

from agentsec.domain.events import SecurityEvent


class InMemoryEventSink:
    def __init__(self) -> None:
        self._events: list[SecurityEvent] = []

    def append(self, event: SecurityEvent) -> None:
        self._events.append(event.model_copy(deep=True))

    @property
    def events(self) -> tuple[SecurityEvent, ...]:
        return tuple(e.model_copy(deep=True) for e in self._events)
