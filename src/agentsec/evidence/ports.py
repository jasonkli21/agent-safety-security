"""Minimal synchronous evidence boundary; persistence belongs to later phases."""

from typing import Protocol

from agentsec.domain.events import SecurityEvent


class EventSink(Protocol):
    def append(self, event: SecurityEvent) -> None: ...
