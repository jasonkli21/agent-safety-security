"""Synchronous canonical evidence boundary shared by memory and JSONL sinks."""

from typing import Protocol

from agentsec.domain.events import SecurityEvent


class EventSink(Protocol):
    def append(self, event: SecurityEvent) -> None: ...
