"""Canonical UTF-8 event streams, with explicit line-numbered failures."""

from pathlib import Path
from types import TracebackType
from typing import TextIO

from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import MAX_BYTES, parse_document, validate_data
from agentsec.domain.events import SecurityEvent
from agentsec.domain.serialization import canonical_json


class EvidenceError(Exception):
    def __init__(self, code: str, line: int | None = None) -> None:
        self.code = code
        self.line = line
        super().__init__(f"{code}" + (f" at line {line}" if line is not None else ""))


class JsonlEventSink:
    """Create/truncate once; append events in order within this open stream."""

    def __init__(self, path: Path, *, exclusive: bool = False) -> None:
        try:
            self._stream: TextIO = path.open("x" if exclusive else "w", encoding="utf-8")
        except OSError as exc:
            raise EvidenceError("EVIDENCE_WRITE_FAILURE") from exc

    def append(self, event: SecurityEvent) -> None:
        try:
            self._stream.write(canonical_json(event) + "\n")
            self._stream.flush()
        except (OSError, UnicodeError, ValueError) as exc:
            raise EvidenceError("EVIDENCE_WRITE_FAILURE") from exc

    def close(self) -> None:
        try:
            self._stream.close()
        except OSError as exc:
            raise EvidenceError("EVIDENCE_WRITE_FAILURE") from exc

    def __enter__(self) -> "JsonlEventSink":
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def read_jsonl(path: Path, *, max_bytes: int | None = None) -> tuple[SecurityEvent, ...]:
    events = []
    line_number = 0
    total_bytes = 0
    try:
        with path.open("rb") as stream:
            while raw := stream.readline(MAX_BYTES + 1):
                line_number += 1
                total_bytes += len(raw)
                if max_bytes is not None and total_bytes > max_bytes:
                    raise EvidenceError("SOURCE_EVIDENCE_TOO_LARGE", line_number)
                line = raw.decode("utf-8")
                events.append(validate_data(SecurityEvent, parse_document(line, format="json")))
    except (OSError, UnicodeError, ArtifactValidationError) as exc:
        raise EvidenceError("EVIDENCE_READ_FAILURE", line_number or 1) from exc
    return tuple(events)
