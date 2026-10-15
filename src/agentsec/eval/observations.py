"""Ephemeral raw capture, deliberately excluded from report models."""

from enum import StrEnum

from agentsec.domain.base import Identifier, SecurityModel
from agentsec.domain.events import SecurityEvent
from agentsec.domain.findings import Finding


class TextSurface(StrEnum):
    FINAL_OUTPUT = "FINAL_OUTPUT"
    EXTERNAL_SINK = "EXTERNAL_SINK"
    TOOL_ARGUMENT = "TOOL_ARGUMENT"


class ObservationCoverage(SecurityModel):
    event_stream_complete: bool = False
    final_output_complete: bool = False
    external_sink_capture_complete: bool = False
    finding_set_complete: bool = False
    tool_arguments_complete: bool = False


class TextObservation(SecurityModel):
    surface: TextSurface
    source_id: Identifier
    text: str
    argument_values: tuple[str, ...] | None = None

    def contains(self, value: str) -> bool:
        values = (self.text, *(self.argument_values or ()))
        return any(value in text for text in values)


class EvaluationObservation(SecurityModel):
    scenario_id: Identifier
    run_id: Identifier
    trace_id: Identifier
    events: tuple[SecurityEvent, ...]
    text_observations: tuple[TextObservation, ...] = ()
    findings: tuple[Finding, ...] = ()
    coverage: ObservationCoverage = ObservationCoverage()
