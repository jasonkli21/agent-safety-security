"""Conservative interpretation of pre-entry dispatch admission evidence."""

from agentsec.domain.events import SecurityEvent, SecuritySignalPayload, ToolDispatchedPayload

DISPATCH_ABORTED = "DISPATCH_ABORTED_BEFORE_ENTRY"


def aborted_dispatch_ids(events: tuple[SecurityEvent, ...]) -> frozenset[str]:
    return frozenset(
        ref
        for event in events
        if isinstance(event.payload, SecuritySignalPayload)
        and event.payload.redacted_summary == DISPATCH_ABORTED
        for ref in event.payload.artifact_refs
    )


def dispatch_admissions(events: tuple[SecurityEvent, ...]) -> tuple[SecurityEvent, ...]:
    """Exclude known pre-entry aborts; remaining admissions still do not prove effects."""
    aborted = aborted_dispatch_ids(events)
    return tuple(
        event
        for event in events
        if isinstance(event.payload, ToolDispatchedPayload)
        and event.payload.dispatch_id not in aborted
    )
