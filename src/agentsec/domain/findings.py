"""Interpreted security results reference evidence without requiring raw content."""

from agentsec.domain.base import Identifier, NonEmpty, VersionedModel
from agentsec.domain.taxonomy import SecurityCategory, Severity


class Finding(VersionedModel):
    finding_id: Identifier
    category: SecurityCategory
    severity: Severity
    title: NonEmpty
    description: NonEmpty
    run_id: Identifier | None = None
    scenario_id: Identifier | None = None
    event_refs: frozenset[Identifier] = frozenset()
    artifact_refs: frozenset[Identifier] = frozenset()
    expected: NonEmpty | None = None
    observed: NonEmpty | None = None
    remediation_hint: NonEmpty | None = None
