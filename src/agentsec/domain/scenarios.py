"""Static deterministic evaluation specifications. No executors or provider integration."""

from typing import Annotated, Literal, Self

from pydantic import Field, JsonValue, ValidationInfo, field_validator, model_validator
from pydantic_core import PydanticCustomError

from agentsec.domain.base import (
    CapabilityId,
    Count,
    Identifier,
    NonEmpty,
    SecurityModel,
    VersionedModel,
)
from agentsec.domain.identity import TaskScope
from agentsec.domain.provenance import DataArtifactRef
from agentsec.domain.taxonomy import DataLabel, ReasonCode, SecurityCategory, TrustClass
from agentsec.domain.tools import ToolDescriptor


class ToolNotCalled(SecurityModel):
    type: Literal["TOOL_NOT_CALLED"]
    tool_id: Identifier


class ToolCalled(SecurityModel):
    type: Literal["TOOL_CALLED"]
    tool_id: Identifier


class CapabilityNotRequested(SecurityModel):
    type: Literal["CAPABILITY_NOT_REQUESTED"]
    capability: CapabilityId


class OutputNotContainsCanary(SecurityModel):
    type: Literal["OUTPUT_NOT_CONTAINS_CANARY"]
    canary_id: Identifier


class ApprovalRequired(SecurityModel):
    type: Literal["APPROVAL_REQUIRED"]
    capability: CapabilityId


class MaxToolCalls(SecurityModel):
    type: Literal["MAX_TOOL_CALLS"]
    maximum: Count


class RunTerminatedReason(SecurityModel):
    type: Literal["RUN_TERMINATED_REASON"]
    reason: ReasonCode


class NoFindingCategory(SecurityModel):
    type: Literal["NO_FINDING_CATEGORY"]
    category: SecurityCategory


class FindingCategoryPresent(SecurityModel):
    type: Literal["FINDING_CATEGORY_PRESENT"]
    category: SecurityCategory


Assertion = Annotated[
    ToolNotCalled
    | ToolCalled
    | CapabilityNotRequested
    | OutputNotContainsCanary
    | ApprovalRequired
    | MaxToolCalls
    | RunTerminatedReason
    | NoFindingCategory
    | FindingCategoryPresent,
    Field(discriminator="type"),
]


class ExpectedToolCalled(SecurityModel):
    type: Literal["EXPECTED_TOOL_CALLED"]
    tool_id: Identifier


class OutputContains(SecurityModel):
    type: Literal["OUTPUT_CONTAINS"]
    text: NonEmpty


UtilityAssertion = Annotated[ExpectedToolCalled | OutputContains, Field(discriminator="type")]


class Canary(SecurityModel):
    canary_id: Identifier
    value: NonEmpty


class MockResponse(SecurityModel):
    tool_id: Identifier
    response: JsonValue


class ScenarioSetup(SecurityModel):
    tools: tuple[ToolDescriptor, ...] = ()
    data_artifacts: tuple[DataArtifactRef, ...] = ()
    mock_responses: tuple[MockResponse, ...] = ()
    canaries: tuple[Canary, ...] = ()
    initial_memory: tuple[Identifier, ...] = ()


class ScenarioTask(SecurityModel):
    task_id: Identifier
    user_input: NonEmpty
    task_scope: TaskScope | None = None

    @field_validator("task_scope")
    @classmethod
    def scope_matches_task(cls, value: TaskScope | None, info: ValidationInfo) -> TaskScope | None:
        task_id = info.data.get("task_id")
        if value is not None and value.task_id != task_id:
            raise PydanticCustomError("INVALID_SCHEMA", "Task scope task ID differs")
        return value


class Injection(SecurityModel):
    source: Identifier
    location: NonEmpty
    content: NonEmpty | None = None
    fixture_ref: Identifier | None = None
    trust_class: TrustClass
    labels: frozenset[DataLabel] = frozenset()

    @model_validator(mode="after")
    def exactly_one_source(self) -> Self:
        if (self.content is None) == (self.fixture_ref is None):
            raise PydanticCustomError(
                "INVALID_SCHEMA", "Provide content or fixture_ref, exclusively"
            )
        return self


class Scenario(VersionedModel):
    scenario_id: Identifier
    title: NonEmpty
    description: NonEmpty | None = None
    attack_family: SecurityCategory
    tags: frozenset[Identifier] = frozenset()
    setup: ScenarioSetup
    task: ScenarioTask
    injections: tuple[Injection, ...] = ()
    assertions: Annotated[tuple[Assertion, ...], Field(min_length=1)]
    utility_assertions: tuple[UtilityAssertion, ...] = ()

    @model_validator(mode="after")
    def references(self) -> Self:
        tools = {t.tool_id for t in self.setup.tools}
        artifacts = {a.artifact_id for a in self.setup.data_artifacts}
        canaries = {c.canary_id for c in self.setup.canaries}
        if (
            len(tools) != len(self.setup.tools)
            or len(artifacts) != len(self.setup.data_artifacts)
            or len(canaries) != len(self.setup.canaries)
        ):
            raise PydanticCustomError("DUPLICATE_ID", "Duplicate setup ID")
        for assertion in (*self.assertions, *self.utility_assertions):
            if (
                isinstance(assertion, (ToolNotCalled, ToolCalled, ExpectedToolCalled))
                and assertion.tool_id not in tools
            ):
                raise PydanticCustomError("INVALID_SCHEMA", "Assertion references unknown tool")
            if (
                isinstance(assertion, OutputNotContainsCanary)
                and assertion.canary_id not in canaries
            ):
                raise PydanticCustomError("INVALID_SCHEMA", "Assertion references unknown canary")
        if any(r.tool_id not in tools for r in self.setup.mock_responses):
            raise PydanticCustomError("INVALID_SCHEMA", "Mock response references unknown tool")
        if any(ref not in artifacts for ref in self.setup.initial_memory):
            raise PydanticCustomError(
                "INVALID_SCHEMA", "Initial memory references unknown artifact"
            )
        return self
