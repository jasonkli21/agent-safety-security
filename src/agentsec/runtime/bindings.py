"""Immutable protected configuration and the shared adapter entry point."""

from collections.abc import Awaitable, Callable
from copy import deepcopy
from typing import Literal, Self

from pydantic import JsonValue, model_validator

from agentsec.domain.base import Identifier, NonEmpty, VersionedModel
from agentsec.domain.execution import ExecutionBinding
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import DataLabel, EnforcementMode
from agentsec.domain.tools import ToolDescriptor
from agentsec.runtime.arguments import check_local_schema, validate_arguments
from agentsec.runtime.coverage import binding_coverage
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure, ToolResponse


class ProtectedTool(VersionedModel):
    descriptor: ToolDescriptor
    execution_binding: ExecutionBinding
    resource_argument_path: tuple[NonEmpty, ...] | None = None
    resource_semantics: Literal["opaque_exact"] | None = None
    approval_display_paths: tuple[tuple[NonEmpty, ...], ...] = ()
    data_sink_destination: Identifier | None = None
    output_data_labels: frozenset[DataLabel] | None = None

    @model_validator(mode="after")
    def valid_binding(self) -> Self:
        if len(self.descriptor.capabilities) != 1:
            raise ValueError("Exactly one capability required")
        if self.resource_argument_path == () or any(not p for p in self.approval_display_paths):
            raise ValueError("Empty extraction/display path")
        if self.resource_semantics and self.resource_argument_path is None:
            raise ValueError("Resource semantics require extraction")
        if len(set(self.approval_display_paths)) != len(self.approval_display_paths):
            raise ValueError("Duplicate display path")
        check_local_schema(self.descriptor.input_schema)
        check_local_schema(self.descriptor.output_schema)
        return self


class ProtectedCall:
    """Only invocation enters the gateway; dispatcher and snapshots stay private."""

    def __init__(
        self,
        gateway: RuntimeGateway,
        tool: ProtectedTool,
        dispatch: Callable[[dict[str, JsonValue]], Awaitable[ToolResponse]],
    ) -> None:
        # Bind the entire classification/extraction configuration as well as transport identity.
        route = tool.execution_binding.model_copy(update={"binding_digest": content_digest(tool)})
        tool = tool.model_copy(update={"execution_binding": route})
        self.__tool_json = tool.model_dump_json(round_trip=True)
        self.__gateway = gateway
        self.__dispatch = dispatch
        capability = next(iter(tool.descriptor.capabilities))
        coverage = binding_coverage(gateway.plan, [(tool.descriptor.name, capability, tool)])
        self.__gap = bool(coverage.uncovered_tool_names)
        self.__data_gap = bool(coverage.data_uncovered_tool_names)
        if coverage.gaps and gateway.mode == EnforcementMode.ENFORCE:
            raise RuntimeFailure("ADAPTER_COVERAGE_GAP")

    @property
    def tool(self) -> ProtectedTool:
        return ProtectedTool.model_validate_json(self.__tool_json)

    def for_adapter(self, adapter_kind: str) -> "ProtectedCall":
        """Rebind a protected harness route without exposing the underlying dispatcher."""
        tool = self.tool
        route = tool.execution_binding.model_copy(update={"adapter_kind": adapter_kind})
        return ProtectedCall(
            self.__gateway, tool.model_copy(update={"execution_binding": route}), self.__dispatch
        )

    async def invoke(self, arguments: dict[str, JsonValue]) -> ToolResponse:
        tool = self.tool
        arguments = deepcopy(arguments)
        resource = validate_arguments(tool.descriptor, arguments, tool.resource_argument_path)
        return await self.__gateway.call(
            tool.descriptor,
            arguments,
            resource,
            self.__dispatch,
            bound=True,
            execution_binding=tool.execution_binding,
            approval_display_paths=tool.approval_display_paths,
            resource_coverage_gap=self.__gap,
            data_coverage_gap=self.__data_gap,
            data_destination=tool.data_sink_destination,
            output_data_labels=tool.output_data_labels,
        )
