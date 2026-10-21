"""Structured coding/process actions. Executable, cwd, env and backend are protected."""

from typing import Self

from pydantic import Field, JsonValue, model_validator

from agentsec.domain.base import Identifier, NonEmpty, VersionedModel
from agentsec.domain.execution import ExecutionBinding
from agentsec.domain.serialization import content_digest
from agentsec.isolation.backends import IsolationBackend
from agentsec.isolation.process import ProcessRequest
from agentsec.runtime.bindings import ProtectedCall, ProtectedTool
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure, ToolResponse


class ProcessAction(VersionedModel):
    adapter_id: Identifier
    request: ProcessRequest
    argument_slots: tuple[Identifier, ...] = ()
    trusted_effect_resource: NonEmpty | None = Field(
        default=None,
        description=(
            "Reviewed operator assertion of the configured executable's fixed effect target."
        ),
    )

    @model_validator(mode="after")
    def unique_slots(self) -> Self:
        if len(set(self.argument_slots)) != len(self.argument_slots):
            raise ValueError("Duplicate argument slot")
        return self


def protect_process(
    gateway: RuntimeGateway, tool: ProtectedTool, config: ProcessAction, backend: IsolationBackend
) -> ProtectedCall:
    config = ProcessAction.model_validate_json(config.model_dump_json())
    identity = backend.identity_digest
    binding = ExecutionBinding(
        schema_version="0.1",
        adapter_kind="process",
        adapter_id=config.adapter_id,
        adapter_version="2",
        binding_digest=content_digest(config),
        isolation_digest=identity,
    )
    tool = tool.model_copy(update={"execution_binding": binding})
    tool = tool.model_copy(update={"trusted_effect_resource": config.trusted_effect_resource})
    if tool.resource_argument_path is not None and (
        len(tool.resource_argument_path) != 1
        or tool.resource_argument_path[0] not in config.argument_slots
    ):
        raise RuntimeFailure("ADAPTER_RESOURCE_MAPPING_INVALID")

    def preflight(arguments: dict[str, JsonValue]) -> None:
        if set(arguments) != set(config.argument_slots):
            raise RuntimeFailure("INVALID_PROCESS_ARGUMENTS")
        values = [arguments[key] for key in config.argument_slots]
        if any(not isinstance(v, str) or "\0" in v for v in values):
            raise RuntimeFailure("INVALID_PROCESS_ARGUMENTS")
        argv = (*config.request.argv, *(str(v) for v in values))
        if sum(len(v.encode()) for v in argv) > 65536:
            raise RuntimeFailure("PROCESS_REQUEST_LIMIT")

    async def dispatch(arguments: dict[str, JsonValue]) -> ToolResponse:
        if backend.identity_digest != identity:
            raise RuntimeFailure("ISOLATION_BINDING_CHANGED")
        values = [arguments[key] for key in config.argument_slots]
        argv = (*config.request.argv, *(str(v) for v in values))
        request = config.request.model_copy(update={"argv": argv})
        result = await backend.execute(request)
        body: dict[str, JsonValue] = {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        return ToolResponse(body=body, structured=body, success=result.exit_code == 0)

    return ProtectedCall(gateway, tool, dispatch, preflight)
