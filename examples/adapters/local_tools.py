"""Credential-free native/provider/explicit-host demonstration; no model calls."""

import asyncio
import sys
from pathlib import Path

from pydantic import JsonValue

from agentsec.adapters.native import native_binding, protect_native
from agentsec.adapters.process import ProcessAction, protect_process
from agentsec.adapters.providers import ProviderTools
from agentsec.contracts.loader import load_contract
from agentsec.domain.taxonomy import EnforcementMode, SideEffectClass
from agentsec.domain.tools import ToolDescriptor
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.isolation.backends import HostBackend
from agentsec.isolation.process import ProcessRequest
from agentsec.runtime.bindings import ProtectedTool
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure


class NoApproval:
    async def decide(self, request: object, presentation: str) -> None:
        raise RuntimeFailure("NO_APPROVER_CONFIGURED")


def metadata(capability: str, effect: SideEffectClass) -> ProtectedTool:
    return ProtectedTool(
        schema_version="0.1",
        descriptor=ToolDescriptor(
            schema_version="0.1",
            tool_id=capability,
            namespace="demo",
            name="echo",
            protocol="native",
            description="Local demonstration",
            input_schema={"type": "object"},
            capabilities=frozenset({capability}),
            side_effect_class=effect,
        ),
        execution_binding=native_binding("demo", "1"),
        output_data_labels=frozenset(),
    )


async def main() -> None:
    contract = load_contract(Path(__file__).with_name("contract.yaml"))
    gateway = RuntimeGateway(
        contract, EnforcementMode.ENFORCE, RuntimeEvents(InMemoryEventSink()), NoApproval()
    )

    async def echo(arguments: dict[str, JsonValue]) -> JsonValue:
        return arguments

    native = protect_native(gateway, metadata("local.echo", SideEffectClass.NONE), echo)
    print((await native.invoke({"text": "hello"})).structured)
    provider = ProviderTools("openai", (native,))
    print(
        (
            await provider.invoke(
                {
                    "type": "function",
                    "function": {"name": "echo", "arguments": '{"text":"provider shape"}'},
                }
            )
        ).structured
    )
    process = protect_process(
        gateway,
        metadata("process.execute", SideEffectClass.CODE_EXECUTION),
        ProcessAction(
            schema_version="0.1",
            adapter_id="demo-process",
            request=ProcessRequest(
                schema_version="0.1",
                argv=(sys.executable, "-c", "print('local process')"),
                cwd="/",
                env={},
            ),
        ),
        HostBackend(),
    )
    print((await process.invoke({})).structured)
    gateway.finish()


if __name__ == "__main__":
    asyncio.run(main())
