"""Use a separately reviewed static lock; never derive expected pins at startup."""

import asyncio
from pathlib import Path

from pydantic import JsonValue

from agentsec.adapters.native import protect_native
from agentsec.contracts.loader import load_contract
from agentsec.domain.taxonomy import EnforcementMode
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.runtime.bindings import ProtectedTool
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure
from agentsec.supply_chain.guard import TrustGuard
from agentsec.supply_chain.io import load_json
from agentsec.supply_chain.models import TrustLock


class NoApproval:
    async def decide(self, request: object, presentation: str) -> None:
        raise RuntimeFailure("NO_APPROVER_CONFIGURED")


async def main() -> None:
    root = Path(__file__).resolve().parent
    guard = TrustGuard(load_json(root / "native-lock.json", TrustLock))
    runtime = RuntimeGateway(
        load_contract(root.parent / "mcp/contract.yaml"),
        EnforcementMode.ENFORCE,
        RuntimeEvents(InMemoryEventSink()),
        NoApproval(),
        trust_guard=guard,
    )

    async def search(arguments: dict[str, JsonValue]) -> JsonValue:
        return {"ok": True}

    call = protect_native(runtime, load_json(root / "native-tool.json", ProtectedTool), search)
    print((await call.invoke({"query": "synthetic"})).structured)
    # Operator removal blocks the same registered call on its next invocation.
    guard.replace_lock(
        TrustLock(schema_version="0.1", status="REVIEWED", generation="removed", pins=())
    )
    try:
        await call.invoke({"query": "synthetic"})
    except RuntimeFailure as exc:
        print(exc.code)
    runtime.finish()


if __name__ == "__main__":
    asyncio.run(main())
