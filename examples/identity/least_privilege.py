"""Local synthetic flow; no real filesystem tools, network or production credentials.

Run with .venv/bin/python examples/identity/least_privilege.py
Optional --regression-out PATH exclusively writes an explicit safe regression fixture.
"""

import argparse
import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agentsec.contracts.loader import load_contract
from agentsec.domain.authority import AuthorityContext
from agentsec.domain.identity import Delegation, TaskScope
from agentsec.domain.scenarios import ToolNotCalled
from agentsec.domain.serialization import canonical_json
from agentsec.domain.taxonomy import EnforcementMode, SideEffectClass
from agentsec.domain.tools import ToolDescriptor
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.identity.static import StaticIdentityProvider
from agentsec.incident.classify import classify
from agentsec.incident.promote import promote
from agentsec.replay.bundle import create_bundle
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure, ToolResponse


class NoApproval:
    async def decide(self, request, presentation):
        raise AssertionError("This example has no approval rule")


async def main(out: Path | None) -> None:
    contract = load_contract(Path(__file__).with_name("contract.yaml"))
    now = datetime.now(UTC)
    credential = StaticIdentityProvider(contract.identity.principal).verify(None, now)
    grant = Delegation(
        schema_version="0.1",
        delegation_id="read-only",
        delegator=contract.identity.acts_on_behalf_of,
        delegate=credential.principal,
        task_scope=TaskScope(task_id="local-demo", description="Read-only demonstration"),
        capability_scope=frozenset({"filesystem.read"}),
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    authority = AuthorityContext(
        schema_version="0.1", credential=credential, delegation_json=canonical_json(grant)
    )
    sink = InMemoryEventSink()
    gateway = RuntimeGateway(
        contract, EnforcementMode.ENFORCE, RuntimeEvents(sink), NoApproval(), authority=authority
    )
    descriptors = tuple(
        ToolDescriptor(
            schema_version="0.1",
            tool_id=name,
            namespace="synthetic",
            name=name,
            protocol="synthetic",
            description="No external effects",
            capabilities=frozenset({f"filesystem.{name}"}),
            input_schema={"type": "object"},
            side_effect_class=SideEffectClass.READ
            if name == "read"
            else SideEffectClass.EXTERNAL_WRITE,
        )
        for name in ("read", "write")
    )

    async def substitute(_):
        return ToolResponse(body={}, success=True)

    await gateway.call(descriptors[0], {}, None, substitute, bound=True)
    print("read: ALLOW")
    try:
        await gateway.call(descriptors[1], {}, None, substitute, bound=True)
    except RuntimeFailure as error:
        assert error.code == "POLICY_DENIED"
        print("write: DENY (outside delegated authority)")
    else:
        raise AssertionError("Delegation failed to restrict write")
    gateway.finish()
    if out is not None:
        bundle = create_bundle(
            tuple(sink.events),
            contract,
            tools=descriptors,
            expectations=(ToolNotCalled(type="TOOL_NOT_CALLED", tool_id="write"),),
        )
        case = promote(bundle, classify(bundle))
        with out.open("x") as stream:
            stream.write(canonical_json(case) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--regression-out", type=Path)
    asyncio.run(main(parser.parse_args().regression_out))
