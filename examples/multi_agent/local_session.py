"""Run with .venv/bin/python examples/multi_agent/local_session.py. No network or model."""

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import JsonValue

from agentsec.adapters.native import native_binding, protect_native
from agentsec.compiler import compile_contract
from agentsec.contracts.loader import load_contract
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.approvals import ApprovalDecision, ApprovalRequest
from agentsec.domain.graph import AgentNode, DelegationEdge, GraphSnapshot
from agentsec.domain.identity import Delegation, PrincipalRef, TaskScope
from agentsec.domain.serialization import canonical_json
from agentsec.domain.taxonomy import ApprovalOutcome, DataLabel, PrincipalType, SideEffectClass
from agentsec.domain.tools import ToolDescriptor
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.identity.static import StaticIdentityProvider
from agentsec.multi_agent.messaging import MessageRoute
from agentsec.multi_agent.session import MultiAgentSession
from agentsec.runtime.bindings import ProtectedCall, ProtectedTool
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure

NOW = datetime(2026, 10, 21, tzinfo=UTC)
USER = PrincipalRef(principal_id="user", principal_type=PrincipalType.USER)


class LocalBroker:
    async def decide(self, request: ApprovalRequest, presentation: str) -> ApprovalDecision:
        return ApprovalDecision(
            schema_version="0.1",
            approval_id=request.approval_id,
            approver=USER,
            outcome=ApprovalOutcome.APPROVE,
            decided_at=NOW,
        )


def build_session(
    *,
    budget: int = 5,
    approval: bool = False,
    broker: LocalBroker | None = None,
    sibling: bool = False,
) -> tuple[MultiAgentSession, dict[str, RuntimeGateway], dict[str, InMemoryEventSink]]:
    template = load_contract(Path(__file__).with_name("contract-a.yaml"))
    contracts: dict[str, AgentSecurityContract] = {}
    nodes, edges = [], []
    parents: dict[str, str | None] = {"a": None, "b": "a", "c": "a" if sibling else "b"}
    principals = {
        n: PrincipalRef(principal_id=n, principal_type=PrincipalType.AGENT) for n in parents
    }
    for node, parent in parents.items():
        raw = template.model_dump(mode="json")
        raw["metadata"]["contract_id"] = f"graph-{node}"
        raw["agent"]["agent_id"] = node
        raw["identity"] = {
            "principal": principals[node].model_dump(mode="json"),
            "acts_on_behalf_of": (principals[parent] if parent else USER).model_dump(mode="json"),
        }
        raw["budgets"]["max_tool_calls"] = budget if node == "a" else 20
        for rule in raw["tools"]["rules"]:
            if node != "a" and rule["rule_id"] == "write":
                rule["decision"] = "ALLOW"
            if node == "a" and approval and rule["rule_id"] == "read":
                rule["decision"] = "REQUIRE_APPROVAL"
        contract = AgentSecurityContract.model_validate_json(canonical_json(raw))
        contracts[node] = contract
        nodes.append(
            AgentNode(
                node_id=node,
                principal=principals[node],
                plan_identity=compile_contract(contract, multi_agent=True).identity,
            )
        )
        grant = Delegation(
            schema_version="0.1",
            delegation_id=f"grant-{node}",
            delegate=principals[node],
            delegator=principals[parent] if parent else USER,
            parent_delegation_id=f"grant-{parent}" if parent else None,
            task_scope=TaskScope(task_id="local-graph", description="Protected finite local grant"),
            capability_scope=frozenset(
                {"filesystem.read", "filesystem.write", "agent.message.send"}
            ),
            issued_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=5),
        )
        edges.append(
            DelegationEdge(parent_id=parent, child_id=node, delegation_json=canonical_json(grant))
        )
    graph = GraphSnapshot(
        schema_version="0.1", generation=1, root=USER, nodes=tuple(nodes), edges=tuple(edges)
    )
    session = MultiAgentSession(
        graph,
        contracts,
        {n: StaticIdentityProvider(p) for n, p in principals.items()},
        broker or LocalBroker(),
        clock=lambda: NOW,
    )
    sinks = {node: InMemoryEventSink() for node in parents}
    gateways = {node: session.activate(node, RuntimeEvents(sinks[node])) for node in parents}
    return session, gateways, sinks


def read_tool(gateway: RuntimeGateway, capability: str = "filesystem.read") -> ProtectedCall:
    metadata = ProtectedTool(
        schema_version="0.1",
        execution_binding=native_binding("local-read", "1"),
        descriptor=ToolDescriptor(
            schema_version="0.1",
            tool_id=capability,
            namespace="local",
            name="read",
            protocol="native",
            description="Synthetic read; no filesystem access",
            input_schema={"type": "object", "additionalProperties": False},
            side_effect_class=SideEffectClass.READ,
            capabilities=frozenset({capability}),
        ),
        output_data_labels=frozenset({DataLabel.SECRET}),
        data_sink_destination="local",
    )

    async def synthetic(arguments: dict[str, JsonValue]) -> JsonValue:
        return {"synthetic_read": True}

    return protect_native(gateway, metadata, synthetic)


async def expect(code: str, operation: object) -> None:
    from collections.abc import Awaitable

    assert isinstance(operation, Awaitable)
    try:
        await operation
    except RuntimeFailure as exc:
        assert exc.code == code, (exc.code, code)
    else:
        raise AssertionError(f"Expected {code}")


async def main() -> None:
    session, gateways, _ = build_session()
    assert (await read_tool(gateways["c"]).invoke({})).success
    await expect("POLICY_DENIED", read_tool(gateways["c"], "filesystem.write").invoke({}))
    await read_tool(gateways["a"]).invoke({})
    await MessageRoute(session, "a", "b").send("Untrusted local message")
    assert session.receive("b") == ("Untrusted local message",)
    await MessageRoute(session, "b", "c").send("Untrusted relay")
    assert session.receive("c") == ("Untrusted relay",)
    assert all(DataLabel.SECRET in ref.labels for ref in gateways["c"].provenance.snapshot())
    await read_tool(gateways["c"]).invoke({})
    await expect("BUDGET_EXCEEDED", read_tool(gateways["c"]).invoke({}))
    siblings, _, _ = build_session(sibling=True)
    try:
        MessageRoute(siblings, "b", "c")
    except RuntimeFailure as exc:
        assert exc.code == "GRAPH_NONADJACENT_ROUTE"
    else:
        raise AssertionError("sibling route accepted")
    entered, release = asyncio.Event(), asyncio.Event()

    class Waiting(LocalBroker):
        async def decide(self, request: ApprovalRequest, presentation: str) -> ApprovalDecision:
            entered.set()
            await release.wait()
            return await super().decide(request, presentation)

    pending_session, pending_gateways, _ = build_session(approval=True, broker=Waiting())
    pending = asyncio.create_task(read_tool(pending_gateways["c"]).invoke({}))
    await entered.wait()
    pending_session.replace_graph(
        pending_session.material.graph.model_copy(update={"generation": 2})
    )
    release.set()
    await expect("GRAPH_BINDING_STALE", pending)
    print(
        "PASS: two-hop read, ancestor deny, labeled relay, shared budget, "
        "sibling reject, approval epoch"
    )


if __name__ == "__main__":
    asyncio.run(main())
