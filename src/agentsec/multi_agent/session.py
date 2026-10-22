"""Protected local session owner. Never expose this object as an agent tool."""

import asyncio
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from threading import get_ident
from time import monotonic

from agentsec.compiler import compile_contract
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.authority import AuthorityContext
from agentsec.domain.events import GraphEventPayload
from agentsec.domain.graph import GraphBinding, GraphSnapshot
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.taxonomy import DataLabel, EnforcementMode
from agentsec.identity.ports import IdentityProvider
from agentsec.multi_agent.authority import GraphMaterial, ParticipantFacts, check_path, decide_path
from agentsec.multi_agent.budgets import HierarchicalBudgets
from agentsec.runtime.approvals import ApprovalBroker
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure
from agentsec.supply_chain.guard import TrustGuard


class MultiAgentSession:
    def __init__(
        self,
        graph: GraphSnapshot,
        contracts: Mapping[str, AgentSecurityContract],
        providers: Mapping[str, IdentityProvider],
        broker: ApprovalBroker,
        *,
        credentials: Mapping[str, str | None] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        budget_clock: Callable[[], float] = monotonic,
    ) -> None:
        self._thread = get_ident()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._clock, self._broker = clock, broker
        graph = GraphSnapshot.model_validate_json(graph.model_dump_json())
        keys = {n.node_id for n in graph.nodes}
        if set(contracts) != keys or set(providers) != keys or set(credentials or {}) - keys:
            raise RuntimeFailure("GRAPH_CONFIGURATION_MISMATCH")
        self._contracts = {
            n: AgentSecurityContract.model_validate_json(c.model_dump_json(round_trip=True))
            for n, c in contracts.items()
        }
        facts = tuple(
            ParticipantFacts(
                node_id=node.node_id,
                plan=compile_contract(self._contracts[node.node_id], multi_agent=True),
                credential=providers[node.node_id].verify(
                    (credentials or {}).get(node.node_id), clock()
                ),
            )
            for node in graph.nodes
        )
        self._material = GraphMaterial(schema_version="0.1", graph=graph, participants=facts)
        for node in graph.nodes:
            check_path(self._material, self._material.binding(node.node_id), clock())
        self._active: set[str] = set()
        self._retired: set[str] = set()
        self._messages: set[str] = set()
        self._inboxes: dict[str, list[str]] = {}
        self._gateways: dict[str, RuntimeGateway] = {}
        self._budgets = HierarchicalBudgets(lambda: self._material, self._owner, budget_clock)

    def _owner(self) -> None:
        if get_ident() != self._thread:
            raise RuntimeFailure("GRAPH_CROSS_THREAD_UNSUPPORTED")
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            if self._loop is None:
                self._loop = loop
            elif self._loop is not loop:
                raise RuntimeFailure("GRAPH_CROSS_LOOP_UNSUPPORTED")

    @property
    def material(self) -> GraphMaterial:
        self._owner()
        return self._material

    def _binding(self, node_id: str, now: datetime) -> GraphBinding:
        self._owner()
        if node_id not in {n.node_id for n in self._material.graph.nodes}:
            raise RuntimeFailure("GRAPH_NODE_REMOVED")
        binding = self._material.binding(node_id)
        if not set(binding.path) <= self._active:
            raise RuntimeFailure("GRAPH_ANCESTOR_INACTIVE")
        check_path(self._material, binding, now)
        return binding

    def activate(
        self,
        node_id: str,
        events: RuntimeEvents,
        *,
        trust_guard: TrustGuard | None = None,
    ) -> RuntimeGateway:
        self._owner()
        if node_id in self._active or node_id in self._gateways or node_id in self._retired:
            raise RuntimeFailure("GRAPH_NODE_ALREADY_ACTIVATED")
        events.clock = self._clock
        path = self._material.graph.path(node_id)
        if not set(path[:-1]) <= self._active:
            raise RuntimeFailure("GRAPH_ANCESTOR_INACTIVE")
        self._budgets.admit(node_id)
        self._active.add(node_id)
        fact = self._material.participant(node_id)
        try:
            gateway = RuntimeGateway(
                self._contracts[node_id],
                EnforcementMode.ENFORCE,
                events,
                self._broker,
                plan=fact.plan,
                authority=AuthorityContext(schema_version="0.1", credential=fact.credential),
                budgets=self._budgets.facade(node_id),
                graph_guard=SessionGuard(self, node_id),
                trust_guard=trust_guard,
            )
        except BaseException:
            self._active.discard(node_id)
            raise
        try:
            events.emit(
                GraphEventPayload(
                    schema_version="0.1",
                    operation="ADMITTED",
                    binding=self._material.binding(node_id),
                )
            )
        except BaseException:
            self._active.discard(node_id)
            raise
        self._gateways[node_id] = gateway
        return gateway

    def receive(self, node_id: str) -> tuple[str, ...]:
        """Protected application read; bind the node outside agent-provided arguments."""
        self._binding(node_id, self._clock())
        return tuple(self._inboxes.pop(node_id, []))

    def replace_graph(self, graph: GraphSnapshot) -> None:
        self._owner()
        graph = GraphSnapshot.model_validate_json(graph.model_dump_json())
        if graph.generation <= self._material.graph.generation:
            raise RuntimeFailure("GRAPH_GENERATION_NOT_INCREASING")
        old = {n.node_id: n for n in self._material.graph.nodes}
        if (
            any(old.get(n.node_id) != n for n in graph.nodes)
            or graph.root != self._material.graph.root
        ):
            raise RuntimeFailure("GRAPH_REENROLLMENT_REQUIRES_NEW_SESSION")
        facts = tuple(self._material.participant(n.node_id) for n in graph.nodes)
        material = GraphMaterial(schema_version="0.1", graph=graph, participants=facts)
        previous = self._material
        self._material = material
        remaining = {n.node_id for n in material.graph.nodes}
        try:
            for node in tuple(self._active):
                if node not in remaining:
                    self._active.discard(node)
                    self._retired.add(node)
                self._gateways[node].events.emit(
                    GraphEventPayload(
                        schema_version="0.1",
                        operation="RECONFIGURED" if node in remaining else "REVOKED",
                        binding=material.binding(node)
                        if node in remaining
                        else previous.binding(node),
                    )
                )
        except BaseException:
            self._retired.update(self._active)
            self._active.clear()
            raise

    def revoke(self, node_id: str) -> None:
        self._owner()
        was_active = node_id in self._active
        self._active.discard(node_id)
        self._retired.add(node_id)
        if was_active and node_id in self._gateways:
            self._gateways[node_id].events.emit(
                GraphEventPayload(
                    schema_version="0.1",
                    operation="REVOKED",
                    binding=self._material.binding(node_id),
                )
            )


class SessionGuard:
    def __init__(self, session: MultiAgentSession, node_id: str) -> None:
        self._session, self._node_id = session, node_id

    def snapshot(self, now: datetime) -> GraphBinding:
        return self._session._binding(self._node_id, now)

    def final(
        self,
        binding: GraphBinding,
        now: datetime,
        capability: str,
        resource: str | None,
    ) -> None:
        if self.snapshot(now) != binding:
            raise RuntimeFailure("GRAPH_BINDING_STALE")
        check_path(self._session.material, binding, now, capability, resource)

    def decide(self, request: PolicyRequest, now: datetime) -> PolicyDecision:
        if request.graph_binding != self.snapshot(now):
            raise RuntimeFailure("GRAPH_BINDING_STALE")
        return decide_path(self._session.material, request, now)

    def classifications(
        self,
        binding: GraphBinding,
        destination: str | None,
        labels: frozenset[DataLabel] | None,
    ) -> None:
        for node in binding.path:
            plan = self._session.material.participant(node).plan
            if labels is None and any(
                r.label not in {DataLabel.TOOL_OUTPUT, DataLabel.UNTRUSTED_CONTENT}
                for r in plan.data_rules
            ):
                raise RuntimeFailure("GRAPH_SOURCE_CLASSIFICATION_REQUIRED")
            if destination is None and any(
                r.allowed_destinations or r.denied_destinations for r in plan.data_rules
            ):
                raise RuntimeFailure("GRAPH_DESTINATION_REQUIRED")

    def approval_timeout(self, binding: GraphBinding) -> int:
        return min(
            self._session.material.participant(n).plan.approvals.default_timeout_seconds
            for n in binding.path
        )

    def close(self) -> None:
        self._session.revoke(self._node_id)
