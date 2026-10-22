"""One atomic ancestry coordinator. All mutations are owned by the session thread/loop."""

from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
from time import monotonic
from uuid import uuid4

from agentsec.domain.graph import GraphBinding
from agentsec.domain.taxonomy import SideEffectClass
from agentsec.domain.tools import ToolDescriptor
from agentsec.multi_agent.authority import GraphMaterial
from agentsec.runtime.budgets import BudgetLedger
from agentsec.runtime.models import RuntimeFailure


@dataclass(frozen=True)
class Reservation:
    binding: GraphBinding
    action_digest: str
    delta: tuple[int, int, int]


class HierarchicalBudgets:
    def __init__(
        self,
        material: Callable[[], GraphMaterial],
        owner: Callable[[], None],
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._material, self._owner, self._clock = material, owner, clock
        self._started = clock()
        self._lock = RLock()
        self._pending: dict[str, Reservation] = {}
        self._committed: dict[str, Reservation] = {}
        self._used: dict[str, list[int]] = {}
        self._admitted: dict[str, set[str]] = {}

    def admit(self, node_id: str) -> None:
        self._owner()
        material = self._material()
        path = material.graph.path(node_id)
        with self._lock:
            for ancestor in path[:-1]:
                limit = material.participant(ancestor).plan.max_delegated_agents
                seen = self._admitted.get(ancestor, set())
                principal = material.participant(node_id).plan.principal.principal_id
                if limit is not None and len(seen | {principal}) > limit:
                    raise RuntimeFailure("GRAPH_AGENT_CAP_EXCEEDED")
            for ancestor in path[:-1]:
                self._admitted.setdefault(ancestor, set()).add(
                    material.participant(node_id).plan.principal.principal_id
                )

    def _check(self, reservation: Reservation, *, include: bool) -> None:
        material = self._material()
        if material.binding(reservation.binding.node_id) != reservation.binding:
            raise RuntimeFailure("GRAPH_BINDING_STALE")
        for node in reservation.binding.path:
            limits = material.participant(node).plan.budgets
            if limits.max_runtime_seconds is not None and (
                self._clock() - self._started >= limits.max_runtime_seconds
            ):
                raise RuntimeFailure("BUDGET_EXCEEDED")
            caps = (limits.max_tool_calls, limits.max_external_writes, limits.max_destructive_calls)
            for index, limit in enumerate(caps):
                total = (
                    self._used.get(node, [0, 0, 0])[index]
                    + sum(r.delta[index] for r in self._pending.values() if node in r.binding.path)
                    + (reservation.delta[index] if include else 0)
                )
                if limit is not None and total > limit:
                    raise RuntimeFailure("BUDGET_EXCEEDED")

    def reserve(self, tool: ToolDescriptor, binding: GraphBinding, action_digest: str) -> str:
        self._owner()
        receipt = Reservation(
            binding,
            action_digest,
            (
                1,
                int(tool.side_effect_class == SideEffectClass.EXTERNAL_WRITE),
                int(tool.destructive),
            ),
        )
        with self._lock:
            self._check(receipt, include=True)
            token = str(uuid4())
            self._pending[token] = receipt
            return token

    def commit(self, token: str) -> None:
        self._owner()
        with self._lock:
            receipt = self._pending.get(token)
            if receipt is None:
                raise RuntimeFailure("GRAPH_INVALID_RESERVATION")
            self._check(receipt, include=False)
            del self._pending[token]
            for node in receipt.binding.path:
                used = self._used.setdefault(node, [0, 0, 0])
                for i, delta in enumerate(receipt.delta):
                    used[i] += delta
            self._committed[token] = receipt

    def validate_commit(self, token: str) -> None:
        self._owner()
        with self._lock:
            receipt = self._committed.get(token)
            if receipt is None:
                raise RuntimeFailure("GRAPH_INVALID_RESERVATION")
            self._check(receipt, include=False)

    def release(self, token: str) -> None:
        self._owner()
        with self._lock:
            self._pending.pop(token, None)

    def refund(self, token: str) -> None:
        self._owner()
        with self._lock:
            receipt = self._committed.pop(token, None)
            if receipt:
                for node in receipt.binding.path:
                    for i, delta in enumerate(receipt.delta):
                        self._used[node][i] -= delta

    def forget(self, token: str) -> None:
        self._owner()
        with self._lock:
            self._committed.pop(token, None)

    def facade(self, node_id: str) -> BudgetLedger:
        return NodeBudget(self, node_id)


class NodeBudget(BudgetLedger):
    """Gateway-compatible view; contains no independent counters."""

    def __init__(self, coordinator: HierarchicalBudgets, node_id: str) -> None:
        self._coordinator, self._node_id = coordinator, node_id

    def reserve(
        self,
        tool: ToolDescriptor,
        *,
        enforce: bool = True,
        action_digest: str = "",
        graph_binding: GraphBinding | None = None,
    ) -> tuple[str, bool]:
        if not enforce:
            raise RuntimeFailure("GRAPH_MODE_UNSUPPORTED")
        if graph_binding is None or graph_binding.node_id != self._node_id or not action_digest:
            raise RuntimeFailure("GRAPH_BINDING_REQUIRED")
        return self._coordinator.reserve(tool, graph_binding, action_digest), False

    def commit(self, token: str, *, enforce: bool = True) -> None:
        self._coordinator.commit(token)

    def validate_commit(self, token: str, *, enforce: bool = True) -> None:
        self._coordinator.validate_commit(token)

    def release(self, token: str) -> None:
        self._coordinator.release(token)

    def refund(self, token: str) -> None:
        self._coordinator.refund(token)

    def forget(self, token: str) -> None:
        self._coordinator.forget(token)
