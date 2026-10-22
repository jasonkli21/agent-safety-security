"""Session counters including reservations; no I/O under the lock."""

from collections.abc import Callable
from threading import Lock
from time import monotonic
from uuid import uuid4

from agentsec.contracts.models import Budgets
from agentsec.domain.graph import GraphBinding
from agentsec.domain.taxonomy import SideEffectClass
from agentsec.domain.tools import ToolDescriptor
from agentsec.runtime.models import RuntimeFailure


class BudgetLedger:
    def __init__(
        self,
        limits: Budgets,
        clock: Callable[[], float] = monotonic,
        id_factory: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        self.id_factory = id_factory
        self.limits = limits
        self.clock = clock
        self.started = clock()
        self._lock = Lock()
        self._pending: dict[str, tuple[int, int, int]] = {}
        self._used = (0, 0, 0)
        self._receipts: dict[str, tuple[int, int, int]] = {}

    def _check(self, delta: tuple[int, int, int]) -> None:
        if (
            self.limits.max_runtime_seconds is not None
            and self.clock() - self.started >= self.limits.max_runtime_seconds
        ):
            raise RuntimeFailure("BUDGET_EXCEEDED")
        limits = (
            self.limits.max_tool_calls,
            self.limits.max_external_writes,
            self.limits.max_destructive_calls,
        )
        for i, limit in enumerate(limits):
            total = self._used[i] + sum(v[i] for v in self._pending.values()) + delta[i]
            if limit is not None and total > limit:
                raise RuntimeFailure("BUDGET_EXCEEDED")

    def reserve(
        self,
        tool: ToolDescriptor,
        *,
        enforce: bool = True,
        action_digest: str = "",
        graph_binding: GraphBinding | None = None,
    ) -> tuple[str, bool]:
        delta = (
            1,
            int(tool.side_effect_class == SideEffectClass.EXTERNAL_WRITE),
            int(tool.destructive),
        )
        with self._lock:
            exceeded = False
            try:
                self._check(delta)
            except RuntimeFailure:
                if enforce:
                    raise
                exceeded = True
            token = self.id_factory()
            self._pending[token] = delta
            return token, exceeded

    def commit(self, token: str, *, enforce: bool = True) -> None:
        with self._lock:
            if enforce:
                self._check((0, 0, 0))
            delta = self._pending.pop(token)
            self._receipts[token] = delta
            self._used = (
                self._used[0] + delta[0],
                self._used[1] + delta[1],
                self._used[2] + delta[2],
            )

    def release(self, token: str) -> None:
        with self._lock:
            self._pending.pop(token, None)

    def validate_commit(self, token: str, *, enforce: bool = True) -> None:
        with self._lock:
            if token not in self._receipts:
                raise RuntimeFailure("INVALID_BUDGET_RESERVATION")
            if enforce:
                self._check((0, 0, 0))

    def refund(self, token: str) -> None:
        """Compensate one exact commit only before dispatcher entry."""
        with self._lock:
            delta = self._receipts.pop(token, None)
            if delta is not None:
                self._used = (
                    self._used[0] - delta[0],
                    self._used[1] - delta[1],
                    self._used[2] - delta[2],
                )

    def forget(self, token: str) -> None:
        """Dispatcher entry makes this commit nonrefundable."""
        with self._lock:
            self._receipts.pop(token, None)
