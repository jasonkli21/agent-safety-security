"""Session counters including reservations; no I/O under the lock."""

from collections.abc import Callable
from threading import Lock
from time import monotonic
from uuid import uuid4

from agentsec.contracts.models import Budgets
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

    def reserve(self, tool: ToolDescriptor, *, enforce: bool = True) -> tuple[str, bool]:
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
            self._used = (
                self._used[0] + delta[0],
                self._used[1] + delta[1],
                self._used[2] + delta[2],
            )

    def release(self, token: str) -> None:
        with self._lock:
            self._pending.pop(token, None)

    def refund(self, tool: ToolDescriptor) -> None:
        """Only before dispatcher entry when critical evidence failed (no await)."""
        with self._lock:
            self._used = (
                self._used[0] - 1,
                self._used[1] - int(tool.side_effect_class == SideEffectClass.EXTERNAL_WRITE),
                self._used[2] - int(tool.destructive),
            )
