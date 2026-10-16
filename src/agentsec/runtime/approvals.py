"""Exact one-shot approvals owned by a single runtime session."""

from collections.abc import Callable
from datetime import datetime
from threading import Lock
from typing import Protocol

from agentsec.domain.approvals import ApprovalDecision, ApprovalRequest
from agentsec.domain.taxonomy import ApprovalOutcome
from agentsec.runtime.models import RuntimeFailure


class ApprovalBroker(Protocol):
    async def decide(self, request: ApprovalRequest, presentation: str) -> ApprovalDecision: ...


class ApprovalLedger:
    def __init__(self, clock: Callable[[], datetime]) -> None:
        self.clock = clock
        self._lock = Lock()
        self._requests: dict[str, ApprovalRequest] = {}
        self._decisions: dict[str, ApprovalDecision] = {}

    def create(self, request: ApprovalRequest) -> None:
        with self._lock:
            if request.approval_id in self._requests:
                raise RuntimeFailure("INVALID_APPROVAL")
            self._requests[request.approval_id] = request

    def record(self, decision: ApprovalDecision) -> None:
        try:
            decision = ApprovalDecision.model_validate_json(decision.model_dump_json())
        except (ValueError, AttributeError) as exc:
            raise RuntimeFailure("INVALID_APPROVAL") from exc
        with self._lock:
            request = self._requests.get(decision.approval_id)
            now = self.clock()
            if (
                request is None
                or decision.approval_id in self._decisions
                or request.expires_at is None
                or now >= request.expires_at
                or not request.created_at <= decision.decided_at <= now
                or decision.decided_at >= request.expires_at
            ):
                raise RuntimeFailure("INVALID_APPROVAL")
            self._decisions[decision.approval_id] = decision

    def redeem(self, approval_id: str, digest: str) -> None:
        with self._lock:
            request = self._requests.pop(approval_id, None)
            decision = self._decisions.pop(approval_id, None)
            if request is None or decision is None or request.action_digest != digest:
                raise RuntimeFailure("INVALID_APPROVAL")
            if decision.outcome == ApprovalOutcome.DENY:
                raise RuntimeFailure("APPROVAL_DENIED")
            if request.expires_at is None or self.clock() >= request.expires_at:
                raise RuntimeFailure("APPROVAL_EXPIRED")

    def invalidate(self, approval_id: str) -> None:
        with self._lock:
            self._requests.pop(approval_id, None)
            self._decisions.pop(approval_id, None)
