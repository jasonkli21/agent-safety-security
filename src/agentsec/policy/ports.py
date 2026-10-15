"""The authorization boundary accepts structured requests, never prompt strings."""

from typing import Protocol

from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.policy import PolicyDecision, PolicyRequest


class PolicyEngine(Protocol):
    def decide(self, request: PolicyRequest, contract: AgentSecurityContract) -> PolicyDecision: ...
