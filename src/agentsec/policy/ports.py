"""The authorization boundary accepts structured requests, never prompt strings."""

from typing import Protocol

from agentsec.compiler.models import CompiledSecurityPlan
from agentsec.domain.policy import PolicyDecision, PolicyRequest


class PolicyEngine(Protocol):
    def decide(self, request: PolicyRequest, contract: CompiledSecurityPlan) -> PolicyDecision: ...
