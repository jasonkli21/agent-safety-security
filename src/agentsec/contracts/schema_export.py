"""Deterministic JSON Schema export from canonical model definitions."""

import json
from pathlib import Path

from pydantic import BaseModel

from agentsec.adapters.mcp.config import McpGatewayConfig
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.approvals import ApprovalDecision, ApprovalRequest, NormalizedAction
from agentsec.domain.events import SecurityEvent
from agentsec.domain.findings import Finding
from agentsec.domain.identity import Delegation
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.provenance import DataArtifactRef
from agentsec.domain.scenarios import Scenario
from agentsec.domain.tools import ToolDescriptor
from agentsec.eval.fixtures import TargetFixture
from agentsec.eval.models import EvaluationResult, EvaluationSummary

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "mcp-gateway-config": McpGatewayConfig,
    "agent-security-contract": AgentSecurityContract,
    "scenario": Scenario,
    "security-event": SecurityEvent,
    "policy-request": PolicyRequest,
    "policy-decision": PolicyDecision,
    "approval-request": ApprovalRequest,
    "approval-decision": ApprovalDecision,
    "normalized-action": NormalizedAction,
    "tool-descriptor": ToolDescriptor,
    "delegation": Delegation,
    "data-artifact": DataArtifactRef,
    "finding": Finding,
    "evaluation-result": EvaluationResult,
    "evaluation-summary": EvaluationSummary,
    "target-fixture": TargetFixture,
}


def schema_text(model: type[BaseModel]) -> str:
    schema = model.model_json_schema(mode="validation")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def export_schemas(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, model in SCHEMA_MODELS.items():
        (out / f"{name}.schema.json").write_text(schema_text(model), encoding="utf-8")
