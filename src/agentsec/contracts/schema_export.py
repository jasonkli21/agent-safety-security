"""Deterministic JSON Schema export from canonical model definitions."""

import json
from pathlib import Path

from pydantic import BaseModel

from agentsec.adapters.http import HttpAction
from agentsec.adapters.mcp.config import McpGatewayConfig
from agentsec.adapters.process import ProcessAction
from agentsec.compiler.diff import SemanticDiff
from agentsec.compiler.models import CompiledSecurityPlan
from agentsec.compiler.reporting import ConformanceReport, CoverageReport
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.approvals import ApprovalDecision, ApprovalRequest, NormalizedAction
from agentsec.domain.authority import AuthorityContext, VerifiedCredential
from agentsec.domain.events import SecurityEvent
from agentsec.domain.execution import ExecutionBinding
from agentsec.domain.findings import Finding
from agentsec.domain.graph import GraphBinding, GraphSnapshot
from agentsec.domain.identity import Delegation
from agentsec.domain.policy import PolicyDecision, PolicyRequest
from agentsec.domain.provenance import DataArtifactRef
from agentsec.domain.replay import (
    CandidateRouteManifest,
    Incident,
    RegressionCase,
    ReplayBundle,
    ReplayResult,
    TraceDiff,
)
from agentsec.domain.scenarios import Scenario
from agentsec.domain.tools import ToolDescriptor
from agentsec.eval.fixtures import TargetFixture
from agentsec.eval.models import EvaluationResult, EvaluationSummary
from agentsec.isolation.backends import DockerProfile
from agentsec.multi_agent.authority import GraphMaterial
from agentsec.multi_agent.conformance import GraphConformanceReport
from agentsec.multi_agent.regression import GraphRegressionCase, GraphRegressionResult
from agentsec.multi_agent.replay import GraphReplayInput, GraphReplayResult
from agentsec.runtime.bindings import ProtectedTool
from agentsec.supply_chain.models import (
    DependencyManifest,
    Inventory,
    InventoryDiff,
    ScanReport,
    Signature,
    TrustAssessment,
    TrustInputs,
    TrustLock,
)

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "graph-regression-case": GraphRegressionCase,
    "graph-regression-result": GraphRegressionResult,
    "agent-graph": GraphSnapshot,
    "graph-binding": GraphBinding,
    "graph-material": GraphMaterial,
    "graph-conformance": GraphConformanceReport,
    "graph-replay-input": GraphReplayInput,
    "graph-replay-result": GraphReplayResult,
    "trust-inputs": TrustInputs,
    "trust-inventory": Inventory,
    "trust-lock": TrustLock,
    "trust-dependencies": DependencyManifest,
    "trust-assessment": TrustAssessment,
    "trust-diff": InventoryDiff,
    "trust-scan": ScanReport,
    "trust-signature": Signature,
    "protected-tool": ProtectedTool,
    "execution-binding": ExecutionBinding,
    "http-action": HttpAction,
    "process-action": ProcessAction,
    "docker-profile": DockerProfile,
    "authority-context": AuthorityContext,
    "verified-credential": VerifiedCredential,
    "incident": Incident,
    "replay-bundle": ReplayBundle,
    "replay-result": ReplayResult,
    "trace-diff": TraceDiff,
    "candidate-route-manifest": CandidateRouteManifest,
    "regression-case": RegressionCase,
    "compiled-security-plan": CompiledSecurityPlan,
    "contract-conformance-report": ConformanceReport,
    "contract-coverage-report": CoverageReport,
    "contract-semantic-diff": SemanticDiff,
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
