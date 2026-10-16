"""Focused Phase 3 boundaries: independent expectations and truthful coverage."""

from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from agentsec.cli.main import app
from agentsec.compiler import compile_contract
from agentsec.compiler.diff import semantic_diff
from agentsec.compiler.models import CompiledSecurityPlan
from agentsec.compiler.probes import generate_probes, partition
from agentsec.compiler.reporting import coverage_report, run_conformance
from agentsec.contracts.loader import load_contract, validate_data
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.serialization import canonical_json
from agentsec.domain.taxonomy import PolicyOutcome, ReasonCode
from agentsec.eval.contract_cases import run_contract_cases
from agentsec.policy.native import NativePolicyEngine

ROOT = Path(__file__).resolve().parents[2]


def contract(**updates):
    data = load_contract(ROOT / "examples/mcp/contract.yaml").model_dump(mode="json")
    data.update(task_scope=None, budgets={})
    data.update(updates)
    return validate_data(AgentSecurityContract, data)


def rules(general="ALLOW", exact="DENY"):
    return {
        "rules": [
            {"rule_id": "general", "capability": "web.search", "decision": general},
            {
                "rule_id": "exception",
                "capability": "web.search",
                "decision": exact,
                "resource": "x",
            },
        ]
    }


def test_compile_deterministic_sources_gaps_and_deep_immutability():
    c = contract(
        data={"rules": [{"rule_id": "secret", "label": "SECRET"}]},
        invariants=[{"id": "never", "description": "No leaks"}],
        budgets={"max_tool_calls": 2, "max_model_calls": 0},
    )
    plan = compile_contract(c)
    assert canonical_json(plan) == canonical_json(compile_contract(c))
    assert plan.gaps == ("budgets.max_model_calls", "data.rules/secret", "invariants/never")
    assert plan.budgets.max_tool_calls == 2
    assert all(a.source_ref == a.atom_id for a in plan.atoms)
    scoped = compile_contract(load_contract(ROOT / "examples/mcp/contract.yaml"))
    scope = scoped.task_scope
    scope.resource_scopes.clear()
    assert scoped.task_scope.resource_scopes
    with pytest.raises(ValidationError):
        plan.environment = "other"
    for patch in ({"schema_version": "9"}, {"unknown": True}, {"budgets": {"max_tool_calls": -1}}):
        with pytest.raises(ValidationError):
            CompiledSecurityPlan.model_validate_json(canonical_json({**plan.model_dump(), **patch}))


def test_probe_expectations_never_call_engine(monkeypatch):
    plan = compile_contract(contract(tools=rules()))

    def explode(*args):
        raise AssertionError("engine used to generate expectations")

    monkeypatch.setattr(NativePolicyEngine, "decide", explode)
    probes = generate_probes(plan)
    assert probes == generate_probes(plan)
    exact = next(p for p in probes if p.resource == "x")
    assert exact.expected == PolicyOutcome.DENY
    assert exact.reason == ReasonCode.EXPLICIT_DENY
    assert {"tools.rules/general", "tools.rules/exception"} <= set(exact.atom_ids)
    unknown = [p for p in probes if p.capability != "web.search"]
    assert unknown and all(p.reason == ReasonCode.DEFAULT_DENY for p in unknown)


def test_collision_free_unknown_and_other():
    c = contract(
        tools={
            "rules": [
                {
                    "rule_id": "collision",
                    "capability": "conformance.unknown",
                    "decision": "ALLOW",
                    "resource": "conformance-other",
                }
            ]
        }
    )
    rows = partition(compile_contract(c))
    assert ("conformance.unknown_1", None) in rows
    assert ("conformance.unknown", "conformance-other_1") in rows


@pytest.mark.parametrize(
    "general,exact,expected",
    [
        ("ALLOW", "DENY", PolicyOutcome.DENY),
        ("ALLOW", "REQUIRE_APPROVAL", PolicyOutcome.REQUIRE_APPROVAL),
        ("REQUIRE_APPROVAL", "ALLOW", PolicyOutcome.REQUIRE_APPROVAL),
    ],
)
def test_policy_eval_non_circular_matrix(general, exact, expected):
    c = contract(tools=rules(general, exact))
    plan = compile_contract(c)
    assert next(p for p in generate_probes(plan) if p.resource == "x").expected == expected
    assert all(r.status == "PASS" for r in run_conformance(plan).probes)
    assert all(r.status == "PASS" for r in run_contract_cases(c, plan))


def test_broken_policy_fails_eval_and_probe():
    c = contract(tools=rules("ALLOW", "REQUIRE_APPROVAL"))
    plan = compile_contract(c)

    class Broken:
        def decide(self, request, plan):
            return (
                NativePolicyEngine()
                .decide(request, plan)
                .model_copy(update={"outcome": PolicyOutcome.ALLOW})
            )

    assert any(r.status == "FAIL" for r in run_conformance(plan, Broken()).probes)
    results = run_contract_cases(c, plan, Broken())
    assert any(r.expected == PolicyOutcome.REQUIRE_APPROVAL and r.status == "FAIL" for r in results)

    class Error:
        def decide(self, request, plan):
            raise ValueError("private value")

    assert all(r.status == "ERROR" for r in run_contract_cases(c, plan, Error()))
    assert all(r.status == "ERROR" for r in run_conformance(plan, Error()).probes)


def test_coverage_separates_not_run_unsupported_and_adapter():
    plan = compile_contract(
        contract(tools=rules(), data={"rules": [{"rule_id": "secret", "label": "SECRET"}]})
    )
    report = coverage_report(plan)
    secret = next(a for a in report.atoms if a.atom_id == "data.rules/secret")
    assert not secret.compiled and not secret.runtime_supported
    assert not secret.probe_ids and not secret.eval_case_ids
    exact = next(a for a in report.atoms if a.atom_id == "tools.rules/exception")
    assert exact.adapter_status == "UNPROVEN" and exact.probe_status == "NOT_RUN"
    ran = coverage_report(plan, run_conformance(plan))
    exact = next(a for a in ran.atoms if a.atom_id == "tools.rules/exception")
    assert exact.probe_status == "PASS" and exact.eval_status == "NOT_RUN"
    with pytest.raises(ValueError, match="STALE"):
        coverage_report(compile_contract(contract(tools=rules("DENY"))), run_conformance(plan))


@pytest.mark.parametrize(
    "before,after,kind",
    [
        ("DENY", "ALLOW", "authority_expansion"),
        ("REQUIRE_APPROVAL", "ALLOW", "authority_expansion"),
        ("ALLOW", "REQUIRE_APPROVAL", "authority_reduction"),
    ],
)
def test_diff_approval_and_authority(before, after, kind):
    diff = semantic_diff(
        compile_contract(contract(tools=rules(before, before))),
        compile_contract(contract(tools=rules(after, after))),
    )
    assert kind in {c.kind for c in diff.changes}
    assert ("approval_boundary" in {c.kind for c in diff.changes}) == (
        "REQUIRE_APPROVAL" in (before, after)
    )


def test_diff_exception_scope_budgets_and_unsupported():
    old = compile_contract(contract(tools=rules("ALLOW", "ALLOW"), budgets={"max_tool_calls": 1}))
    new = compile_contract(
        contract(
            tools=rules(),
            budgets={"max_tool_calls": 2},
            invariants=[{"id": "i", "description": "intent"}],
        )
    )
    diff = semantic_diff(old, new)
    assert {"authority_reduction", "budget_relaxation", "unsupported_change"} <= {
        c.kind for c in diff.changes
    }
    scope = {
        "task_id": "t",
        "description": "ceiling",
        "requested_capabilities": ["web.search"],
        "resource_scopes": {"web.search": ["x"]},
    }
    restricted = compile_contract(contract(tools=rules(), task_scope=scope))
    assert "task_scope_narrowing" in {c.kind for c in semantic_diff(old, restricted).changes}
    assert "task_scope_widening" in {c.kind for c in semantic_diff(restricted, old).changes}
    assert "budget_tightening" in {c.kind for c in semantic_diff(new, old).changes}
    assert diff == semantic_diff(old, new)
    assert diff.representatives >= 5


@pytest.mark.parametrize("command", ["compile", "test", "coverage", "diff"])
def test_cli_commands(command):
    path = str(ROOT / "examples/mcp/contract.yaml")
    args = ["contract", command, path]
    if command == "diff":
        args.append(path)
    if command == "coverage":
        args.append("--run")
    args += ["--format", "json"]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert '"schema_version":"0.1"' in result.output


def test_scope_never_grants_and_compiled_identity_errors():
    scope = {
        "task_id": "t",
        "description": "ceiling",
        "requested_capabilities": ["web.search"],
        "resource_scopes": {"web.search": ["x"]},
    }
    plan = compile_contract(contract(tools={"rules": []}, task_scope=scope))
    assert all(p.expected == PolicyOutcome.DENY for p in generate_probes(plan))
    assert all(r.status == "PASS" for r in run_conformance(plan).probes)
    probe = next(p for p in generate_probes(plan) if p.resource == "x")
    request = probe.request(plan)
    for update in (
        {"delegation_id": "unverified"},
        {"tool_id": None},
        {"principal": request.principal.model_copy(update={"principal_id": "other"})},
        {"environment": "other"},
    ):
        result = NativePolicyEngine().decide(request.model_copy(update=update), plan)
        assert result.outcome == PolicyOutcome.DENY
        assert result.reason_codes == {ReasonCode.INVALID_REQUEST}


def test_broken_evidence_cannot_validate(monkeypatch):
    from agentsec.eval.contract_cases import ContractTarget
    from agentsec.eval.observations import EvaluationObservation, ObservationCoverage

    c = contract(tools=rules())
    plan = compile_contract(c)

    def empty_observation(self, *, contract, scenario, context):
        return EvaluationObservation(
            scenario_id=scenario.scenario_id,
            run_id=context.run_id,
            trace_id=context.trace_id,
            events=(),
            coverage=ObservationCoverage(event_stream_complete=True),
        )

    monkeypatch.setattr(ContractTarget, "run", empty_observation)
    assert all(r.status == "ERROR" for r in run_contract_cases(c, plan))


def test_diff_identity_timeout_and_unsupported_removal():
    base = contract(
        approvals={"default_timeout_seconds": 10}, invariants=[{"id": "i", "description": "intent"}]
    )
    agent = base.agent.model_dump(mode="json")
    agent["agent_id"] = "other-agent"
    changed = contract(agent=agent, approvals={"default_timeout_seconds": 20})
    changes = semantic_diff(compile_contract(base), compile_contract(changed)).changes
    assert {"identity_environment_change", "approval_timeout_change", "unsupported_change"} <= {
        c.kind for c in changes
    }


def test_compiler_rule_order_and_cosmetic_policy_identity():
    original = contract(tools=rules())
    data = original.model_dump(mode="json")
    data["tools"]["rules"].reverse()
    assert compile_contract(validate_data(AgentSecurityContract, data)) == compile_contract(
        original
    )
    data["metadata"]["name"] = "Cosmetic rename"
    assert compile_contract(validate_data(AgentSecurityContract, data)) == compile_contract(
        original
    )
