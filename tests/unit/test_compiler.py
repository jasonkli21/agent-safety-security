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


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "Renamed"),
        ("framework", "framework"),
        ("model_provider", "provider"),
        ("model_name", "model"),
    ],
)
def test_cosmetic_agent_fields_do_not_change_execution(field, value):
    from agentsec.contracts.canonical import document_hash, effective_policy_hash

    original = contract(tools=rules())
    changed = original.model_copy(
        update={"agent": original.agent.model_copy(update={field: value})}
    )
    a, b = compile_contract(original), compile_contract(changed)
    assert document_hash(original) != document_hash(changed)
    assert effective_policy_hash(original) == effective_policy_hash(changed)
    assert a == b and a.identity == b.identity
    assert not semantic_diff(a, b).changes
    request = generate_probes(a)[0].request(a).model_copy(update={"agent": changed.agent})
    assert NativePolicyEngine().decide(request, a).reason_codes != {ReasonCode.INVALID_REQUEST}


def test_cosmetic_scope_description_does_not_change_execution():
    original = load_contract(ROOT / "examples/mcp/contract.yaml")
    changed = original.model_copy(
        update={
            "task_scope": original.task_scope.model_copy(update={"description": "Different prose"})
        }
    )
    a, b = compile_contract(original), compile_contract(changed)
    assert a == b and a.identity == b.identity
    assert not semantic_diff(a, b).changes
    request = generate_probes(a)[0].request(a).model_copy(update={"task_scope": changed.task_scope})
    assert NativePolicyEngine().decide(request, a).reason_codes != {ReasonCode.INVALID_REQUEST}


@pytest.mark.parametrize(
    "field,value",
    [
        ("agent_id", "another-agent"),
        ("environment", "another-env"),
        ("trust_level", "another-trust"),
    ],
)
def test_security_agent_fields_change_policy_identity(field, value):
    original = contract(tools=rules())
    changed = original.model_copy(
        update={"agent": original.agent.model_copy(update={field: value})}
    )
    if field == "environment":
        changed = changed.model_copy(
            update={"environment": changed.environment.model_copy(update={"mode": value})}
        )
    a, b = compile_contract(original), compile_contract(changed)
    assert a.effective_policy_hash != b.effective_policy_hash
    assert a.identity != b.identity
    assert "identity_environment_change" in {c.kind for c in semantic_diff(a, b).changes}
    request = generate_probes(a)[0].request(a).model_copy(update={"agent": changed.agent})
    assert NativePolicyEngine().decide(request, a).reason_codes == {ReasonCode.INVALID_REQUEST}


@pytest.mark.parametrize("alteration", ["contract_id", "compiler_version", "contents"])
def test_same_policy_hash_does_not_allow_stale_evidence(alteration):
    c = contract(tools=rules())
    plan = compile_contract(c)
    if alteration == "contract_id":
        stale = plan.model_copy(update={"contract_id": "another-contract"})
    elif alteration == "compiler_version":
        # Simulate an artifact from a future compiler, without accepting it in public parsing.
        stale = plan.model_copy(update={"compiler_version": "future"})
    else:
        stale = plan.model_copy(update={"rules": ()})
    assert plan.effective_policy_hash == stale.effective_policy_hash
    assert plan.identity != stale.identity
    with pytest.raises(ValueError, match="STALE_CONFORMANCE_REPORT"):
        coverage_report(stale, run_conformance(plan))
    assert all(r.status == "ERROR" for r in run_contract_cases(c, stale))


@pytest.mark.parametrize("mutation", ["drop_shadowed", "extra_reason", "wrong_rule"])
def test_explanation_mutations_fail_direct_and_eval(mutation):
    c = contract(tools=rules())
    plan = compile_contract(c)

    class Broken:
        def decide(self, request, plan):
            decision = NativePolicyEngine().decide(request, plan)
            if request.capability == "web.search" and request.resource == "x":
                update = (
                    {"matched_rule_ids": frozenset({"exception"})}
                    if mutation == "drop_shadowed"
                    else {"reason_codes": decision.reason_codes | {ReasonCode.DEFAULT_DENY}}
                    if mutation == "extra_reason"
                    else {"matched_rule_ids": frozenset({"wrong"})}
                )
                return decision.model_copy(update=update)
            return decision

    exact = next(p for p in generate_probes(plan) if p.resource == "x")
    assert exact.matched_rule_ids == {"general", "exception"}
    for rows in (run_conformance(plan, Broken()).probes, run_contract_cases(c, plan, Broken())):
        assert next(r for r in rows if r.probe_id == exact.probe_id).status == "FAIL"


def test_grouped_identity_scope_coverage_remains_unclaimed():
    c = load_contract(ROOT / "examples/mcp/contract.yaml")
    plan = compile_contract(c)
    results = run_conformance(plan).model_copy(update={"eval_cases": run_contract_cases(c, plan)})
    report = coverage_report(plan, results)
    for atom in report.atoms:
        if atom.atom_id in {"identity", "task_scope"}:
            assert not atom.probe_ids and not atom.eval_case_ids
            assert atom.probe_status == atom.eval_status == "NOT_RUN"
    for probe in generate_probes(plan):
        if probe.reason in {ReasonCode.OUTSIDE_TASK_SCOPE, ReasonCode.DEFAULT_DENY}:
            assert not probe.matched_rule_ids


@pytest.mark.parametrize("mutation", ["remove_deny", "rename", "shadowed_rule"])
def test_diff_explanation_changes_without_authority_changes(mutation):
    original = contract(tools=rules("DENY", "DENY"))
    data = original.model_dump(mode="json")
    if mutation == "remove_deny":
        data["tools"]["rules"] = []
    elif mutation == "rename":
        data["tools"]["rules"][0]["rule_id"] = "renamed"
    else:
        data["tools"]["rules"].append(
            {
                "rule_id": "shadowed",
                "capability": "web.search",
                "decision": "ALLOW",
                "resource": "y",
            }
        )
    a, b = compile_contract(original), compile_contract(validate_data(AgentSecurityContract, data))
    diff = semantic_diff(a, b)
    assert diff == semantic_diff(a, b)
    assert {c.kind for c in diff.changes} == {"policy_explanation_change"}
    assert all(c.old_outcome == c.new_outcome for c in diff.changes)
    assert any(
        c.old_reason_codes != c.new_reason_codes or c.old_matched_rule_ids != c.new_matched_rule_ids
        for c in diff.changes
    )


@pytest.mark.parametrize("field", ["owner", "principal", "task_id", "capabilities", "resources"])
def test_protected_bindings_and_scope_change_semantics(field):
    original = load_contract(ROOT / "examples/mcp/contract.yaml")
    data = original.model_dump(mode="json")
    if field == "owner":
        data["agent"]["owner"] = data["identity"]["principal"] | {"principal_id": "owner"}
    elif field == "principal":
        data["identity"]["principal"]["principal_id"] = "other-principal"
    elif field == "task_id":
        data["task_scope"]["task_id"] = "other-task"
    elif field == "capabilities":
        data["task_scope"]["requested_capabilities"] = []
    else:
        data["task_scope"]["resource_scopes"] = {"web.search": ["restricted"]}
    changed = validate_data(AgentSecurityContract, data)
    a, b = compile_contract(original), compile_contract(changed)
    assert a.effective_policy_hash != b.effective_policy_hash
    assert a.identity != b.identity
    assert semantic_diff(a, b).changes
    assert NativePolicyEngine().decide(generate_probes(a)[0].request(a), b).reason_codes == {
        ReasonCode.INVALID_REQUEST
    }


def test_cli_reports_explanation_only_changes(tmp_path):
    from agentsec.domain.serialization import canonical_json

    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(canonical_json(contract(tools=rules("DENY", "DENY"))))
    after.write_text(canonical_json(contract(tools={"rules": []})))
    result = CliRunner().invoke(app, ["contract", "diff", str(before), str(after)])
    assert result.exit_code == 0
    assert "policy_explanation_change" in result.output
    assert "No changes detected" not in result.output
