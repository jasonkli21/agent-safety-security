"""Minimization and strict team validators, using actual local lifecycle/eval artifacts."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from agentsec.compiler import compile_contract
from agentsec.compiler.reporting import coverage_report
from agentsec.contracts.loader import load_artifact, load_contract
from agentsec.control_plane.metadata import project_ci, project_events
from agentsec.control_plane.models import Counters, Issuer, Key, Metadata, TeamConfig
from agentsec.control_plane.policies import assess
from agentsec.domain.events import SecurityEvent
from agentsec.domain.scenarios import Scenario
from agentsec.eval.contract_cases import test_contract as run_conformance
from agentsec.eval.fixtures import FixtureTarget, TargetFixture
from agentsec.eval.runner import evaluate
from agentsec.regression.runner import load_corpus, run_case

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)


def dimensions():
    return dict(
        run_id=UUID(int=1),
        agent_id="agent",
        environment="test",
        repository="repo",
        start=NOW,
        end=NOW,
    )


def test_event_projection_omits_canary_and_does_not_imply_completeness():
    data = json.loads(Path("tests/fixtures/events/approval-run.json").read_text())
    events = tuple(SecurityEvent.model_validate_json(json.dumps(e)) for e in data)
    canary = "PRIVATE_CANARY_CONTENT"
    # A valid raw signal summary is local content, never projected.
    from agentsec.domain.events import SecuritySignalPayload
    from agentsec.domain.taxonomy import EventType, SecurityCategory, Severity

    event = events[0].model_copy(
        update={
            "event_id": canary,
            "event_type": EventType.SECURITY_SIGNAL,
            "payload": SecuritySignalPayload(
                kind=EventType.SECURITY_SIGNAL,
                category=SecurityCategory.PROMPT_INJECTION,
                severity=Severity.HIGH,
                redacted_summary=canary,
            ),
        }
    )
    metadata = project_events(events=(*events, event), **dimensions())
    assert canary not in metadata.model_dump_json()
    assert "payload" not in metadata.model_dump_json()
    assert metadata.counters.requested >= 1
    assert metadata.completeness == "INCOMPLETE"
    assert metadata.counters.effect_verified == 1
    without_effects = tuple(e for e in events if e.event_type != EventType.EFFECT_VERIFIED)
    assert project_events(events=without_effects, **dimensions()).counters.effect_verified == 0


def test_real_ci_projection_keeps_draft_unknown_coverage():
    contract = load_contract(Path("examples/contracts/research.yaml"))
    conformance = run_conformance(contract)
    coverage = coverage_report(compile_contract(contract), conformance)
    result = evaluate(
        contract=contract,
        scenario=load_artifact(Path("examples/scenarios/indirect-injection.yaml"), Scenario),
        target=FixtureTarget(
            load_artifact(
                Path("examples/eval-fixtures/indirect-injection-safe.yaml"), TargetFixture
            )
        ),
    )
    projected = project_ci(
        evaluations=(result,),
        regressions=tuple(run_case(c) for c in load_corpus(Path("examples/regressions"))),
        conformance=conformance,
        coverage=coverage,
        **dimensions(),
    )
    assert projected.regression == "DRAFT"
    assert projected.coverage == "GAPS"
    assert projected.mode == "UNKNOWN"
    assert "findings" not in projected.model_dump_json()
    assert "canary" not in projected.model_dump_json()
    with pytest.raises(ValueError, match="PLAN_MISMATCH"):
        project_ci(
            evaluations=(
                result.model_copy(update={"effective_policy_hash": "sha256:" + "0" * 64}),
            ),
            regressions=(),
            conformance=conformance,
            coverage=coverage,
            **dimensions(),
        )
    with pytest.raises(ValueError, match="REGRESSION_STATUS"):
        project_ci(
            evaluations=(),
            regressions=("SECURE",),
            conformance=conformance,
            coverage=coverage,
            **dimensions(),
        )


def test_server_hashes_cosmetic_and_semantic_changes_and_diff():
    source = Path("examples/mcp/contract.yaml").read_text()
    initial = assess(source, None)
    cosmetic = assess(
        source.replace("Synthetic protected tools", "A different display name"), source
    )
    assert initial.document_hash != cosmetic.document_hash
    assert initial.effective_policy_hash == cosmetic.effective_policy_hash
    assert cosmetic.semantic_diff is not None
    assert cosmetic.semantic_diff.changes == ()
    expansion = assess(source.replace("decision: DENY", "decision: ALLOW"), source)
    assert expansion.expansions
    assert "authority_expansion" in expansion.change_kinds
    assert initial.compiled_plan_digest != expansion.compiled_plan_digest


@pytest.mark.parametrize(
    "value",
    [
        {"requested": -1},
        {"requested": 1000001},
        {"returned": 1},
        {"effect_verified": 1},
        {"approval_decided": 1},
        {"extra": 0},
        {"requested": "1"},
    ],
)
def test_counter_negatives(value):
    with pytest.raises(ValidationError):
        Counters.model_validate_json(json.dumps(value))


def test_invalid_config_duplicate_issuers_and_keys():
    key = Key(kid="one", public_key_pem="invalid")
    with pytest.raises(ValidationError):
        Issuer(issuer="issuer", audience="audience", keys=(key, key))
    issuer = Issuer(issuer="issuer", audience="audience", keys=(key,))
    with pytest.raises(ValidationError):
        TeamConfig(issuers=(issuer, issuer))
    with pytest.raises(ValidationError):
        TeamConfig(issuers=(issuer,), skew_seconds=61)


@pytest.mark.parametrize("delta", [-1, 86401])
def test_period_bounds(delta):
    with pytest.raises(ValidationError):
        Metadata(
            run_id=UUID(int=1),
            agent_id="agent",
            environment="test",
            repository="repo",
            source="RUNTIME",
            period_start=NOW,
            period_end=NOW + timedelta(seconds=delta),
        )


def test_no_control_plane_extra_needed_by_local_core():
    import subprocess
    import sys

    script = """
import importlib.abc
import sys
class NoExtra(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'jwt','cryptography','starlette','uvicorn'}:
            raise ModuleNotFoundError(fullname)
sys.meta_path.insert(0, NoExtra())
from agentsec.cli.team import app
from agentsec.compiler import compile_contract
from agentsec.contracts.loader import load_contract
from pathlib import Path
plan = compile_contract(load_contract(Path('examples/mcp/contract.yaml')))
assert plan.compiler_version == 'phase6-v1'
import runpy
runpy.run_path('examples/multi_agent/local_session.py', run_name='__main__')
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


def test_loopback_only_cli_refuses_proxy_claim():
    from typer.testing import CliRunner

    from agentsec.cli.main import app

    result = CliRunner().invoke(
        app, ["team", "serve", "missing.db", "missing.json", "--host", "0.0.0.0"]
    )
    assert result.exit_code == 1
    assert "INVALID_INPUT" in result.output


def test_replay_projection_minimized_and_blocked_remains_explicit():
    from agentsec.control_plane.metadata import project_replay
    from agentsec.domain.replay import ReplayBundle
    from agentsec.replay.engine import replay

    result = replay(load_artifact(Path("examples/replay/bundle.json"), ReplayBundle))
    projected = project_replay(result=result, **dimensions())
    assert projected.counters.effect_verified == 0
    assert projected.coverage == "UNKNOWN"
    assert "events" not in projected.model_dump_json()
    assert "authority" not in projected.model_dump_json()
    blocked = result.model_copy(
        update={
            "assessment": result.assessment.model_copy(
                update={"blockers": frozenset({"MISSING_AUTHORITY_CONTEXT"})}
            )
        }
    )
    projected = project_replay(result=blocked, **dimensions())
    assert projected.replay == "BLOCKED"
    assert projected.ci == "INCONCLUSIVE"
