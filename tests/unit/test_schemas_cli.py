import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from agentsec.cli.main import app
from agentsec.contracts.canonical import canonical_contract
from agentsec.contracts.loader import load_artifact, load_contract, validate_data
from agentsec.contracts.schema_export import SCHEMA_MODELS, export_schemas, schema_text
from agentsec.domain.events import SecurityEvent
from agentsec.domain.scenarios import Scenario
from agentsec.domain.serialization import canonical_json
from agentsec.domain.tools import ToolDescriptor
from agentsec.version import __version__

ROOT = Path(__file__).resolve().parents[2]
runner = CliRunner()


def test_generated_schemas_current(tmp_path):
    export_schemas(tmp_path)
    assert {p.name for p in tmp_path.glob("*.json")} == {
        p.name for p in (ROOT / "schemas/generated").glob("*.json")
    }
    for path in tmp_path.glob("*.json"):
        assert path.read_bytes() == (ROOT / "schemas/generated" / path.name).read_bytes()
        Draft202012Validator.check_schema(json.loads(path.read_text()))


@pytest.mark.parametrize(
    "kind,model_name", [("contracts", "agent-security-contract"), ("scenarios", "scenario")]
)
def test_examples_against_independent_json_schema(kind, model_name):
    model = SCHEMA_MODELS[model_name]
    validator = Draft202012Validator(json.loads(schema_text(model)))
    for path in (ROOT / "examples" / kind).glob("*.yaml"):
        instance = load_artifact(path, model)
        validator.validate(instance.model_dump(mode="json", round_trip=True))


def test_events_against_json_schema_and_mismatch():
    validator = Draft202012Validator(json.loads(schema_text(SecurityEvent)))
    events = json.loads((ROOT / "tests/fixtures/events/approval-run.json").read_text())
    for data in events:
        validator.validate(data)
    assert not validator.is_valid({**events[0], "event_type": "TOOL_RETURNED"})


def test_destructive_metadata_relation_is_in_exported_schema():
    validator = Draft202012Validator(json.loads(schema_text(ToolDescriptor)))
    tool = load_artifact(ROOT / "examples/scenarios/indirect-injection.yaml", Scenario).setup.tools[
        0
    ]
    data = tool.model_dump(mode="json", round_trip=True)
    data.update(side_effect_class="DESTRUCTIVE", destructive=False)
    assert not validator.is_valid(data)
    data["destructive"] = True
    validator.validate(data)


def test_golden_forms():
    contract = load_contract(ROOT / "examples/contracts/research.yaml")
    scenario = load_artifact(ROOT / "examples/scenarios/indirect-injection.yaml", Scenario)
    event = validate_data(
        SecurityEvent, json.loads((ROOT / "tests/fixtures/events/approval-run.json").read_text())[1]
    )
    actual = {
        "contract": canonical_contract(contract),
        "scenario": canonical_json(scenario),
        "event": canonical_json(event),
        "tool": canonical_json(scenario.setup.tools[0]),
    }
    for name, text in actual.items():
        assert text + "\n" == (ROOT / f"tests/golden/{name}.json").read_text()


@pytest.mark.parametrize(
    "args",
    [
        ["version"],
        ["contract", "validate", str(ROOT / "examples/contracts/research.yaml")],
        ["scenario", "validate", str(ROOT / "examples/scenarios/indirect-injection.yaml")],
        ["examples", "validate", "--root", str(ROOT / "examples")],
    ],
)
def test_cli_success(args):
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    if args[0] == "version":
        assert result.output.strip() == __version__
    else:
        assert "VALID" in result.output
    if args[0] == "contract":
        for name in ["contract_id", "schema_version", "document_hash", "effective_policy_hash"]:
            assert name + ":" in result.output


@pytest.mark.parametrize(
    "args,code",
    [
        (
            ["contract", "validate", str(ROOT / "tests/fixtures/contracts/unknown-field.yaml")],
            "UNKNOWN_FIELD",
        ),
        (["contract", "validate", "does-not-exist.yaml"], "PATH_ERROR"),
        (
            ["scenario", "validate", str(ROOT / "tests/fixtures/scenarios/unknown-assertion.yaml")],
            "UNKNOWN_ASSERTION_TYPE",
        ),
        (["examples", "validate", "--root", "does-not-exist"], "PATH_ERROR"),
    ],
)
def test_cli_errors(args, code):
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    assert code in result.output
    assert "Traceback" not in result.output


def test_cli_schema_export_and_file_error(tmp_path):
    result = runner.invoke(app, ["schema", "export", "--out", str(tmp_path / "schemas")])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "schemas/scenario.schema.json").exists()
    blocked = tmp_path / "blocked"
    blocked.write_text("file")
    result = runner.invoke(app, ["schema", "export", "--out", str(blocked)])
    assert result.exit_code == 1
    assert "PATH_ERROR" in result.output


@pytest.mark.parametrize("command", ["eval", "protect", "replay"])
def test_no_future_commands(command):
    result = runner.invoke(app, [command])
    assert result.exit_code == 2


def test_cli_examples_reports_invalid_file(tmp_path):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "contracts/bad.yaml").write_text('schema_version: "99"')
    (tmp_path / "scenarios/example.yaml").write_bytes(
        (ROOT / "examples/scenarios/indirect-injection.yaml").read_bytes()
    )
    result = runner.invoke(app, ["examples", "validate", "--root", str(tmp_path)])
    assert result.exit_code == 1
    assert "UNSUPPORTED_SCHEMA_VERSION" in result.output
