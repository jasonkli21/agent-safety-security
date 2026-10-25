"""Local validation, evaluation, schema tooling, and MCP runtime protection."""

from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer

from agentsec.cli.contract import register_contract_commands
from agentsec.cli.enterprise import app as enterprise_app
from agentsec.cli.evaluation import app as eval_app
from agentsec.cli.graph import app as graph_app
from agentsec.cli.protect import app as protect_app
from agentsec.cli.replay import incident_app, regression_app, replay_app
from agentsec.cli.team import app as team_app
from agentsec.cli.trust import app as trust_app
from agentsec.contracts.canonical import document_hash, effective_policy_hash
from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import load_artifact, load_contract, load_contracts
from agentsec.contracts.schema_export import export_schemas
from agentsec.domain.scenarios import Scenario
from agentsec.version import __version__

app = typer.Typer(no_args_is_help=True)
contract_app = typer.Typer(no_args_is_help=True)
scenario_app = typer.Typer(no_args_is_help=True)
schema_app = typer.Typer(no_args_is_help=True)
examples_app = typer.Typer(no_args_is_help=True)
team_app.add_typer(enterprise_app, name="enterprise")
app.add_typer(team_app, name="team")
app.add_typer(graph_app, name="graph")
app.add_typer(trust_app, name="trust")
app.add_typer(replay_app, name="replay")
app.add_typer(incident_app, name="incident")
app.add_typer(regression_app, name="regression")
app.add_typer(eval_app, name="eval")
app.add_typer(protect_app, name="protect")
app.add_typer(contract_app, name="contract")
app.add_typer(scenario_app, name="scenario")
app.add_typer(schema_app, name="schema")
app.add_typer(examples_app, name="examples")


def checked(operation: Callable[[], None]) -> None:
    try:
        operation()
    except ArtifactValidationError as exc:
        for issue in exc.issues:
            typer.echo(f"{issue.code}: {issue.path}: {issue.message}", err=True)
        raise typer.Exit(1) from exc
    except OSError as exc:
        typer.echo(f"PATH_ERROR: {exc.strerror}", err=True)
        raise typer.Exit(1) from exc


@app.command()
def version() -> None:
    """Report the installed package version."""
    typer.echo(__version__)


@contract_app.command("validate")
def contract_validate(path: Path) -> None:
    """Validate a contract and print its explicitly named identities."""

    def operation() -> None:
        contract = load_contract(path)
        typer.echo(
            f"VALID\ncontract_id: {contract.metadata.contract_id}\n"
            f"schema_version: {contract.schema_version}"
        )
        typer.echo(f"document_hash: {document_hash(contract)}")
        typer.echo(f"effective_policy_hash: {effective_policy_hash(contract)}")

    checked(operation)


@scenario_app.command("validate")
def scenario_validate(path: Path) -> None:
    """Validate a static scenario without executing it."""

    def operation() -> None:
        scenario = load_artifact(path, Scenario)
        typer.echo(
            f"VALID\nscenario_id: {scenario.scenario_id}\nschema_version: {scenario.schema_version}"
        )

    checked(operation)


@schema_app.command("export")
def schema_export(out: Annotated[Path, typer.Option()] = Path("schemas/generated")) -> None:
    """Export current JSON Schemas."""
    checked(lambda: export_schemas(out))
    typer.echo(f"EXPORTED: {out}")


@examples_app.command("validate")
def examples_validate(
    root: Annotated[Path, typer.Option(help="Public examples directory")] = Path("examples"),
) -> None:
    """Validate the public corpus from the repository (or --root directory)."""

    def operation() -> None:
        contracts = sorted(
            p for p in (root / "contracts").glob("*") if p.suffix in {".json", ".yaml", ".yml"}
        )
        scenarios = sorted(
            p for p in (root / "scenarios").glob("*") if p.suffix in {".json", ".yaml", ".yml"}
        )
        if not contracts or not scenarios:
            from agentsec.contracts.errors import ErrorCode, fail

            fail(ErrorCode.PATH_ERROR, "Examples corpus is missing or empty", str(root))
        load_contracts(contracts)
        ids: set[str] = set()
        for path in scenarios:
            scenario = load_artifact(path, Scenario)
            if scenario.scenario_id in ids:
                from agentsec.contracts.errors import ErrorCode, fail

                fail(ErrorCode.DUPLICATE_ID, "Duplicate scenario ID", str(path))
            ids.add(scenario.scenario_id)
        typer.echo(f"VALID: {len(contracts)} contracts, {len(scenarios)} scenarios")

    checked(operation)


register_contract_commands(contract_app)


if __name__ == "__main__":
    app()
