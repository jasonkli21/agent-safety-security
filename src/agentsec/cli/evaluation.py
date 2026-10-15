"""Executable local evaluation commands."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import load_artifact, load_contract
from agentsec.domain.scenarios import Scenario
from agentsec.eval.fixtures import FixtureTarget, TargetFixture
from agentsec.eval.models import EvaluationStatus, aggregate
from agentsec.eval.reporting import EXIT_CODES, render_report
from agentsec.eval.runner import evaluate

app = typer.Typer(no_args_is_help=True)


class ReportFormat(StrEnum):
    TEXT = "text"
    JSON = "json"


@app.command("run")
def run(
    contract: Annotated[Path, typer.Option()],
    scenario: Annotated[Path, typer.Option()],
    fixture: Annotated[Path, typer.Option()],
    format: Annotated[ReportFormat, typer.Option()] = ReportFormat.TEXT,
    report_out: Annotated[Path | None, typer.Option()] = None,
    evidence_out: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Evaluate a scripted target locally; no network or production enforcement."""
    try:
        # Prevent accidental truncation of any input or collision of output streams.
        inputs = {p.resolve() for p in (contract, scenario, fixture)}
        outputs = [p.resolve() for p in (report_out, evidence_out) if p is not None]
        if any(p in inputs for p in outputs) or len(outputs) != len(set(outputs)):
            typer.echo("OUTPUT_PATH_COLLISION", err=True)
            raise typer.Exit(4)
        result = evaluate(
            contract=load_contract(contract),
            scenario=load_artifact(scenario, Scenario),
            target=FixtureTarget(load_artifact(fixture, TargetFixture)),
            evidence_out=evidence_out,
        )
        report = render_report(result, format.value)
        if report_out is not None:
            report_out.write_text(report + "\n", encoding="utf-8")
        typer.echo(report)
        if result.error_code:
            typer.echo(result.error_code, err=True)
        raise typer.Exit(EXIT_CODES[result.overall_status])
    except ArtifactValidationError as exc:
        # Do not echo user-controlled validation messages, paths, or raw fixture data.
        typer.echo(
            "INVALID_EVALUATION_INPUT: " + ", ".join(sorted({i.code.value for i in exc.issues})),
            err=True,
        )
        raise typer.Exit(4) from exc
    except (OSError, UnicodeError) as exc:
        typer.echo("REPORT_WRITE_FAILURE", err=True)
        raise typer.Exit(4) from exc


@app.command("examples")
def examples(root: Annotated[Path, typer.Option()] = Path("examples")) -> None:
    """Gate six known safe/vulnerable fixtures against their expected outcomes."""
    cases = (
        ("indirect-injection", "safe", EvaluationStatus.PASS),
        ("indirect-injection", "vulnerable", EvaluationStatus.FAIL),
        ("canary-exfiltration", "protected", EvaluationStatus.PASS),
        ("canary-exfiltration", "leak", EvaluationStatus.FAIL),
        ("resource-exhaustion", "contained", EvaluationStatus.PASS),
        ("resource-exhaustion", "runaway", EvaluationStatus.FAIL),
    )
    gate_statuses: list[EvaluationStatus] = []
    try:
        contract = load_contract(root / "contracts/research.yaml")
        for scenario_id, variant, expected in cases:
            name = f"{scenario_id}-{variant}"
            result = evaluate(
                contract=contract,
                scenario=load_artifact(root / f"scenarios/{scenario_id}.yaml", Scenario),
                target=FixtureTarget(
                    load_artifact(root / f"eval-fixtures/{name}.yaml", TargetFixture)
                ),
            )
            match = (
                result.overall_status == expected
                and result.security_status == expected
                and result.utility_status == EvaluationStatus.PASS
            )
            if result.overall_status == EvaluationStatus.ERROR:
                gate_status = EvaluationStatus.ERROR
            elif result.overall_status == EvaluationStatus.INCONCLUSIVE:
                gate_status = EvaluationStatus.INCONCLUSIVE
            else:
                gate_status = EvaluationStatus.PASS if match else EvaluationStatus.FAIL
            gate_statuses.append(gate_status)
            typer.echo(
                f"{'MATCH' if match else 'MISMATCH'} {name}: "
                f"{result.overall_status} (expected {expected}; gate {gate_status})"
            )
    except ArtifactValidationError as exc:
        typer.echo("INVALID_EXAMPLE_INPUT", err=True)
        raise typer.Exit(4) from exc
    raise typer.Exit(EXIT_CODES[aggregate(tuple(gate_statuses))])
