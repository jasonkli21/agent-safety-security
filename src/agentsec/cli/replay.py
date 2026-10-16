"""Offline lifecycle commands with bounded strict inputs and exclusive outputs."""

from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from pydantic import BaseModel, ValidationError

from agentsec.compiler import compile_contract
from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import MAX_BYTES, load_artifact, load_contract
from agentsec.domain.authority import AuthorityContext
from agentsec.domain.events import RunStartedPayload
from agentsec.domain.replay import Incident, ReplayBundle, ReplayError
from agentsec.domain.scenarios import Scenario
from agentsec.domain.serialization import canonical_json
from agentsec.domain.taxonomy import SecurityCategory
from agentsec.eval.models import EvaluationResult
from agentsec.evidence.jsonl import EvidenceError, read_jsonl
from agentsec.incident.classify import classify
from agentsec.incident.promote import promote
from agentsec.regression.runner import load_corpus, run_case
from agentsec.replay.bundle import create_bundle, validate_bundle
from agentsec.replay.engine import replay

replay_app = typer.Typer(no_args_is_help=True)
bundle_app = typer.Typer(no_args_is_help=True)
incident_app = typer.Typer(no_args_is_help=True)
regression_app = typer.Typer(no_args_is_help=True)
replay_app.add_typer(bundle_app, name="bundle")


def checked(operation: Callable[[], object]) -> None:
    try:
        operation()
    except (ReplayError, EvidenceError) as exc:
        typer.echo(exc.code, err=True)
        raise typer.Exit(4) from exc
    except (ArtifactValidationError, ValidationError):
        typer.echo("INVALID_ARTIFACT", err=True)
        raise typer.Exit(4) from None
    except (OSError, UnicodeError):
        typer.echo("OUTPUT_COLLISION_OR_PATH_ERROR", err=True)
        raise typer.Exit(4) from None


def output(value: BaseModel, out: Path | None) -> None:
    encoded = canonical_json(value) + "\n"
    if out is not None:
        with out.open("x", encoding="utf-8") as stream:
            stream.write(encoded)
    typer.echo(encoded.rstrip())


def load_bundle(path: Path) -> ReplayBundle:
    return validate_bundle(load_artifact(path, ReplayBundle))


@bundle_app.command("create")
def bundle_create(
    evidence: Annotated[Path, typer.Option()],
    contract: Annotated[Path, typer.Option()],
    out: Annotated[Path, typer.Option()],
    scenario: Annotated[Path | None, typer.Option()] = None,
    report: Annotated[Path | None, typer.Option()] = None,
    authority: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Package source evidence; optional scenario supplies tools and explicit expectations."""

    def operation() -> None:
        spec = load_artifact(scenario, Scenario) if scenario else None
        source_report = load_artifact(report, EvaluationResult) if report else None
        source_events = read_jsonl(evidence, max_bytes=MAX_BYTES)
        if source_report is not None and (
            not source_events
            or (
                source_report.run_id,
                source_report.trace_id,
            )
            != (source_events[0].run_id, source_events[0].trace_id)
        ):
            raise ReplayError("SOURCE_REPORT_MISMATCH")
        if source_report is not None and (
            not isinstance(source_events[0].payload, RunStartedPayload)
            or source_report.contract_id != source_events[0].payload.contract_id
            or source_report.effective_policy_hash != source_events[0].payload.effective_policy_hash
        ):
            raise ReplayError("SOURCE_REPORT_MISMATCH")
        output(
            create_bundle(
                source_events,
                load_contract(contract),
                tools=spec.setup.tools if spec else (),
                expectations=spec.assertions if spec else (),
                findings=source_report.findings if source_report else (),
                authority=load_artifact(authority, AuthorityContext) if authority else None,
            ),
            out,
        )

    checked(operation)


@replay_app.command("run")
def replay_run(
    bundle: Annotated[Path, typer.Option()],
    contract: Annotated[Path | None, typer.Option()] = None,
    out: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Emit deterministic JSON. Code 3 means incomplete; semantic drift alone is not failure."""

    def operation() -> None:
        result = replay(load_bundle(bundle), load_contract(contract) if contract else None)
        output(result, out)
        if result.assessment.blockers or result.diff.status == "INCOMPLETE":
            raise typer.Exit(3)

    checked(operation)


@incident_app.command("classify")
def incident_classify(
    bundle: Annotated[Path, typer.Option()],
    out: Annotated[Path, typer.Option()],
    category: Annotated[SecurityCategory | None, typer.Option()] = None,
) -> None:
    checked(lambda: output(classify(load_bundle(bundle), category), out))


@incident_app.command("promote")
def incident_promote(
    bundle: Annotated[Path, typer.Option()],
    incident: Annotated[Path, typer.Option()],
    out: Annotated[Path, typer.Option()],
    contract: Annotated[Path | None, typer.Option()] = None,
) -> None:
    checked(
        lambda: output(
            promote(
                load_bundle(bundle),
                load_artifact(incident, Incident),
                load_contract(contract) if contract else None,
            ),
            out,
        )
    )


@regression_app.command("validate")
def regression_validate(root: Annotated[Path, typer.Option()]) -> None:
    checked(lambda: typer.echo(canonical_json({"validated": len(load_corpus(root))})))


@regression_app.command("run")
def regression_run(
    root: Annotated[Path, typer.Option()],
    contract: Annotated[Path | None, typer.Option()] = None,
) -> None:
    def operation() -> None:
        candidate = compile_contract(load_contract(contract)) if contract else None
        results = [
            {"regression_id": c.regression_id, "status": run_case(c, candidate)}
            for c in load_corpus(root)
        ]
        typer.echo(canonical_json({"results": results}))
        if any(r["status"] in {"FAIL", "ERROR"} for r in results):
            raise typer.Exit(1)
        if not any(r["status"] == "PASS" for r in results):
            raise typer.Exit(3)

    checked(operation)
