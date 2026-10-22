"""Strict offline graph inspection; no enrollment, credentials or effects."""

from pathlib import Path
from typing import Annotated

import typer

from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import load_artifact
from agentsec.domain.graph import GraphSnapshot
from agentsec.domain.serialization import canonical_json
from agentsec.multi_agent.regression import GraphRegressionCase, run_graph_case
from agentsec.multi_agent.replay import GraphReplayInput, replay_graph

app = typer.Typer(no_args_is_help=True)


@app.command("validate")
def validate(config: Annotated[Path, typer.Option()]) -> None:
    try:
        graph = load_artifact(config, GraphSnapshot)
    except (ArtifactValidationError, OSError, ValueError) as exc:
        typer.echo("GRAPH_INPUT_INVALID", err=True)
        raise typer.Exit(1) from exc
    typer.echo(
        canonical_json(
            {
                "schema_version": "0.1",
                "digest": graph.digest,
                "generation": graph.generation,
                "node_count": len(graph.nodes),
                "maximum_depth": max(len(graph.path(n.node_id)) for n in graph.nodes),
                "status": "STRUCTURALLY_VALID_NOT_AUTHENTICATED",
            }
        )
    )


@app.command("replay")
def replay_command(config: Annotated[Path, typer.Option()]) -> None:
    """Reconstruct recorded local graph facts offline, never deliver messages."""
    try:
        source = load_artifact(config, GraphReplayInput)
        result = replay_graph(source)
    except (ArtifactValidationError, OSError, ValueError) as exc:
        typer.echo("GRAPH_REPLAY_INPUT_INVALID", err=True)
        raise typer.Exit(1) from exc
    typer.echo(canonical_json(result))
    if result.blockers:
        raise typer.Exit(1)


@app.command("regression")
def regression_command(
    case: Annotated[Path, typer.Option()],
    source: Annotated[Path, typer.Option()],
) -> None:
    """Run a minimal incident manifest with separately protected session replay material."""
    try:
        result = run_graph_case(
            load_artifact(case, GraphRegressionCase), load_artifact(source, GraphReplayInput)
        )
    except (ArtifactValidationError, OSError, ValueError) as exc:
        typer.echo("GRAPH_REGRESSION_INPUT_INVALID", err=True)
        raise typer.Exit(1) from exc
    typer.echo(canonical_json(result))
    if result.status != "PASS":
        raise typer.Exit(1)
