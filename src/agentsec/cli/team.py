"""Explicit offline setup and optional loopback HTTP service; no ambient credentials."""

from pathlib import Path
from typing import Annotated

import typer

from agentsec.contracts.loader import load_artifact
from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import Binding, TeamConfig
from agentsec.control_plane.service import TeamService
from agentsec.control_plane.store import Store

app = typer.Typer(no_args_is_help=True)


def fail(exc: Exception) -> None:
    typer.echo(exc.code if isinstance(exc, TeamError) else "TEAM_OPERATION_FAILED", err=True)
    raise typer.Exit(1) from None


@app.command("init")
def init(db: Path, config: Path, owner: Path, org: str) -> None:
    """Explicitly create private SQLite storage and bootstrap a verified human binding."""
    try:
        settings = load_artifact(config, TeamConfig)
        binding = load_artifact(owner, Binding)
        from agentsec.control_plane.auth import TeamVerifier

        TeamVerifier(settings)
        store = Store(db, initialize=True)
        store.provision(binding)
        TeamService(store, settings).bootstrap(org, binding)
        store.close()
        typer.echo("INITIALIZED team-v1")
    except Exception as exc:
        fail(exc)


@app.command("provision")
def provision(db: Path, binding: Path) -> None:
    """Offline operator provisioning; never issue a token or runtime identity."""
    try:
        store = Store(db)
        store.provision(load_artifact(binding, Binding))
        store.close()
        typer.echo("PROVISIONED")
    except Exception as exc:
        fail(exc)


@app.command("serve")
def serve(
    db: Path,
    config: Path,
    host: Annotated[str, typer.Option()] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1024, max=65535)] = 8765,
) -> None:
    """Serve synthetic local clients only. Public TLS/proxy deployment is deferred."""
    if host not in {"127.0.0.1", "::1"}:
        fail(TeamError("INVALID_INPUT"))
    try:
        import uvicorn

        from agentsec.control_plane.api import create_app

        store = Store(db)
        application = create_app(TeamService(store, load_artifact(config, TeamConfig)))
        uvicorn.run(
            application,
            host=host,
            port=port,
            access_log=False,
            log_level="critical",
            limit_concurrency=16,
            timeout_keep_alive=5,
            proxy_headers=False,
        )
    except Exception as exc:
        fail(exc)


@app.command("posture")
def posture(db: Path, config: Path, token_file: Path, org: str) -> None:
    """Inspect scoped posture locally with an explicit protected credential file."""
    try:
        from agentsec.control_plane.auth import TeamVerifier
        from agentsec.identity.ingress import read_credential

        settings = load_artifact(config, TeamConfig)
        store = Store(db)
        service = TeamService(store, settings)
        identity = TeamVerifier(settings).verify(read_credential(token_file), service.clock())
        result = service.posture(identity, org)
        typer.echo(result.model_dump_json(indent=2))
        store.close()
    except Exception as exc:
        fail(exc)
