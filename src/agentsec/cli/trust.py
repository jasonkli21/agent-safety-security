"""Offline inspection, proposed pins, verification and safe machine-readable reports."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.runtime.bindings import ProtectedTool
from agentsec.runtime.models import RuntimeFailure
from agentsec.supply_chain.inspection import (
    artifact_digest,
    declared_dependencies,
    diff,
    propose,
    scan,
)
from agentsec.supply_chain.io import load_json
from agentsec.supply_chain.models import DependencyManifest, Inventory, Signature, TrustLock
from agentsec.supply_chain.verification import assess

app = typer.Typer(no_args_is_help=True)


def _error(exc: Exception) -> None:
    typer.echo(exc.code if isinstance(exc, RuntimeFailure) else "TRUST_INPUT_INVALID", err=True)
    raise typer.Exit(1) from None


@app.command("inspect")
def inspect(
    protected_tool: Annotated[Path | None, typer.Option()] = None,
    mcp_config: Annotated[Path | None, typer.Option()] = None,
    mcp_tools: Annotated[
        Path | None, typer.Option(help="Previously captured ListToolsResult JSON")
    ] = None,
    pyproject: Annotated[Path | None, typer.Option()] = None,
    artifact: Annotated[
        Path | None, typer.Option(help="Local bytes; never executed-code proof")
    ] = None,
    dependencies: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Observe static protected registration or captured MCP discovery; never run tools."""
    try:
        if pyproject:
            if protected_tool or mcp_config or mcp_tools:
                raise RuntimeFailure("TRUST_INPUT_INVALID")
            typer.echo(canonical_json(declared_dependencies(pyproject.absolute())))
            return
        # Use identical route builders to registration, without starting a gateway.
        from agentsec.supply_chain.registration import inspect_mcp, inspect_protected

        if protected_tool and not mcp_config and not mcp_tools:
            inventory = Inventory(
                schema_version="0.1",
                candidates=(inspect_protected(load_json(protected_tool, ProtectedTool)),),
            )
        elif mcp_config and mcp_tools and not protected_tool:
            from mcp.types import ListToolsResult

            from agentsec.adapters.mcp.config import McpGatewayConfig
            from agentsec.contracts.loader import load_artifact

            inventory = inspect_mcp(
                load_artifact(mcp_config, McpGatewayConfig),
                load_json(mcp_tools, ListToolsResult),
            )
        else:
            raise RuntimeFailure("TRUST_INPUT_INVALID")
        if artifact or dependencies:
            if artifact and len(inventory.candidates) != 1:
                raise RuntimeFailure("TRUST_ARTIFACT_SCOPE_AMBIGUOUS")
            updates: dict[str, object] = {}
            if artifact:
                updates.update(
                    artifact_digest=artifact_digest(artifact.absolute()),
                    implementation_proof="LOCAL_BYTES",
                )
            if dependencies:
                updates["dependency_digest"] = content_digest(
                    load_json(dependencies, DependencyManifest)
                )
            inventory = Inventory(
                schema_version="0.1",
                candidates=tuple(
                    type(c).model_validate(c.model_dump() | updates) for c in inventory.candidates
                ),
            )
        typer.echo(canonical_json(inventory))
    except Exception as exc:
        _error(exc)


@app.command("propose")
def proposed_lock(inventory: Path, generation: str = "review-1") -> None:
    """Emit an UNREVIEWED proposal; never apply pins or promote trust automatically."""
    try:
        typer.echo(canonical_json(propose(load_json(inventory, Inventory), generation)))
    except (RuntimeFailure, ValidationError) as exc:
        _error(exc)


@app.command("scan")
def scan_inventory(inventory: Path, lock: Annotated[Path | None, typer.Option()] = None) -> None:
    """Explain deterministic advisory risk findings without granting authority."""
    try:
        typer.echo(
            canonical_json(
                scan(load_json(inventory, Inventory), load_json(lock, TrustLock) if lock else None)
            )
        )
    except RuntimeFailure as exc:
        _error(exc)


@app.command("diff")
def diff_inventory(before: Path, after: Path, format: str = "json") -> None:
    """Compare observed fields; missing implementation/dependency evidence is incomplete."""
    try:
        result = diff(load_json(before, Inventory), load_json(after, Inventory))
        if format == "json":
            typer.echo(canonical_json(result))
        elif format == "text":
            for change in result.changes:
                typer.echo(f"{change.status} {change.target} {','.join(change.fields)}")
        else:
            raise RuntimeFailure("TRUST_FORMAT_INVALID")
    except RuntimeFailure as exc:
        _error(exc)


@app.command("verify")
def verify_inventory(
    inventory: Path,
    lock: Annotated[Path, typer.Option()],
    signature: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Verify observations against separate operator pins/keys; no online verification."""
    try:
        candidates = load_json(inventory, Inventory)
        if not candidates.candidates:
            raise RuntimeFailure("TRUST_CANDIDATE_UNOBSERVED")
        baseline = load_json(lock, TrustLock)
        proof = load_json(signature, Signature) if signature else None
        results = tuple(
            assess(
                c,
                baseline,
                datetime.now(UTC),
                proof
                or next(
                    (p for p in candidates.signatures if p.candidate_id == c.candidate_id), None
                ),
            )
            for c in candidates.candidates
        )
        typer.echo(canonical_json(results))
        if not all(r.admitted for r in results):
            raise typer.Exit(1)
    except RuntimeFailure as exc:
        _error(exc)
