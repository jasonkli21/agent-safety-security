"""Stdio protocol owns stdout; operational diagnostics are bounded safe stderr codes."""

import asyncio
import logging
from pathlib import Path
from typing import Annotated

import typer

from agentsec.adapters.mcp.config import McpGatewayConfig
from agentsec.adapters.mcp.coverage import configured_resource_coverage_gaps
from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import load_artifact, load_contract
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.taxonomy import EnforcementMode
from agentsec.evidence.jsonl import EvidenceError, JsonlEventSink
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.evidence.ports import EventSink
from agentsec.policy.coverage import coverage_gaps
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure
from agentsec.runtime.terminal_approval import TerminalApprovalBroker

app = typer.Typer(no_args_is_help=True)


async def run(contract: AgentSecurityContract, config: McpGatewayConfig, sink: EventSink) -> None:
    from agentsec.adapters.mcp.server import create_server, serve_stdio
    from agentsec.adapters.mcp.upstream import connect

    # SDK diagnostics can embed invalid wire payloads. CLI emits only our safe codes.
    sdk_logger = logging.getLogger("mcp")
    sdk_logger.addHandler(logging.NullHandler())
    sdk_logger.propagate = False
    events = RuntimeEvents(
        sink,
        required=config.mode == EnforcementMode.ENFORCE,
        on_failure=lambda: typer.echo("EVIDENCE_WRITE_FAILURE", err=True),
    )
    runtime = RuntimeGateway(contract, config.mode, events, TerminalApprovalBroker())
    async with connect(config.upstream) as client:
        server, gaps = await create_server(client, config, runtime)
        for gap in gaps:
            typer.echo(f"COVERAGE_GAP: {gap}", err=True)
        try:
            await serve_stdio(server)
        finally:
            runtime.finish()
        if events.failed:
            raise RuntimeFailure("EVIDENCE_WRITE_FAILURE")


@app.command("mcp")
def protect_mcp(
    contract: Annotated[Path, typer.Option()],
    config: Annotated[Path, typer.Option()],
    evidence_out: Annotated[Path | None, typer.Option()] = None,
    check: Annotated[
        bool, typer.Option(help="Validate config/coverage without connecting upstream")
    ] = False,
) -> None:
    """Protect tools with an explicit contract and operational gateway config."""
    try:
        loaded_contract = load_contract(contract)
        loaded_config = load_artifact(config, McpGatewayConfig)
        contract_gaps = coverage_gaps(loaded_contract)
        resource_gaps = configured_resource_coverage_gaps(
            loaded_contract, loaded_config.tool_bindings
        )
        gaps = (*contract_gaps, *resource_gaps)
        if loaded_config.mode == EnforcementMode.ENFORCE and contract_gaps:
            raise RuntimeFailure("UNSUPPORTED_POLICY_SEMANTICS")
        for gap in gaps:
            typer.echo(f"COVERAGE_GAP: {gap}", err=True)
        if loaded_config.mode == EnforcementMode.ENFORCE and resource_gaps:
            raise RuntimeFailure("UNSUPPORTED_RESOURCE_COVERAGE")
        typer.echo(f"agentsec MCP mode: {loaded_config.mode}", err=True)
        if check:
            return
        try:
            import mcp  # noqa: F401
        except ImportError as exc:
            raise RuntimeFailure(
                "MCP_DEPENDENCY_MISSING: install agent-safety-security[mcp]"
            ) from exc
        if evidence_out is not None:
            if evidence_out.resolve() in {contract.resolve(), config.resolve()}:
                raise RuntimeFailure("OUTPUT_PATH_COLLISION")
            # Exclusive creation prevents overwriting protected inputs, executables or old audit.
            with JsonlEventSink(evidence_out, exclusive=True) as sink:
                asyncio.run(run(loaded_contract, loaded_config, sink))
        else:
            asyncio.run(run(loaded_contract, loaded_config, InMemoryEventSink()))
    except (RuntimeFailure, EvidenceError) as exc:
        typer.echo(exc.code, err=True)
        raise typer.Exit(1) from exc
    except ArtifactValidationError as exc:
        typer.echo(
            "INVALID_GATEWAY_INPUT: " + ",".join(sorted({i.code for i in exc.issues})), err=True
        )
        raise typer.Exit(1) from exc
    except Exception as exc:
        typer.echo("GATEWAY_SETUP_OR_TRANSPORT_FAILURE", err=True)
        raise typer.Exit(1) from exc
