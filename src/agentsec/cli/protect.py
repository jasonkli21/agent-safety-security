"""Stdio protocol owns stdout; operational diagnostics are bounded safe stderr codes."""

import asyncio
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from agentsec.adapters.mcp.config import McpGatewayConfig, StdioUpstream
from agentsec.adapters.mcp.coverage import configured_resource_coverage_gaps
from agentsec.contracts.errors import ArtifactValidationError
from agentsec.contracts.loader import load_artifact, load_contract
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.authority import AuthorityContext
from agentsec.domain.serialization import canonical_json
from agentsec.domain.taxonomy import EnforcementMode
from agentsec.evidence.jsonl import EvidenceError, JsonlEventSink
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.evidence.ports import EventSink
from agentsec.identity.authority import authority_failure
from agentsec.identity.config import JwtIdentityConfig
from agentsec.identity.ports import IdentityError
from agentsec.identity.setup import bind_authority, configured_provider
from agentsec.policy.coverage import coverage_gaps
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure
from agentsec.runtime.terminal_approval import TerminalApprovalBroker
from agentsec.supply_chain.guard import TrustGuard
from agentsec.supply_chain.io import load_json
from agentsec.supply_chain.models import TrustInputs, TrustLock

app = typer.Typer(no_args_is_help=True)


async def run(
    contract: AgentSecurityContract,
    config: McpGatewayConfig,
    sink: EventSink,
    credential_file: Path | None = None,
    trust_guard: TrustGuard | None = None,
) -> None:
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
    if (
        trust_guard is not None
        and config.mode == EnforcementMode.ENFORCE
        and isinstance(config.upstream, StdioUpstream)
        and config.upstream.launch_boundary != "operator_managed"
    ):
        # This check runs before connect() can ask the SDK to spawn the candidate.
        raise RuntimeFailure("TRUST_STDIO_LAUNCH_BOUNDARY_REQUIRED")
    authority = None
    identity_error = None
    try:
        authority = bind_authority(
            config.identity,
            contract.identity.principal,
            config.delegation,
            credential_file,
            events.clock(),
        )
    except IdentityError as exc:
        if config.mode == EnforcementMode.ENFORCE:
            raise RuntimeFailure(exc.code) from None
        identity_error = exc.code
    runtime = RuntimeGateway(
        contract,
        config.mode,
        events,
        TerminalApprovalBroker(),
        authority=authority,
        identity_error=identity_error,
        trust_guard=trust_guard,
    )
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
    trust_lock: Annotated[
        Path | None, typer.Option(help="Protected operator-reviewed trust lock")
    ] = None,
    trust_inputs: Annotated[
        Path | None, typer.Option(help="Protected signature/artifact inputs")
    ] = None,
    credential_file: Annotated[
        Path | None, typer.Option(help="Protected out-of-band JWT file")
    ] = None,
    check: Annotated[
        bool, typer.Option(help="Validate config/coverage without connecting upstream")
    ] = False,
) -> None:
    """Protect tools with an explicit contract and operational gateway config."""
    try:
        if trust_inputs and not trust_lock:
            raise RuntimeFailure("TRUST_LOCK_REQUIRED")
        inputs = load_json(trust_inputs, TrustInputs) if trust_inputs else None
        guard = (
            TrustGuard(
                load_json(trust_lock, TrustLock),
                signatures=inputs.signatures if inputs else (),
                artifacts={a.candidate_id: Path(a.path) for a in inputs.artifacts}
                if inputs
                else None,
                dependencies=inputs.dependencies if inputs else None,
            )
            if trust_lock
            else None
        )
        loaded_contract = load_contract(contract)
        loaded_config = load_artifact(config, McpGatewayConfig)
        if (
            trust_lock
            and loaded_config.mode == EnforcementMode.ENFORCE
            and isinstance(loaded_config.upstream, StdioUpstream)
            and loaded_config.upstream.launch_boundary != "operator_managed"
        ):
            raise RuntimeFailure("TRUST_STDIO_LAUNCH_BOUNDARY_REQUIRED")
        configured_provider(loaded_config.identity, loaded_contract.identity.principal)
        # Configuration coverage only: JWT proof is deliberately not required by --check.
        from agentsec.identity.static import StaticIdentityProvider

        cfg = loaded_config.identity
        expected = (
            cfg.principal
            if cfg is not None and not isinstance(cfg, JwtIdentityConfig)
            else loaded_contract.identity.principal
        )
        if isinstance(cfg, JwtIdentityConfig) and not any(
            s.principal == loaded_contract.identity.principal for s in cfg.subjects
        ):
            raise RuntimeFailure("IDENTITY_PRINCIPAL_UNMAPPED")
        check_authority = AuthorityContext(
            schema_version="0.1",
            credential=StaticIdentityProvider(expected).verify(None, datetime.now(UTC)),
            delegation_json=canonical_json(loaded_config.delegation)
            if loaded_config.delegation
            else None,
        )
        failure = authority_failure(
            check_authority,
            loaded_contract.identity.principal,
            loaded_contract.identity.acts_on_behalf_of,
            loaded_contract.task_scope,
            datetime.now(UTC),
        )
        if failure and loaded_config.mode == EnforcementMode.ENFORCE:
            raise RuntimeFailure(failure.value)
        if failure:
            typer.echo(f"AUTHORITY_COVERAGE: {failure.value}", err=True)
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
            if evidence_out.resolve() in {
                contract.resolve(),
                config.resolve(),
                *([trust_lock.resolve()] if trust_lock else []),
                *([trust_inputs.resolve()] if trust_inputs else []),
            }:
                raise RuntimeFailure("OUTPUT_PATH_COLLISION")
            # Exclusive creation prevents overwriting protected inputs, executables or old audit.
            with JsonlEventSink(evidence_out, exclusive=True) as sink:
                asyncio.run(run(loaded_contract, loaded_config, sink, credential_file, guard))
        else:
            asyncio.run(
                run(loaded_contract, loaded_config, InMemoryEventSink(), credential_file, guard)
            )
    except (RuntimeFailure, EvidenceError, IdentityError) as exc:
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
