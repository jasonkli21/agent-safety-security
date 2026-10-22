"""Actual protected native/provider/MCP calls through enrolled graph gateways."""

import asyncio
import importlib.util
from pathlib import Path

import pytest

from agentsec.adapters.providers import ProviderTools
from agentsec.domain.taxonomy import DataLabel
from agentsec.multi_agent.messaging import MessageRoute
from agentsec.runtime.models import RuntimeFailure

ROOT = Path(__file__).resolve().parents[2]


def demo():
    spec = importlib.util.spec_from_file_location(
        "graph_demo", ROOT / "examples/multi_agent/local_session.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_executable_vertical_slice():
    asyncio.run(demo().main())


def test_provider_rebind_preserves_ancestor_deny_and_message_labels():
    async def run():
        module = demo()
        session, gateways, _ = module.build_session(budget=10)
        provider = ProviderTools("openai", (module.read_tool(gateways["c"]),))
        assert (
            await provider.invoke(
                {"type": "function", "function": {"name": "read", "arguments": "{}"}}
            )
        ).success
        write = ProviderTools("openai", (module.read_tool(gateways["c"], "filesystem.write"),))
        with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
            await write.invoke(
                {"type": "function", "function": {"name": "read", "arguments": "{}"}}
            )
        await MessageRoute(session, "c", "b").send("explicit response direction")
        assert session.receive("b") == ("explicit response direction",)
        assert all(DataLabel.SECRET in r.labels for r in gateways["b"].provenance.snapshot())

    asyncio.run(run())


def test_real_mcp_ingress_cannot_omit_enrolled_graph_guard():
    mcp = pytest.importorskip("mcp")
    from mcp import types
    from mcp.server.lowlevel import Server

    from agentsec.adapters.mcp.config import McpGatewayConfig
    from agentsec.adapters.mcp.server import create_server
    from agentsec.domain.serialization import canonical_json

    async def run():
        module = demo()
        session, gateways, _ = module.build_session(budget=5)
        attempts = []

        async def listing(ctx, params):
            return types.ListToolsResult(
                tools=[
                    types.Tool(
                        name="read", description="synthetic", input_schema={"type": "object"}
                    )
                ]
            )

        async def dispatch(ctx, params):
            attempts.append(params.name)
            return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

        config = McpGatewayConfig.model_validate_json(
            canonical_json(
                {
                    "schema_version": "0.1",
                    "gateway_id": "graph-mcp",
                    "server_id": "local",
                    "mode": "ENFORCE",
                    "upstream": {"transport": "stdio", "command": "/unused"},
                    "tool_bindings": [
                        {
                            "upstream_name": "read",
                            "capability": "filesystem.read",
                            "side_effect_class": "READ",
                            "output_data_labels": [],
                            "data_sink_destination": "local",
                        }
                    ],
                }
            )
        )
        async with mcp.Client(
            Server("local", on_list_tools=listing, on_call_tool=dispatch), mode="legacy"
        ) as upstream:
            server, gaps = await create_server(upstream, config, gateways["c"])
            assert not gaps
            async with mcp.Client(server, mode="legacy") as client:
                assert not (await client.call_tool("read", {})).is_error
                session.revoke("a")
                result = await client.call_tool("read", {})
                assert result.is_error
                assert result.content[0].text == "GRAPH_ANCESTOR_INACTIVE"
        assert attempts == ["read"]

    asyncio.run(run())


def test_graph_cli_and_reviewed_synthetic_incident_regression(tmp_path):
    from typer.testing import CliRunner

    from agentsec.cli.main import app

    runner = CliRunner()
    example = ROOT / "examples/multi_agent"
    validated = runner.invoke(app, ["graph", "validate", "--config", str(example / "graph.json")])
    assert validated.exit_code == 0
    assert "STRUCTURALLY_VALID_NOT_AUTHENTICATED" in validated.stdout
    replayed = runner.invoke(app, ["graph", "replay", "--config", str(example / "replay.json")])
    assert replayed.exit_code == 0, replayed.stdout
    assert '"fidelity":"SECURITY_SEMANTIC"' in replayed.stdout
    regression = runner.invoke(
        app,
        [
            "graph",
            "regression",
            "--case",
            str(example / "regression.json"),
            "--source",
            str(example / "replay.json"),
        ],
    )
    assert regression.exit_code == 0, regression.stdout
    assert '"status":"PASS"' in regression.stdout
    forged = tmp_path / "bad.yaml"
    forged.write_text('schema_version: "0.1"\nsender: FORGED_PRIVATE_CANARY\n')
    result = runner.invoke(app, ["graph", "validate", "--config", str(forged)])
    assert result.exit_code == 1
    assert "FORGED_PRIVATE_CANARY" not in result.output
