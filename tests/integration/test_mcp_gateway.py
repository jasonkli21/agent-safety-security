"""Real SDK in-memory protocol flows and one two-process stdio smoke path."""

import asyncio
import json
import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import anyio
import pytest
from typer.testing import CliRunner

pytest.importorskip("mcp")
from mcp import Client, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server

from agentsec.adapters.mcp.config import McpGatewayConfig
from agentsec.adapters.mcp.coverage import configured_resource_coverage_gaps
from agentsec.adapters.mcp.discovery import discover
from agentsec.adapters.mcp.server import create_server
from agentsec.adapters.mcp.upstream import process_parameters
from agentsec.cli.main import app
from agentsec.contracts.loader import load_artifact, load_contract, validate_data
from agentsec.domain.approvals import ApprovalDecision
from agentsec.domain.serialization import canonical_json
from agentsec.domain.taxonomy import ApprovalOutcome, EnforcementMode, EventType, PolicyOutcome
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 15, tzinfo=UTC)


def configuration(mode="ENFORCE", **updates):
    data = load_artifact(ROOT / "examples/mcp/gateway.yaml", McpGatewayConfig).model_dump(
        mode="json"
    )
    data.update(mode=mode, **updates)
    return validate_data(McpGatewayConfig, data)


def contract(**updates):
    from agentsec.contracts.models import AgentSecurityContract

    data = load_contract(ROOT / "examples/mcp/contract.yaml").model_dump(mode="json")
    data.update(updates)
    return validate_data(AgentSecurityContract, data)


class Broker:
    def __init__(self, outcome=ApprovalOutcome.APPROVE, when=NOW):
        self.outcome, self.when = outcome, when
        self.requests = []
        self.presentations = []

    async def decide(self, request, presentation):
        self.requests.append(request)
        self.presentations.append(presentation)
        return ApprovalDecision(
            schema_version="0.1",
            approval_id=request.approval_id,
            approver=contract().identity.principal,
            outcome=self.outcome,
            decided_at=self.when,
        )


def synthetic(attempts, *, invalid_output=False, upstream_error=False):
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("example", ROOT / "examples/mcp/upstream_server.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    async def listing(ctx, params):
        return types.ListToolsResult(tools=module.TOOLS)

    async def call(ctx, params):
        attempts.append((params.name, params.arguments))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="private response")],
            structured_content={"ok": "wrong" if invalid_output else True},
            is_error=upstream_error,
        )

    return Server("test-upstream", on_list_tools=listing, on_call_tool=call)


async def with_gateway(
    operation,
    *,
    mode="ENFORCE",
    broker=None,
    loaded_contract=None,
    invalid_output=False,
    upstream_error=False,
    config=None,
    host_mode="legacy",
):
    attempts = []
    sink = InMemoryEventSink()
    selected_config = config or configuration(mode)
    runtime = RuntimeGateway(
        loaded_contract or contract(),
        EnforcementMode(mode),
        RuntimeEvents(sink, lambda: NOW, required=mode == "ENFORCE"),
        broker or Broker(),
    )
    async with Client(
        synthetic(attempts, invalid_output=invalid_output, upstream_error=upstream_error),
        mode="legacy",
    ) as upstream:
        gateway, gaps = await create_server(upstream, selected_config, runtime)
        async with Client(gateway, mode=host_mode) as host:
            await operation(host, runtime, sink, attempts, gaps)
    runtime.finish()
    return sink.events


@pytest.mark.parametrize(
    "name,args,expected,dispatches",
    [
        ("search", {"query": "private secret"}, None, 1),
        ("write_file", {"path": "/tmp/private", "content": "secret"}, "POLICY_DENIED", 0),
        ("search", {"query": 4}, "INVALID_ARGUMENTS", 0),
        ("send_email", {"recipient": "outside", "body": "secret"}, "POLICY_DENIED", 0),
        ("send_email", {"recipient": "demo@example.invalid", "body": "secret"}, None, 1),
    ],
)
def test_enforce_flows(name, args, expected, dispatches):
    async def operation(host, runtime, sink, attempts, gaps):
        assert len((await host.list_tools()).tools) == 3
        result = await host.call_tool(name, args)
        assert result.is_error == (expected is not None)
        if expected:
            assert result.content[0].text == expected
        assert len(attempts) == dispatches
        assert "private secret" not in canonical_json(sink.events)
        assert "demo@example.invalid" not in canonical_json(sink.events)
        assert not gaps

    asyncio.run(with_gateway(operation))


@pytest.mark.parametrize(
    "broker", [Broker(ApprovalOutcome.DENY), Broker(when=NOW + timedelta(seconds=121))]
)
def test_bad_approval_never_dispatches(broker):
    async def operation(host, runtime, sink, attempts, gaps):
        result = await host.call_tool(
            "send_email", {"recipient": "demo@example.invalid", "body": "secret"}
        )
        assert result.is_error
        assert not attempts
        assert broker.requests

    asyncio.run(with_gateway(operation, broker=broker))


def test_budget_rejection_is_not_upstream_error():
    async def operation(host, runtime, sink, attempts, gaps):
        first = await host.call_tool("search", {"query": "x"})
        second = await host.call_tool("search", {"query": "x"})
        assert not first.is_error
        assert second.is_error and second.content[0].text == "BUDGET_EXCEEDED"
        assert len(attempts) == 1
        assert len([e for e in sink.events if e.event_type == EventType.TOOL_RETURNED]) == 1

    asyncio.run(with_gateway(operation, loaded_contract=contract(budgets={"max_tool_calls": 1})))


@pytest.mark.parametrize("mode", ["SHADOW", "DISABLED"])
def test_non_enforcing_dispatch_is_truthful(mode):
    async def operation(host, runtime, sink, attempts, gaps):
        result = await host.call_tool("write_file", {"path": "/tmp/private", "content": "secret"})
        assert not result.is_error and len(attempts) == 1
        decisions = [
            e.payload.decision for e in sink.events if e.event_type == EventType.POLICY_EVALUATED
        ]
        dispatches = [e.payload for e in sink.events if e.event_type == EventType.TOOL_DISPATCHED]
        assert dispatches[0].enforcement_mode == EnforcementMode(mode)
        if mode == "SHADOW":
            assert decisions[0].outcome == PolicyOutcome.DENY
            assert dispatches[0].decision_id == decisions[0].decision_id
        else:
            assert not decisions and dispatches[0].decision_id is None

    asyncio.run(with_gateway(operation, mode=mode))


@pytest.mark.parametrize("mode", ["ENFORCE", "SHADOW"])
def test_output_guard(mode):
    async def operation(host, runtime, sink, attempts, gaps):
        # The SDK's high-level host validates output too. Typed raw request lets this test
        # observe the gateway's SHADOW result directly rather than the host's own guard.
        result = await host.session.send_request(
            types.CallToolRequest(
                params=types.CallToolRequestParams(name="search", arguments={"query": "x"})
            ),
            types.CallToolResult,
        )
        assert len(attempts) == 1
        assert result.is_error == (mode == "ENFORCE")
        if mode == "ENFORCE":
            assert result.content[0].text == "OUTPUT_SCHEMA_VIOLATION"
        else:
            assert result.structured_content == {"ok": "wrong"}
        returned = [e.payload for e in sink.events if e.event_type == EventType.TOOL_RETURNED]
        assert returned[0].success and returned[0].response_hash
        assert "private response" not in canonical_json(sink.events)
        assert any(
            e.payload.redacted_summary == "OUTPUT_SCHEMA_VIOLATION"
            for e in sink.events
            if e.event_type == EventType.SECURITY_SIGNAL
        )

    asyncio.run(with_gateway(operation, mode=mode, invalid_output=True))


def test_upstream_tool_error_preserved():
    async def operation(host, runtime, sink, attempts, gaps):
        result = await host.call_tool("search", {"query": "x"})
        assert result.is_error and result.content[0].text == "private response"
        assert len(attempts) == 1
        assert not next(
            e.payload.success for e in sink.events if e.event_type == EventType.TOOL_RETURNED
        )

    asyncio.run(with_gateway(operation, upstream_error=True))


def test_discovery_snapshot_binding_and_pins():
    async def scenario():
        async with Client(synthetic([]), mode="legacy") as client:
            tools = (await client.list_tools()).tools
        config = configuration()
        registry, gaps = discover(tools, config)
        original = registry["search"].descriptor.schema_hash
        tools[0].input_schema["title"] = "mutated"
        registry["search"].descriptor.input_schema["title"] = "also mutated"
        assert registry["search"].descriptor.schema_hash == original
        assert not gaps
        with pytest.raises(RuntimeFailure, match="DUPLICATE_TOOL"):
            discover([tools[0], tools[0]], config)
        data = config.model_dump(mode="json")
        data["tool_bindings"][0]["expected_schema_hash"] = "sha256:" + "0" * 64
        with pytest.raises(RuntimeFailure, match="TOOL_METADATA_MISMATCH"):
            discover(tools, validate_data(McpGatewayConfig, data))
        data["mode"] = "SHADOW"
        _, gaps = discover(tools, validate_data(McpGatewayConfig, data))
        assert any(g.startswith("metadata_pin:") for g in gaps)
        with pytest.raises(RuntimeFailure, match="STALE_TOOL_BINDING"):
            discover(tools[:1], config)

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["ENFORCE", "SHADOW"])
def test_resource_policy_requires_discovered_extractor(mode):
    async def scenario():
        attempts = []
        sink = InMemoryEventSink()
        selected_contract = contract(
            tools={
                "rules": [
                    {
                        "rule_id": "broad-write",
                        "capability": "filesystem.write",
                        "decision": "ALLOW",
                    },
                    {
                        "rule_id": "protected-path",
                        "capability": "filesystem.write",
                        "resource": "/protected",
                        "decision": "DENY",
                    },
                ]
            }
        )
        config_data = configuration(mode).model_dump(mode="json")
        write_binding = next(
            binding
            for binding in config_data["tool_bindings"]
            if binding["upstream_name"] == "write_file"
        )
        write_binding.pop("resource_argument_path")
        selected_config = validate_data(McpGatewayConfig, config_data)
        runtime = RuntimeGateway(
            selected_contract,
            EnforcementMode(mode),
            RuntimeEvents(sink, lambda: NOW, required=mode == "ENFORCE"),
            Broker(),
        )
        async with Client(synthetic(attempts), mode="legacy") as upstream:
            if mode == "ENFORCE":
                with pytest.raises(RuntimeFailure, match="UNSUPPORTED_RESOURCE_COVERAGE"):
                    await create_server(upstream, selected_config, runtime)
                assert not attempts
            else:
                server, gaps = await create_server(upstream, selected_config, runtime)
                expected = "resource_extractor:filesystem.write:write_file"
                assert expected in gaps
                assert any(
                    event.payload.redacted_summary == "COVERAGE_GAP:" + expected
                    for event in sink.events
                    if event.event_type == EventType.SECURITY_SIGNAL
                )
                async with Client(server, mode="legacy") as host:
                    result = await host.call_tool(
                        "write_file", {"path": "/protected", "content": "secret"}
                    )
                assert not result.is_error and len(attempts) == 1
                decision = next(
                    event.payload.decision
                    for event in sink.events
                    if event.event_type == EventType.POLICY_EVALUATED
                )
                assert decision.outcome == PolicyOutcome.ERROR
                assert decision.human_reason == "UNSUPPORTED_RESOURCE_COVERAGE"

    asyncio.run(scenario())


def test_resource_exception_requires_explicit_exact_semantics():
    selected_contract = contract(
        tools={
            "rules": [
                {
                    "rule_id": "broad-write",
                    "capability": "filesystem.write",
                    "decision": "ALLOW",
                },
                {
                    "rule_id": "protected-path",
                    "capability": "filesystem.write",
                    "resource": "/protected",
                    "decision": "DENY",
                },
            ]
        }
    )
    config_data = configuration().model_dump(mode="json")
    write_binding = next(
        binding
        for binding in config_data["tool_bindings"]
        if binding["upstream_name"] == "write_file"
    )
    write_binding["resource_argument_path"] = ["path"]
    selected_config = validate_data(McpGatewayConfig, config_data)
    expected = "resource_semantics:filesystem.write:write_file:opaque_exact_required"
    assert configured_resource_coverage_gaps(selected_contract, selected_config.tool_bindings) == (
        expected,
    )

    write_binding["resource_semantics"] = "opaque_exact"
    exact_config = validate_data(McpGatewayConfig, config_data)
    assert not configured_resource_coverage_gaps(selected_contract, exact_config.tool_bindings)

    allowlist_contract = contract(
        tools={
            "rules": [
                {
                    "rule_id": "safe-path",
                    "capability": "filesystem.write",
                    "resource": "/safe",
                    "decision": "ALLOW",
                }
            ]
        }
    )
    write_binding.pop("resource_semantics")
    allowlist_config = validate_data(McpGatewayConfig, config_data)
    assert not configured_resource_coverage_gaps(allowlist_contract, allowlist_config.tool_bindings)


def test_reused_mcp_request_identity_never_dispatches_twice():
    async def scenario():
        attempts = []
        sink = InMemoryEventSink()
        runtime = RuntimeGateway(
            contract(),
            EnforcementMode.ENFORCE,
            RuntimeEvents(sink, lambda: NOW),
            Broker(),
        )
        async with Client(synthetic(attempts), mode="legacy") as upstream:
            server, _ = await create_server(upstream, configuration(), runtime)
            handler = server._request_handlers["tools/call"].handler
            context = ServerRequestContext(
                session=None,
                lifespan_context=None,
                protocol_version="2025-11-25",
                method="tools/call",
                request_id=42,
            )
            params = types.CallToolRequestParams(name="search", arguments={"query": "once"})
            first = await handler(context, params)
            duplicate = await handler(context, params)
        assert not first.is_error
        assert duplicate.is_error
        assert duplicate.content[0].text == "DUPLICATE_REQUEST_ID"
        assert len(attempts) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["ENFORCE", "SHADOW"])
def test_unbound_never_implicitly_granted(mode):
    async def operation(host, runtime, sink, attempts, gaps):
        assert bool((await host.list_tools()).tools) == (mode == "SHADOW")
        result = await host.session.send_request(
            types.CallToolRequest(
                params=types.CallToolRequestParams(name="search", arguments={"query": "x"})
            ),
            types.CallToolResult,
        )
        assert result.is_error == (mode == "ENFORCE")
        assert len(attempts) == (0 if mode == "ENFORCE" else 1)
        assert gaps

    asyncio.run(with_gateway(operation, mode=mode, config=configuration(mode, tool_bindings=[])))


@pytest.mark.parametrize(
    "update",
    [
        {"schema_version": "99"},
        {"allow": True},
        {"upstream": {"transport": "stdio", "command": "python\x00"}},
        {"upstream": {"transport": "streamable_http", "url": "file:///tmp/secret"}},
        {
            "tool_bindings": [
                {
                    "upstream_name": "x",
                    "capability": "web.search",
                    "side_effect_class": "DESTRUCTIVE",
                    "destructive": False,
                }
            ]
        },
    ],
)
def test_strict_config(update):
    from agentsec.contracts.errors import ArtifactValidationError

    data = configuration().model_dump(mode="json")
    data.update(update)
    with pytest.raises(ArtifactValidationError):
        validate_data(McpGatewayConfig, data)


def test_process_environment_explicit(monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "never inherit")
    monkeypatch.setenv("HOME", "/sensitive/home")
    params = process_parameters(configuration().upstream)
    assert "SECRET_TOKEN" not in params.env
    assert params.env["HOME"] == ""
    assert params.command == ".venv/bin/python"  # argv, no shell wrapper


def test_cli_check_and_refusal(tmp_path):
    runner = CliRunner()
    args = [
        "protect",
        "mcp",
        "--contract",
        str(ROOT / "examples/mcp/contract.yaml"),
        "--config",
        str(ROOT / "examples/mcp/gateway.yaml"),
        "--check",
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0 and result.stdout == ""
    assert "ENFORCE" in result.stderr
    path = tmp_path / "unsupported.json"
    path.write_text(contract(budgets={"max_cost_usd": 0}).model_dump_json())
    args[3] = str(path)
    result = runner.invoke(app, args)
    assert result.exit_code == 1 and result.stdout == ""
    assert "UNSUPPORTED_POLICY_SEMANTICS" in result.stderr


def test_stdio_smoke(tmp_path):
    async def scenario():
        config = configuration().model_dump(mode="json")
        config["upstream"]["command"] = sys.executable
        config["upstream"]["args"] = [str(ROOT / "examples/mcp/upstream_server.py")]
        config_path = tmp_path / "gateway.json"
        config_path.write_text(json.dumps(config))
        evidence = tmp_path / "evidence.jsonl"
        params = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "agentsec.cli.main",
                "protect",
                "mcp",
                "--contract",
                str(ROOT / "examples/mcp/contract.yaml"),
                "--config",
                str(config_path),
                "--evidence-out",
                str(evidence),
            ],
            cwd=str(ROOT),
            env={},
        )
        # This is a normal SDK MCP host. Any non-protocol stdout would break the session.
        parse_errors = []

        @asynccontextmanager
        async def observed_transport():
            async with stdio_client(params) as (read, write):
                relay_write, relay_read = anyio.create_memory_object_stream(0)

                async def relay():
                    async with relay_write:
                        async for message in read:
                            if isinstance(message, Exception):
                                parse_errors.append(message)
                            await relay_write.send(message)

                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(relay)
                    yield relay_read, write
                    tasks.cancel_scope.cancel()

        async with Client(observed_transport(), mode="legacy") as host:
            assert len((await host.list_tools()).tools) == 3
            result = await host.call_tool("search", {"query": "smoke"})
            assert not result.is_error
            result = await host.call_tool("write_file", {"path": "/tmp/x", "content": "x"})
            assert result.is_error and result.content[0].text == "POLICY_DENIED"
        from agentsec.evidence.jsonl import read_jsonl

        assert not parse_errors, "Non-protocol stdout from gateway"
        events = read_jsonl(evidence)
        assert len([e for e in events if e.event_type == EventType.TOOL_DISPATCHED]) == 1

    asyncio.run(scenario())


def test_shadow_budget_and_approval_requirements_forward_without_broker():
    broker = Broker(ApprovalOutcome.DENY)

    async def operation(host, runtime, sink, attempts, gaps):
        result = await host.call_tool(
            "send_email", {"recipient": "demo@example.invalid", "body": "x"}
        )
        assert not result.is_error and len(attempts) == 1
        assert not broker.requests
        assert any(
            e.payload.decision.outcome == PolicyOutcome.REQUIRE_APPROVAL
            for e in sink.events
            if e.event_type == EventType.POLICY_EVALUATED
        )
        assert any(
            e.payload.redacted_summary == "BUDGET_EXCEEDED"
            for e in sink.events
            if e.event_type == EventType.SECURITY_SIGNAL
        )

    asyncio.run(
        with_gateway(
            operation,
            mode="SHADOW",
            broker=broker,
            loaded_contract=contract(budgets={"max_tool_calls": 0}),
        )
    )


def test_changed_arguments_require_new_approval():
    class ReplayingBroker(Broker):
        async def decide(self, request, presentation):
            self.requests.append(request)
            self.presentations.append(presentation)
            return ApprovalDecision(
                schema_version="0.1",
                approval_id=self.requests[0].approval_id,
                approver=contract().identity.principal,
                outcome=ApprovalOutcome.APPROVE,
                decided_at=NOW,
            )

    broker = ReplayingBroker()

    async def operation(host, runtime, sink, attempts, gaps):
        for body, error in [("first secret", False), ("changed secret", True)]:
            result = await host.call_tool(
                "send_email", {"recipient": "demo@example.invalid", "body": body}
            )
            assert result.is_error == error
        assert len(attempts) == 1
        assert len(broker.requests) == 2
        assert broker.requests[0].action_digest != broker.requests[1].action_digest
        assert "demo@example.invalid" in broker.presentations[0]
        assert "first secret" not in broker.presentations[0]
        assert broker.requests[0].action_digest in broker.presentations[0]
        assert "demo@example.invalid" not in broker.requests[0].summary
        assert "first secret" not in canonical_json(sink.events)
        assert "changed secret" not in canonical_json(sink.events)
        assert "demo@example.invalid" not in canonical_json(sink.events)

    asyncio.run(with_gateway(operation, broker=broker, loaded_contract=contract(budgets={})))


def test_normal_sdk_host_negotiation():
    async def operation(host, runtime, sink, attempts, gaps):
        assert len((await host.list_tools()).tools) == 3
        assert not (await host.call_tool("search", {"query": "auto negotiation"})).is_error
        assert len(attempts) == 1

    asyncio.run(with_gateway(operation, host_mode="auto"))
