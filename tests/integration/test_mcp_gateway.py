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
from agentsec.domain.taxonomy import (
    ApprovalOutcome,
    DataLabel,
    EnforcementMode,
    EventType,
    PolicyOutcome,
)
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


@pytest.mark.parametrize(
    "name,args,capability,resource,outcome",
    [
        ("search", {"query": "x"}, "web.search", None, PolicyOutcome.ALLOW),
        (
            "write_file",
            {"path": "/tmp/private", "content": "x"},
            "filesystem.write",
            "/tmp/private",
            PolicyOutcome.DENY,
        ),
        (
            "send_email",
            {"recipient": "demo@example.invalid", "body": "x"},
            "email.send",
            "demo@example.invalid",
            PolicyOutcome.REQUIRE_APPROVAL,
        ),
        (
            "send_email",
            {"recipient": "outside", "body": "x"},
            "email.send",
            "outside",
            PolicyOutcome.DENY,
        ),
    ],
)
def test_phase3_cross_path_parity(name, args, capability, resource, outcome):
    from agentsec.compiler import compile_contract
    from agentsec.compiler.probes import PolicyProbe, obligation
    from agentsec.domain.events import PolicyEvaluatedPayload
    from agentsec.eval.contract_cases import ContractTarget, case_scenario
    from agentsec.eval.runner import evaluate
    from agentsec.policy.native import NativePolicyEngine

    loaded = contract()
    plan = compile_contract(loaded)
    expected, reason = obligation(plan, capability, resource)
    assert expected == outcome
    probe = PolicyProbe("parity", capability, resource, expected, reason, ())
    assert NativePolicyEngine().decide(probe.request(plan), plan).outcome == outcome
    result = evaluate(
        contract=loaded, scenario=case_scenario(plan, probe), target=ContractTarget(plan, probe)
    )
    assert result.overall_status.value == "PASS"

    async def operation(host, runtime, sink, attempts, gaps):
        await host.call_tool(name, args)
        decisions = [
            e.payload.decision for e in sink.events if isinstance(e.payload, PolicyEvaluatedPayload)
        ]
        assert len(decisions) == 1 and decisions[0].outcome == outcome
        assert len(attempts) == (outcome != PolicyOutcome.DENY)
        if outcome == PolicyOutcome.REQUIRE_APPROVAL:
            assert len(runtime.broker.requests) == 1

    asyncio.run(with_gateway(operation, loaded_contract=loaded))


def test_phase3_stale_plan_and_compile_once(monkeypatch):
    import agentsec.runtime.gateway as gateway_module
    from agentsec.compiler import compile_contract

    loaded = contract()
    stale = compile_contract(contract(budgets={"max_tool_calls": 0}))
    with pytest.raises(RuntimeFailure, match="STALE_COMPILED_PLAN"):
        RuntimeGateway(
            loaded,
            EnforcementMode.ENFORCE,
            RuntimeEvents(InMemoryEventSink(), lambda: NOW),
            Broker(),
            plan=stale,
        )
    calls = []

    def counting_compile(contract):
        calls.append(contract)
        return compile_contract(contract)

    monkeypatch.setattr(gateway_module, "compile_contract", counting_compile)

    async def operation(host, runtime, sink, attempts, gaps):
        await host.call_tool("search", {"query": "x"})
        await host.call_tool("search", {"query": "y"})
        assert len(attempts) == 2

    asyncio.run(with_gateway(operation))
    assert len(calls) == 1


def test_phase3_adapter_atom_proof():
    from agentsec.adapters.mcp.coverage import semantic_adapter_proof
    from agentsec.compiler import compile_contract

    loaded = contract(
        tools={
            "rules": [
                {"rule_id": "all", "capability": "web.search", "decision": "ALLOW"},
                {
                    "rule_id": "secret",
                    "capability": "web.search",
                    "resource": "x",
                    "decision": "DENY",
                },
            ]
        }
    )
    plan = compile_contract(loaded)
    wires = [types.Tool(name="search", input_schema={"type": "object"})]
    registry, _ = discover(wires, configuration("SHADOW"))
    proof = semantic_adapter_proof(plan, registry)
    from agentsec.adapters.mcp.coverage import discovery_snapshot_digest
    from agentsec.compiler.reporting import coverage_report

    assert {p.atom_id: p.covered for p in proof.atoms}["tools.rules/secret"] is False
    assert semantic_adapter_proof(plan, {}).atoms == ()
    assert proof == semantic_adapter_proof(plan, registry)
    from dataclasses import replace

    binding = registry["search"].binding.model_copy(
        update={"resource_argument_path": ("query",), "resource_semantics": "opaque_exact"}
    )
    refreshed = {"search": replace(registry["search"], binding=binding)}
    current = semantic_adapter_proof(plan, refreshed)
    covered = coverage_report(
        plan, adapter_proof=current, discovery_snapshot_digest=discovery_snapshot_digest(refreshed)
    )
    assert (
        next(a for a in covered.atoms if a.atom_id == "tools.rules/secret").adapter_status
        == "COVERED"
    )
    with pytest.raises(ValueError, match="STALE_ADAPTER_PROOF"):
        coverage_report(
            plan,
            adapter_proof=proof,
            discovery_snapshot_digest=discovery_snapshot_digest(refreshed),
        )
    report = coverage_report(
        plan, adapter_proof=proof, discovery_snapshot_digest=discovery_snapshot_digest(registry)
    )
    assert (
        next(a for a in report.atoms if a.atom_id == "tools.rules/secret").adapter_status
        == "UNCOVERED"
    )
    for other_plan, snapshot in (
        (plan.model_copy(update={"contract_id": "other"}), discovery_snapshot_digest(registry)),
        (plan, discovery_snapshot_digest({})),
        (plan, None),
    ):
        with pytest.raises(ValueError, match="STALE_ADAPTER_PROOF"):
            coverage_report(other_plan, adapter_proof=proof, discovery_snapshot_digest=snapshot)


def test_phase3_runtime_protected_inputs_use_compiled_plan():
    from agentsec.compiler.models import AgentBinding
    from agentsec.policy.native import NativePolicyEngine

    async def operation(host, runtime, sink, attempts, gaps):
        seen = []

        class Capture:
            def decide(self, request, plan):
                seen.append(request)
                return NativePolicyEngine().decide(request, plan)

        runtime.policy = Capture()
        # Deliberately poison the retained authored snapshot after startup. It must
        # not be a parallel source for request or approval action identity.
        runtime._contract = runtime.contract.model_copy(
            update={
                "agent": runtime.contract.agent.model_copy(update={"agent_id": "other-agent"}),
                "task_scope": None,
            }
        )
        response = await host.call_tool("search", {"query": "x"})
        assert not response.is_error and len(attempts) == 1
        assert AgentBinding.from_identity(seen[0].agent) == runtime.plan.agent
        assert runtime.plan.matches_scope(seen[0].task_scope)
        assert seen[0].principal == runtime.plan.principal
        assert seen[0].environment == runtime.plan.environment

    asyncio.run(with_gateway(operation))


# Phase 4 exercises the real adapter using the existing local SDK transport.
def flow_configuration(mode="ENFORCE", label="SECRET"):
    data = configuration(mode).model_dump(mode="json")
    for binding in data["tool_bindings"]:
        binding["output_data_labels"] = [label] if binding["upstream_name"] == "search" else []
        binding["data_sink_destination"] = {
            "search": "internal",
            "send_email": "external",
            "write_file": "memory",
        }[binding["upstream_name"]]
    return validate_data(McpGatewayConfig, data)


def flow_contract(label="SECRET", destination="external"):
    return contract(
        task_scope=None,
        budgets={},
        tools={
            "rules": [
                {"rule_id": cap, "capability": cap, "decision": "ALLOW"}
                for cap in ("web.search", "email.send", "filesystem.write")
            ]
        },
        data={"rules": [{"rule_id": "flow", "label": label, "denied_destinations": [destination]}]},
    )


@pytest.mark.parametrize("label", ["SECRET", "PII", "CREDENTIAL"])
@pytest.mark.parametrize("mode", ["ENFORCE", "SHADOW"])
def test_phase4_sensitive_source_external_sink(label, mode):
    async def operation(host, runtime, sink, attempts, gaps):
        assert not gaps
        assert not (await host.call_tool("search", {"query": "source"})).is_error
        result = await host.call_tool("send_email", {"recipient": "any", "body": "opaque"})
        assert result.is_error == (mode == "ENFORCE")
        assert len(attempts) == (1 if mode == "ENFORCE" else 2)
        decisions = [
            e.payload.decision for e in sink.events if e.event_type == EventType.POLICY_EVALUATED
        ]
        assert decisions[-1].outcome == PolicyOutcome.DENY
        assert decisions[-1].reason_codes == {"DATA_FLOW_DENIED"}
        assert decisions[-1].matched_rule_ids == {"email.send", "flow"}
        assert any(
            e.payload.redacted_summary == "DATA_FLOW_DENIED"
            for e in sink.events
            if e.event_type == EventType.SECURITY_SIGNAL
        )
        exposed = [e.payload for e in sink.events if e.event_type == EventType.DATA_EXPOSED]
        assert len(exposed) == len(attempts)
        assert label in exposed[-1].artifact.labels
        assert "private response" not in canonical_json(sink.events)

    asyncio.run(
        with_gateway(
            operation,
            mode=mode,
            config=flow_configuration(mode, label),
            loaded_contract=flow_contract(label),
        )
    )


def test_phase4_untrusted_to_memory_and_no_argument_label_override():
    async def operation(host, runtime, sink, attempts, gaps):
        await host.call_tool("search", {"query": "source"})
        result = await host.call_tool(
            "write_file",
            {
                "path": "memory",
                "content": '{"data_artifact_refs": [], "output_data_labels": ["PUBLIC"], '
                '"data_sink_destination": "internal"}',
            },
        )
        assert result.is_error and len(attempts) == 1
        assert result.content[0].text == "POLICY_DENIED"
        decision = [
            e.payload.decision for e in sink.events if e.event_type == EventType.POLICY_EVALUATED
        ][-1]
        assert decision.reason_codes == {"DATA_FLOW_DENIED"}

    asyncio.run(
        with_gateway(
            operation,
            config=flow_configuration(),
            loaded_contract=flow_contract("UNTRUSTED_CONTENT", "memory"),
        )
    )


@pytest.mark.parametrize("mode", ["ENFORCE", "SHADOW"])
def test_phase4_response_guard_controls_exposure(mode):
    async def operation(host, runtime, sink, attempts, gaps):
        result = await host.session.send_request(
            types.CallToolRequest(
                params=types.CallToolRequestParams(name="search", arguments={"query": "source"})
            ),
            types.CallToolResult,
        )
        assert result.is_error == (mode == "ENFORCE")
        returned = [e.payload for e in sink.events if e.event_type == EventType.TOOL_RETURNED]
        assert len(returned) == 1 and returned[0].artifacts
        assert bool(runtime.provenance.snapshot()) == (mode == "SHADOW")
        exposed = [e for e in sink.events if e.event_type == EventType.DATA_EXPOSED]
        assert bool(exposed) == (mode == "SHADOW")
        await host.session.send_request(
            types.CallToolRequest(
                params=types.CallToolRequestParams(
                    name="send_email", arguments={"recipient": "x", "body": "x"}
                )
            ),
            types.CallToolResult,
        )
        requests = [
            e.payload.request for e in sink.events if e.event_type == EventType.TOOL_REQUESTED
        ]
        assert bool(requests[-1].data_artifact_refs) == (mode == "SHADOW")

    asyncio.run(
        with_gateway(
            operation,
            mode=mode,
            config=flow_configuration(mode),
            loaded_contract=flow_contract(),
            invalid_output=True,
        )
    )


def test_phase4_tool_error_output_is_exposed():
    async def operation(host, runtime, sink, attempts, gaps):
        assert (await host.call_tool("search", {"query": "error"})).is_error
        assert runtime.provenance.snapshot()
        result = await host.call_tool("send_email", {"recipient": "x", "body": "x"})
        assert result.is_error and result.content[0].text == "POLICY_DENIED"
        assert len(attempts) == 1

    asyncio.run(
        with_gateway(
            operation,
            config=flow_configuration(),
            loaded_contract=flow_contract(),
            upstream_error=True,
        )
    )


@pytest.mark.parametrize(
    "field,gap",
    [
        ("output_data_labels", "data_source_classification:search"),
        ("data_sink_destination", "data_sink_destination:search"),
    ],
)
def test_phase4_classification_gaps_and_proof_freshness(field, gap):
    from dataclasses import replace

    from agentsec.adapters.mcp.coverage import discovery_snapshot_digest, semantic_adapter_proof
    from agentsec.compiler import compile_contract
    from agentsec.compiler.reporting import coverage_report

    c = flow_contract()
    plan = compile_contract(c)
    data = flow_configuration().model_dump(mode="json")
    data["tool_bindings"][0][field] = None
    cfg = validate_data(McpGatewayConfig, data)
    assert gap in configured_resource_coverage_gaps(plan, cfg.tool_bindings)

    async def check():
        runtime = RuntimeGateway(
            c, EnforcementMode.ENFORCE, RuntimeEvents(InMemoryEventSink(), lambda: NOW), Broker()
        )
        async with Client(synthetic([]), mode="legacy") as upstream:
            with pytest.raises(RuntimeFailure, match="UNSUPPORTED_RESOURCE_COVERAGE"):
                await create_server(upstream, cfg, runtime)

    asyncio.run(check())
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("flow_example", ROOT / "examples/mcp/upstream_server.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    registry, _ = discover(module.TOOLS, flow_configuration())
    proof = semantic_adapter_proof(plan, registry)
    atom = next(
        a
        for a in coverage_report(
            plan, adapter_proof=proof, discovery_snapshot_digest=discovery_snapshot_digest(registry)
        ).atoms
        if a.atom_id == "data.rules/flow"
    )
    assert atom.adapter_status == "COVERED"
    assert atom.source_classification_required and atom.sink_classification_required
    binding = registry["search"].binding.model_copy(update={field: None})
    changed = {**registry, "search": replace(registry["search"], binding=binding)}
    with pytest.raises(ValueError, match="STALE_ADAPTER_PROOF"):
        coverage_report(
            plan, adapter_proof=proof, discovery_snapshot_digest=discovery_snapshot_digest(changed)
        )
    assert not next(
        a for a in semantic_adapter_proof(plan, changed).atoms if a.atom_id == "data.rules/flow"
    ).covered


def test_phase4_automatic_labels_need_no_extra_source_declaration():
    from importlib.util import module_from_spec, spec_from_file_location

    from agentsec.adapters.mcp.coverage import semantic_adapter_proof
    from agentsec.compiler import compile_contract

    c = flow_contract("UNTRUSTED_CONTENT", "memory")
    data = flow_configuration().model_dump(mode="json")
    for binding in data["tool_bindings"]:
        binding["output_data_labels"] = None
    cfg = validate_data(McpGatewayConfig, data)
    assert not configured_resource_coverage_gaps(c, cfg.tool_bindings)
    spec = spec_from_file_location("flow_example", ROOT / "examples/mcp/upstream_server.py")
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    registry, _ = discover(module.TOOLS, cfg)
    proof = semantic_adapter_proof(compile_contract(c), registry)
    atom = next(a for a in proof.atoms if a.atom_id.startswith("data.rules/"))
    assert atom.source_runtime_reachable and atom.sink_runtime_reachable and atom.covered


def test_phase4_coverage_separates_classification_from_rule_reachability():
    from dataclasses import replace
    from importlib.util import module_from_spec, spec_from_file_location

    from agentsec.adapters.mcp.coverage import discovery_snapshot_digest, semantic_adapter_proof
    from agentsec.compiler import compile_contract
    from agentsec.compiler.reporting import coverage_report

    contract = flow_contract("SECRET", "external")
    plan = compile_contract(contract)
    spec = spec_from_file_location("flow_example", ROOT / "examples/mcp/upstream_server.py")
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    registry, _ = discover(module.TOOLS, flow_configuration())
    source_id = "data.rules/flow"

    no_secret_registry = {
        name: replace(
            entry,
            binding=entry.binding.model_copy(update={"output_data_labels": frozenset()}),
        )
        for name, entry in registry.items()
    }
    proof = semantic_adapter_proof(plan, no_secret_registry)
    row = next(
        item
        for item in coverage_report(
            plan,
            adapter_proof=proof,
            discovery_snapshot_digest=discovery_snapshot_digest(no_secret_registry),
        ).atoms
        if item.atom_id == source_id
    )
    assert row.source_classification_status == "COVERED"
    assert row.source_runtime_status == "UNREACHABLE"
    assert row.sink_runtime_status == "REACHABLE"
    assert row.adapter_status == "UNCOVERED"

    source_registry = {
        **no_secret_registry,
        "search": replace(
            no_secret_registry["search"],
            binding=no_secret_registry["search"].binding.model_copy(
                update={"output_data_labels": frozenset({DataLabel.SECRET})}
            ),
        ),
    }
    internal_registry = {
        name: replace(
            entry,
            binding=entry.binding.model_copy(update={"data_sink_destination": "internal"}),
        )
        for name, entry in source_registry.items()
    }
    proof = semantic_adapter_proof(plan, internal_registry)
    row = next(
        item
        for item in coverage_report(
            plan,
            adapter_proof=proof,
            discovery_snapshot_digest=discovery_snapshot_digest(internal_registry),
        ).atoms
        if item.atom_id == source_id
    )
    assert row.source_runtime_status == "REACHABLE"
    assert row.sink_runtime_status == "UNREACHABLE"
    assert row.adapter_status == "UNCOVERED"

    reachable_registry = {
        **internal_registry,
        "send_email": replace(
            internal_registry["send_email"],
            binding=internal_registry["send_email"].binding.model_copy(
                update={"data_sink_destination": "external"}
            ),
        ),
    }
    proof = semantic_adapter_proof(plan, reachable_registry)
    row = next(item for item in proof.atoms if item.atom_id == source_id)
    assert row.source_runtime_reachable and row.sink_runtime_reachable and row.covered


def test_phase4_approval_binds_changed_context_for_identical_arguments():
    async def operation(host, runtime, sink, attempts, gaps):
        args = {"recipient": "demo@example.invalid", "body": "same"}
        await host.call_tool("send_email", args)
        await host.call_tool("send_email", args)
        approvals = runtime.broker.requests
        assert len(approvals) == 2 and len(attempts) == 2
        assert approvals[0].action_digest != approvals[1].action_digest
        requests = [
            e.payload.request for e in sink.events if e.event_type == EventType.TOOL_REQUESTED
        ]
        assert not requests[0].data_artifact_refs and requests[1].data_artifact_refs

    asyncio.run(with_gateway(operation, loaded_contract=contract(budgets={})))


@pytest.mark.parametrize(
    "fields",
    [
        {"output_data_labels": ["UNKNOWN"]},
        {"output_data_labels": "SECRET"},
        {"data_sink_destination": "invalid destination"},
    ],
)
def test_phase4_binding_classification_strict_validation(fields):
    from agentsec.contracts.errors import ArtifactValidationError

    data = flow_configuration().model_dump(mode="json")
    data["tool_bindings"][0].update(fields)
    with pytest.raises(ArtifactValidationError):
        validate_data(McpGatewayConfig, data)


def trust_lock(inventory):
    from agentsec.supply_chain.inspection import propose
    from agentsec.supply_chain.models import TrustLock

    # Test operator independently chooses the expected snapshot, then explicitly reviews.
    return TrustLock.model_validate_json(
        propose(inventory, "test-reviewed")
        .model_copy(update={"status": "REVIEWED"})
        .model_dump_json()
    )


def test_strict_trust_mcp_sdk_allow_policy_deny_and_live_lock_change():
    from agentsec.supply_chain.guard import TrustGuard
    from agentsec.supply_chain.models import Inventory
    from agentsec.supply_chain.registration import inspect_mcp

    async def operation():
        attempts = []
        broker = Broker()
        sink = InMemoryEventSink()
        config = configuration()
        async with Client(synthetic(attempts), mode="legacy") as upstream:
            inventory = inspect_mcp(config, await upstream.list_tools())
            guard = TrustGuard(trust_lock(inventory))
            runtime = RuntimeGateway(
                contract(),
                EnforcementMode.ENFORCE,
                RuntimeEvents(sink, lambda: NOW),
                broker,
                trust_guard=guard,
            )
            server, _ = await create_server(upstream, config, runtime)
            async with Client(server, mode="legacy") as host:
                assert len((await host.list_tools()).tools) == 3
                assert not (await host.call_tool("search", {"query": "safe"})).is_error
                assert (
                    await host.call_tool("write_file", {"path": "/tmp/test", "content": "x"})
                ).is_error
                assert len(attempts) == 1
                guard.replace_lock(trust_lock(Inventory(schema_version="0.1", candidates=())))
                assert not (await host.list_tools()).tools
                failed = await host.call_tool(
                    "send_email", {"recipient": "demo@example.invalid", "body": "x"}
                )
                assert failed.is_error and failed.content[0].text == "TRUST_ADMISSION_REJECTED"
                assert not broker.requests
                assert len(attempts) == 1
        runtime.finish()
        dispatch = next(e.payload for e in sink.events if e.event_type == EventType.TOOL_DISPATCHED)
        assert dispatch.trust_assessment.admitted
        assert dispatch.execution_binding.adapter_kind == "mcp"

    asyncio.run(operation())


@pytest.mark.parametrize("substitution", ["unknown", "metadata", "route", "attestation"])
def test_strict_mcp_registration_rejects_unreviewed_material(substitution):
    from agentsec.supply_chain.guard import TrustGuard
    from agentsec.supply_chain.models import Inventory
    from agentsec.supply_chain.registration import inspect_mcp

    async def operation():
        attempts = []
        config = configuration()
        sink = InMemoryEventSink()
        broker = Broker()
        async with Client(synthetic(attempts), mode="legacy") as upstream:
            inventory = inspect_mcp(config, await upstream.list_tools())
            lock = trust_lock(inventory)
            if substitution == "unknown":
                lock = trust_lock(Inventory(schema_version="0.1", candidates=()))
            elif substitution in {"metadata", "route"}:
                field = "metadata_digest" if substitution == "metadata" else "route_digest"
                from agentsec.domain.serialization import content_digest

                candidates = tuple(
                    c.model_copy(update={field: content_digest("other")})
                    for c in inventory.candidates
                )
                lock = trust_lock(Inventory(schema_version="0.1", candidates=candidates))
            else:
                lock = lock.model_copy(
                    update={
                        "pins": tuple(
                            p.model_copy(update={"require_runtime_attestation": True})
                            for p in lock.pins
                        )
                    }
                )
            runtime = RuntimeGateway(
                contract(),
                EnforcementMode.ENFORCE,
                RuntimeEvents(sink, lambda: NOW),
                broker,
                trust_guard=TrustGuard(lock),
            )
            with pytest.raises(RuntimeFailure, match="TRUST_ADMISSION_REJECTED"):
                await create_server(upstream, config, runtime)
            assert not attempts and not broker.requests
            assert not any(e.event_type == EventType.TOOL_DISPATCHED for e in sink.events)

    asyncio.run(operation())


def test_strict_mcp_approval_generation_race_has_no_upstream_effect():
    from agentsec.supply_chain.guard import TrustGuard
    from agentsec.supply_chain.registration import inspect_mcp

    async def operation():
        attempts = []
        sink = InMemoryEventSink()
        config = configuration()
        async with Client(synthetic(attempts), mode="legacy") as upstream:
            lock = trust_lock(inspect_mcp(config, await upstream.list_tools()))
            guard = TrustGuard(lock)

            class RacingBroker(Broker):
                async def decide(self, request, presentation):
                    await asyncio.sleep(0)
                    guard.replace_lock(lock.model_copy(update={"generation": "changed"}))
                    return await super().decide(request, presentation)

            runtime = RuntimeGateway(
                contract(),
                EnforcementMode.ENFORCE,
                RuntimeEvents(sink, lambda: NOW),
                RacingBroker(),
                trust_guard=guard,
            )
            server, _ = await create_server(upstream, config, runtime)
            async with Client(server, mode="legacy") as host:
                result = await host.call_tool(
                    "send_email", {"recipient": "demo@example.invalid", "body": "x"}
                )
                assert result.is_error and result.content[0].text == "TRUST_REGISTRY_STALE"
            assert not attempts
            assert not any(e.event_type == EventType.TOOL_DISPATCHED for e in sink.events)

    asyncio.run(operation())


def test_strict_trust_cli_stdio_static_reviewed_example(tmp_path):
    async def scenario():
        evidence = tmp_path / "trust-evidence.jsonl"
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
                str(ROOT / "examples/mcp/gateway.yaml"),
                "--trust-lock",
                str(ROOT / "examples/trust/mcp-lock.json"),
                "--evidence-out",
                str(evidence),
            ],
            cwd=str(ROOT),
            env={},
        )

        @asynccontextmanager
        async def transport():
            async with stdio_client(params) as streams:
                yield streams

        async with Client(transport(), mode="legacy") as host:
            assert len((await host.list_tools()).tools) == 3
            assert not (await host.call_tool("search", {"query": "synthetic"})).is_error
        from agentsec.evidence.jsonl import read_jsonl

        dispatched = [
            e.payload for e in read_jsonl(evidence) if e.event_type == EventType.TOOL_DISPATCHED
        ]
        assert len(dispatched) == 1
        assert dispatched[0].trust_assessment.admitted

    asyncio.run(scenario())
