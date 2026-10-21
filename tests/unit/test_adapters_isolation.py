"""Phase 7 security boundary conformance, entirely local and credential-free."""

import asyncio
import json
import socket
import ssl
import sys
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import ValidationError
from test_runtime_policy import NOW, contract_with
from test_runtime_state import Broker, runtime, tool

from agentsec.adapters.http import HttpAction, protect_http
from agentsec.adapters.native import native_binding, protect_native
from agentsec.adapters.process import ProcessAction, protect_process
from agentsec.adapters.providers import ProviderTools
from agentsec.domain.approvals import ApprovalRequest, NormalizedAction, action_digest
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import EnforcementMode, EventType, ReasonCode
from agentsec.isolation.backends import DockerBackend, DockerMount, DockerProfile, HostBackend
from agentsec.isolation.process import ProcessRequest, run_process
from agentsec.runtime.approvals import ApprovalLedger
from agentsec.runtime.bindings import ProtectedCall, ProtectedTool
from agentsec.runtime.models import RuntimeFailure, ToolResponse


def protected(**updates):
    values = dict(
        schema_version="0.1", descriptor=tool(), execution_binding=native_binding("local", "v1")
    )
    values.update(updates)
    return ProtectedTool(**values)


async def echo(arguments):
    return arguments


def unrestricted(**updates):
    values = dict(task_scope=None, budgets={})
    values.update(updates)
    return contract_with(**values)


def test_native_shared_allow_deny_snapshot_and_secrecy():
    gateway, sink = runtime(unrestricted())
    metadata = protected()
    call = protect_native(gateway, metadata, echo)
    metadata.descriptor.input_schema["type"] = "string"
    response = asyncio.run(call.invoke({"secret": "P7_CANARY"}))
    assert response.structured == {"secret": "P7_CANARY"}
    text = "".join(e.model_dump_json() for e in sink.events)
    assert "P7_CANARY" not in text
    dispatch = next(e.payload for e in sink.events if e.event_type == EventType.TOOL_DISPATCHED)
    assert dispatch.execution_binding.adapter_kind == "native"
    denied = protected(
        descriptor=tool().model_copy(update={"capabilities": frozenset({"unknown.tool"})})
    )
    with pytest.raises(RuntimeFailure):
        asyncio.run(protect_native(gateway, denied, echo).invoke({}))
    assert sum(e.event_type == EventType.TOOL_DISPATCHED for e in sink.events) == 1


@pytest.mark.parametrize("value", [object(), {1: "bad"}, float("nan"), b"bytes"])
def test_native_unsupported_returns(value):
    gateway, _ = runtime(unrestricted())

    async def bad(_):
        return value

    with pytest.raises(RuntimeFailure, match="UPSTREAM_FAILURE"):
        asyncio.run(protect_native(gateway, protected(), bad).invoke({}))


@pytest.mark.parametrize(
    "schema",
    [{"$ref": "https://invalid/schema"}, {"properties": {"x": {"$dynamicRef": "file:///tmp/s"}}}],
)
def test_no_schema_resolution(schema):
    with pytest.raises(RuntimeFailure, match="UNSUPPORTED_SCHEMA_REFERENCE"):
        protected(descriptor=tool().model_copy(update={"input_schema": schema}))


@pytest.mark.parametrize(
    "change",
    [
        {"unknown": 1},
        {"resource_argument_path": ()},
        {"approval_display_paths": ((),)},
        {"resource_semantics": "opaque_exact"},
    ],
)
def test_strict_binding(change):
    with pytest.raises(ValidationError):
        protected(**change)


@pytest.mark.parametrize(
    "provider,shape",
    [
        (
            "openai",
            {
                "type": "function",
                "id": "untrusted",
                "function": {"name": "test", "arguments": '{"x":1}'},
            },
        ),
        ("anthropic", {"type": "tool_use", "id": "untrusted", "name": "test", "input": {"x": 1}}),
        ("gemini", {"name": "test", "args": {"x": 1}}),
    ],
)
def test_provider_conformance(provider, shape):
    gateway, sink = runtime(unrestricted())
    call = protect_native(gateway, protected(), echo)
    tools = ProviderTools(provider, (call,))
    assert tools.declarations()
    assert asyncio.run(tools.invoke(shape)).structured == {"x": 1}
    assert "untrusted" not in "".join(e.model_dump_json() for e in sink.events)
    with pytest.raises(RuntimeFailure, match="DUPLICATE_TOOL"):
        ProviderTools(provider, (call, call))
    with pytest.raises(RuntimeFailure):
        asyncio.run(tools.invoke({**shape, "principal": "forged"}))


@pytest.mark.parametrize(
    "shape",
    [
        {"type": "function", "function": {"name": "test", "arguments": '{"x":1,"x":2}'}},
        {"type": "function", "function": {"name": "test", "arguments": "NaN"}},
        {"type": "function", "function": {"name": "test", "arguments": "[]"}},
        {"type": "function", "function": {"name": "unknown", "arguments": "{}"}},
        {"type": "function", "function": {"name": "test", "arguments": "{"}},
        {"type": "function", "id": {}, "function": {"name": "test", "arguments": "{}"}},
    ],
)
def test_provider_rejects_ambiguity(shape):
    gateway, sink = runtime(unrestricted())
    with pytest.raises(RuntimeFailure):
        asyncio.run(
            ProviderTools("openai", (protect_native(gateway, protected(), echo),)).invoke(shape)
        )
    assert not any(e.event_type == EventType.TOOL_DISPATCHED for e in sink.events)


def test_langchain_real_async_wrapper():
    pytest.importorskip("langchain_core")
    from agentsec.adapters.langchain import as_langchain_tool

    gateway, sink = runtime(unrestricted())
    call = protect_native(gateway, protected(), echo)
    wrapped = as_langchain_tool(call)
    assert asyncio.run(wrapped.ainvoke({"x": "value"}))["success"]
    denied = protected(
        descriptor=tool().model_copy(update={"capabilities": frozenset({"unknown.tool"})})
    )
    with pytest.raises(RuntimeFailure):
        asyncio.run(as_langchain_tool(protect_native(gateway, denied, echo)).ainvoke({}))
    assert sum(e.event_type == EventType.TOOL_DISPATCHED for e in sink.events) == 1


def test_langchain_async_methods_and_callback_precede_denial():
    pytest.importorskip("langchain_core")
    from langchain_core.callbacks import BaseCallbackHandler

    from agentsec.adapters.langchain import as_langchain_tool

    observed = []
    order = []

    class Recorder(BaseCallbackHandler):
        def on_tool_start(self, serialized, input_str, **kwargs):
            observed.append((input_str, kwargs.get("inputs")))
            order.append("callback")

    gateway, sink = runtime(unrestricted(tools={"rules": []}))
    original_call = gateway.call

    async def tracked_call(*args, **kwargs):
        order.append("gateway")
        return await original_call(*args, **kwargs)

    gateway.call = tracked_call
    denied = protected()
    wrapped = as_langchain_tool(protect_native(gateway, denied, echo))
    with pytest.raises(RuntimeFailure):
        asyncio.run(
            wrapped.ainvoke({"secret": "P7_CALLBACK_CANARY"}, config={"callbacks": [Recorder()]})
        )
    assert observed and "P7_CALLBACK_CANARY" in repr(observed)
    assert order.index("callback") < order.index("gateway")
    assert not any(e.event_type == EventType.TOOL_DISPATCHED for e in sink.events)

    gateway, _ = runtime(unrestricted())
    wrapped = as_langchain_tool(protect_native(gateway, protected(), echo))
    assert asyncio.run(wrapped.arun({"x": "async-run"})) == {
        "success": True,
        "result": {"result": {"x": "async-run"}},
    }
    with pytest.raises(NotImplementedError):
        wrapped.run({"x": "sync-run"})
    with pytest.raises(NotImplementedError):
        wrapped.invoke({"x": "sync-invoke"})


def test_binding_hash_approval_and_historical_wire():
    base = NormalizedAction(
        schema_version="0.1",
        principal=contract_with().identity.principal,
        agent_id="agent",
        environment="test",
        capability="web.search",
        tool_id="tool",
        arguments={},
        tool_schema_hash=tool().schema_hash,
        tool_description_hash=tool().description_hash,
        effective_policy_hash=content_digest("policy"),
    )
    wire = base.model_dump(mode="json")
    assert "execution_binding_digest" not in wire
    assert action_digest(base) == content_digest(wire)
    assert NormalizedAction.model_validate_json(json.dumps(wire)) == base
    a = base.model_copy(
        update={"execution_binding_digest": content_digest(native_binding("a", "v1"))}
    )
    b = a.model_copy(update={"execution_binding_digest": content_digest(native_binding("a", "v2"))})
    assert action_digest(a) != action_digest(b)
    approval = ApprovalRequest(
        schema_version="0.1",
        approval_id="a",
        policy_request_id="p",
        action_digest=action_digest(a),
        summary="review",
        reason_codes=frozenset({ReasonCode.APPROVAL_REQUIRED}),
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    ledger = ApprovalLedger(lambda: NOW)
    ledger.create(approval)
    ledger.record(asyncio.run(Broker().decide(approval, "")))
    with pytest.raises(RuntimeFailure, match="INVALID_APPROVAL"):
        ledger.redeem("a", action_digest(b))


_LOCAL_CONNECT = socket.socket.connect


class Handler(BaseHTTPRequestHandler):
    hits: ClassVar[list] = []

    def do_POST(self):
        self.hits.append((self.path, self.rfile.read(int(self.headers["Content-Length"]))))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/escape")
        else:
            self.send_response(200)
        self.end_headers()
        self.wfile.write(b"x" * (100 if self.path == "/large" else 2))

    def log_message(self, *args):
        pass


@pytest.fixture
def http_server(monkeypatch):
    Handler.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def local_connection(address, timeout=10, source_address=None):
        assert address == ("127.0.0.1", server.server_port)
        connection = socket.socket()
        connection.settimeout(timeout)
        _LOCAL_CONNECT(connection, address)
        return connection

    monkeypatch.setattr(socket, "create_connection", local_connection)
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture
def https_server(monkeypatch):
    Handler.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    fixture_dir = Path(__file__).resolve().parents[1] / "fixtures"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=fixture_dir / "http-test-server.pem",
        keyfile=fixture_dir / "http-test-server.key",
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def local_connection(address, timeout=10, source_address=None):
        assert address == ("127.0.0.1", server.server_port)
        connection = socket.socket()
        connection.settimeout(timeout)
        _LOCAL_CONNECT(connection, address)
        return connection

    monkeypatch.setattr(socket, "create_connection", local_connection)
    yield f"https://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()


def http_config(endpoint, **updates):
    values = dict(
        schema_version="0.1",
        adapter_id="http",
        origin=endpoint,
        path="/fixed",
        method="POST",
        destination="internal",
    )
    values.update(updates)
    return HttpAction(**values)


def test_http_fixed_destination_no_proxy_no_retry_secrets(http_server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    gateway, sink = runtime(unrestricted())
    config = http_config(http_server, headers={"Authorization": "P7_AUTH_CANARY"})
    call = protect_http(gateway, protected(), config)
    config.headers["Authorization"] = "mutated"
    response = asyncio.run(call.invoke({"url": "https://evil.invalid", "secret": "P7_BODY_CANARY"}))
    assert response.success and len(Handler.hits) == 1 and Handler.hits[0][0] == "/fixed"
    evidence = "".join(e.model_dump_json() for e in sink.events)
    assert "P7_AUTH_CANARY" not in evidence and "P7_BODY_CANARY" not in evidence


@pytest.mark.parametrize("path,limit", [("/redirect", 100), ("/large", 10)])
def test_http_redirect_and_response_limit(http_server, path, limit):
    gateway, _ = runtime(unrestricted())
    with pytest.raises(RuntimeFailure):
        asyncio.run(
            protect_http(
                gateway, protected(), http_config(http_server, path=path, response_limit=limit)
            ).invoke({})
        )
    assert len(Handler.hits) == 1


@pytest.mark.parametrize(
    "updates",
    [
        {"origin": "http://user:secret@localhost"},
        {"origin": "file:///tmp"},
        {"origin": "http://localhost/#frag"},
        {"path": "//evil.invalid"},
        {"headers": {"Host": "evil.invalid"}},
        {"headers": {"X": "secret\r\nHost: evil"}},
        {"headers": {"A": "x", "a": "y"}},
        {"timeout_seconds": 0},
        {"retry": True},
    ],
)
def test_http_strict_config(updates):
    with pytest.raises(ValidationError):
        http_config("http://localhost", **updates)


def test_https_uses_only_protected_ca_without_ambient_tls_effects(
    https_server, tmp_path, monkeypatch
):
    from agentsec.adapters.http import _tls_context

    ca_pem = (Path(__file__).resolve().parents[1] / "fixtures/http-test-ca.pem").read_text()
    keylog = tmp_path / "tls-keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "ambient-ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "ambient-ca-dir"))
    config = http_config(https_server, tls_ca_pem=ca_pem)
    context = _tls_context(config)
    assert context is not None
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.keylog_filename is None and not keylog.exists()
    assert context.cert_store_stats()["x509_ca"] == 1
    assert ca_pem not in repr(config)
    gateway, sink = runtime(unrestricted())
    response = asyncio.run(
        protect_http(gateway, protected(), config).invoke({"message": "P7_TLS_BODY"})
    )
    assert response.success and Handler.hits == [("/fixed", b'{"message":"P7_TLS_BODY"}')]
    assert not keylog.exists()
    assert "P7_TLS_BODY" not in "".join(event.model_dump_json() for event in sink.events)
    with pytest.raises(ValidationError):
        http_config("https://example.invalid")


def process_request(**updates):
    values = dict(schema_version="0.1", argv=(sys.executable, "-c", "print('ok')"), cwd="/", env={})
    values.update(updates)
    return ProcessRequest(**values)


def test_process_argv_explicit_env_cwd_and_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("P7_PARENT_SECRET", "must-not-inherit")
    code = (
        "import os,sys,json;print(json.dumps([sys.argv[1:],os.getcwd(),"
        "os.getenv('P7_PARENT_SECRET'),os.getenv('EXPLICIT')]))"
    )
    request = process_request(
        argv=(sys.executable, "-c", code), cwd=str(tmp_path), env={"EXPLICIT": "P7_ENV_CANARY"}
    )
    gateway, sink = runtime(unrestricted())
    call = protect_process(
        gateway,
        protected(),
        ProcessAction(
            schema_version="0.1", adapter_id="process", request=request, argument_slots=("text",)
        ),
        HostBackend(),
    )
    result = asyncio.run(call.invoke({"text": "$(touch /tmp/should-not-exist); *"}))
    data = json.loads(result.structured["stdout"])
    assert data == [["$(touch /tmp/should-not-exist); *"], str(tmp_path), None, "P7_ENV_CANARY"]
    assert "P7_ENV_CANARY" not in "".join(e.model_dump_json() for e in sink.events)
    with pytest.raises(RuntimeFailure):
        asyncio.run(call.invoke({"backend": "host"}))


@pytest.mark.parametrize(
    "updates",
    [
        {"argv": ("python",)},
        {"cwd": "relative"},
        {"env": {"X=Y": "a"}},
        {"argv": ("/bin/echo", "\0")},
        {"timeout_seconds": 0},
        {"shell": True},
    ],
)
def test_process_strict_config(updates):
    with pytest.raises(ValidationError):
        process_request(**updates)


@pytest.mark.parametrize(
    "code,updates,error",
    [
        ("print('x'*100000)", {"output_limit": 10}, "PROCESS_OUTPUT_LIMIT"),
        ("import time;time.sleep(30)", {"timeout_seconds": 1}, "PROCESS_TIMEOUT"),
    ],
)
def test_process_bounds(code, updates, error):
    with pytest.raises(RuntimeFailure, match=error):
        asyncio.run(run_process(process_request(argv=(sys.executable, "-c", code), **updates)))


def test_docker_secure_command_and_route_identity():
    profile = DockerProfile(
        schema_version="0.1",
        image="local:test",
        runtime="runsc",
        mounts=(DockerMount(schema_version="0.1", source="/tmp/data", target="/data"),),
    )
    backend = DockerBackend(profile)
    command = backend.command(
        process_request(env={"SECRET": "value"}), "test", "/tmp/private-config"
    )
    for flag in (
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--read-only",
        "--pull=never",
    ):
        assert flag in command.argv
    assert "runsc" in command.argv and "type=bind,src=/tmp/data,dst=/data,readonly" in command.argv
    assert "--rm" not in command.argv
    assert command.env == {} and command.cwd == "/"
    assert backend.identity_digest != HostBackend().identity_digest
    assert (
        backend.identity_digest
        != DockerBackend(profile.model_copy(update={"runtime": None})).identity_digest
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"image": "--privileged"},
        {"runtime": "--host"},
        {"user": "0:0"},
        {"network": "host"},
        {"privileged": True},
    ],
)
def test_docker_strict_profile(updates):
    values = dict(schema_version="0.1", image="local:test")
    values.update(updates)
    with pytest.raises(ValidationError):
        DockerProfile(**values)


@pytest.mark.parametrize(
    "source",
    ["/var/run/docker.sock", "/run", "/", "/tmp/../var/run/docker.sock", "/tmp/data,src=/"],
)
def test_docker_unsafe_mounts(source):
    with pytest.raises(ValidationError):
        DockerMount(schema_version="0.1", source=source, target="/data")


def test_isolation_failure_never_host_fallback(monkeypatch):
    from agentsec.isolation import backends

    attempts = []

    async def fail(request):
        attempts.append(request.argv)
        raise RuntimeFailure("PROCESS_UNAVAILABLE")

    monkeypatch.setattr(backends, "run_process", fail)
    gateway, _ = runtime(unrestricted())
    config = ProcessAction(schema_version="0.1", adapter_id="isolated", request=process_request())
    with pytest.raises(RuntimeFailure):
        asyncio.run(
            protect_process(
                gateway,
                protected(),
                config,
                DockerBackend(DockerProfile(schema_version="0.1", image="local:test")),
            ).invoke({})
        )
    assert len(attempts) == 2 and all(a[0] == "/usr/bin/docker" for a in attempts)
    assert attempts[0][3] == "run" and attempts[1][3:5] == ("rm", "-f")


def test_shared_cancellation_after_entry_unknown_effect():
    gateway, sink = runtime(unrestricted())
    entered = asyncio.Event()
    count = []

    async def dispatch(_):
        count.append(1)
        entered.set()
        await asyncio.Event().wait()
        return ToolResponse(body={}, success=True)

    call = ProtectedCall(gateway, protected(), dispatch)

    async def run():
        task = asyncio.create_task(call.invoke({}))
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert count == [1]
    assert any(
        getattr(e.payload, "redacted_summary", "") == "DISPATCH_CANCELLED_EFFECT_UNKNOWN"
        for e in sink.events
    )


@pytest.mark.parametrize("mode", [EnforcementMode.SHADOW, EnforcementMode.DISABLED])
def test_modes_do_not_ignore_isolation(mode):
    gateway, sink = runtime(unrestricted())
    gateway.mode = mode

    class Unavailable:
        identity_digest = content_digest("unavailable")

        async def execute(self, request):
            raise RuntimeFailure("ISOLATION_UNAVAILABLE")

    with pytest.raises(RuntimeFailure):
        asyncio.run(
            protect_process(
                gateway,
                protected(),
                ProcessAction(schema_version="0.1", adapter_id="p", request=process_request()),
                Unavailable(),
            ).invoke({})
        )
    assert (
        next(
            e.payload for e in sink.events if e.event_type == EventType.TOOL_DISPATCHED
        ).enforcement_mode
        == mode
    )


@pytest.mark.parametrize("gate", ["deny", "authority", "approval", "budget", "data"])
def test_shared_pre_dispatch_failures_never_enter_adapter(gate):
    from agentsec.domain.approvals import ApprovalDecision
    from agentsec.domain.provenance import DataOrigin
    from agentsec.domain.taxonomy import ApprovalOutcome, DataLabel, TrustClass

    class Denier:
        async def decide(self, request, presentation):
            return ApprovalDecision(
                schema_version="0.1",
                approval_id=request.approval_id,
                approver=contract_with().identity.principal,
                outcome=ApprovalOutcome.DENY,
                decided_at=NOW,
            )

    updates = {}
    metadata = protected(output_data_labels=frozenset(), data_sink_destination="external")
    if gate == "deny":
        updates["tools"] = {"rules": []}
    elif gate == "approval":
        updates["tools"] = {
            "rules": [{"rule_id": "r", "capability": "web.search", "decision": "REQUIRE_APPROVAL"}]
        }
    elif gate == "budget":
        updates["budgets"] = {"max_tool_calls": 0}
    elif gate == "data":
        updates["data"] = {
            "rules": [{"rule_id": "r", "label": "TOOL_OUTPUT", "denied_destinations": ["external"]}]
        }
    gateway, sink = runtime(unrestricted(**updates))
    if gate == "approval":
        gateway.broker = Denier()
    if gate == "authority":
        gateway._authority = gateway._authority.model_copy(
            update={
                "credential": gateway._authority.credential.model_copy(
                    update={"capability_ceiling": frozenset()}
                )
            }
        )
    if gate == "data":
        graph = gateway.provenance
        ref = graph.derive(
            DataOrigin(
                origin_type="tool_output", source_id="source", trust_class=TrustClass.TOOL_OUTPUT
            ),
            labels=frozenset({DataLabel.TOOL_OUTPUT}),
        )
        graph.expose(ref, lambda: None)
    entered = []

    async def dispatch(_):
        entered.append(1)
        return ToolResponse(body={}, success=True)

    with pytest.raises(RuntimeFailure):
        asyncio.run(ProtectedCall(gateway, metadata, dispatch).invoke({}))
    assert entered == []
    assert not any(e.event_type == EventType.TOOL_DISPATCHED for e in sink.events)


def test_new_binding_replay_is_offline_and_unchanged(monkeypatch):
    from agentsec.domain.replay import CandidateRouteManifest, ExecutionRouteEntry
    from agentsec.replay.bundle import create_bundle
    from agentsec.replay.engine import replay

    c = unrestricted()
    gateway, sink = runtime(c)
    call = protect_native(gateway, protected(), echo)
    asyncio.run(call.invoke({}))
    gateway.finish()
    bundle = create_bundle(sink.events, c, tools=(tool(),))
    monkeypatch.setattr(ProtectedCall, "invoke", lambda *_: pytest.fail("live adapter"))
    result = replay(bundle)
    assert result.external_effects_performed is False
    assert result.diff.status == "UNCHANGED"
    assert result.route_comparison.status == "UNKNOWN"
    source_route = next(
        e.payload.execution_binding
        for e in sink.events
        if e.event_type == EventType.TOOL_DISPATCHED
    )
    replay_route = next(
        e.payload.execution_binding
        for e in result.events
        if e.event_type == EventType.TOOL_DISPATCHED
    )
    assert source_route == replay_route
    candidate = CandidateRouteManifest(
        schema_version="0.1",
        routes=(ExecutionRouteEntry(tool_id="tool", execution_binding=source_route),),
    )
    matching = replay(bundle, candidate_routes=candidate)
    assert matching.diff.status == "UNCHANGED"
    assert matching.route_comparison.status == "UNCHANGED"
    changed_candidate = CandidateRouteManifest(
        schema_version="0.1",
        routes=(
            ExecutionRouteEntry(
                tool_id="tool",
                execution_binding=source_route.model_copy(update={"adapter_id": "other-route"}),
            ),
        ),
    )
    changed = replay(bundle, candidate_routes=changed_candidate)
    assert changed.diff.status == "UNCHANGED"
    assert changed.route_comparison.status == "CHANGED"
    assert changed.route_comparison.changed_tool_ids == ("tool",)

    legacy_events = tuple(
        event.model_copy(
            update={"payload": event.payload.model_copy(update={"execution_binding": None})}
        )
        if event.event_type == EventType.TOOL_DISPATCHED
        else event
        for event in sink.events
    )
    legacy_bundle = create_bundle(legacy_events, c, tools=(tool(),))
    historical = replay(legacy_bundle, candidate_routes=candidate)
    assert historical.route_comparison.status == "INCOMPLETE"
    assert historical.route_comparison.missing_source_route_tool_ids == ("tool",)


def test_process_cancellation_kills_child(tmp_path):
    pid_file = tmp_path / "pid"
    code = (
        "import os,time,pathlib;pathlib.Path("
        + repr(str(pid_file))
        + ").write_text(str(os.getpid()));time.sleep(30)"
    )

    async def run():
        task = asyncio.create_task(run_process(process_request(argv=(sys.executable, "-c", code))))
        async with asyncio.timeout(3):
            while not pid_file.exists():
                await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    import os

    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)


def test_process_cancellation_during_spawn_waits_for_ownership(monkeypatch):
    from agentsec.isolation import process as process_module

    started = asyncio.Event()
    release = asyncio.Event()
    killed = []
    child_holder = []

    class FakeProcess:
        pid = 918273

        def __init__(self):
            self.stdout = asyncio.StreamReader()
            self.stderr = asyncio.StreamReader()

        async def wait(self):
            return -9

        def kill(self):
            killed.append((self.pid, "leader"))

    async def delayed_spawn(*args, **kwargs):
        started.set()
        await release.wait()
        return child_holder[0]

    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_spawn)
    monkeypatch.setattr(process_module.os, "killpg", lambda pid, sig: killed.append((pid, sig)))

    async def run():
        child = FakeProcess()
        child_holder.append(child)

        task = asyncio.create_task(run_process(process_request()))
        await started.wait()
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert killed and killed[0][0] == 918273


def test_docker_success_calls_real_backend_port_once_and_cleans(monkeypatch):
    from agentsec.isolation import backends
    from agentsec.isolation.process import ProcessResult

    calls = []

    async def fake(request):
        calls.append(request)
        return ProcessResult(schema_version="0.1", exit_code=0, stdout="ok", stderr="")

    monkeypatch.setattr(backends, "run_process", fake)
    gateway, _ = runtime(unrestricted())
    config = ProcessAction(schema_version="0.1", adapter_id="isolated", request=process_request())
    backend = DockerBackend(DockerProfile(schema_version="0.1", image="local:test"))
    response = asyncio.run(protect_process(gateway, protected(), config, backend).invoke({}))
    assert response.success and response.structured["stdout"] == "ok"
    assert len(calls) == 2 and calls[0].argv[3] == "run" and calls[1].argv[3] == "rm"
    assert calls[0].env == {} and not __import__("os").path.exists(calls[0].argv[2])
    assert backend.pending_cleanup_count == 0 and asyncio.run(backend.drain_cleanup())


def test_docker_cleanup_survives_repeated_cancellation(monkeypatch):
    from agentsec.isolation import backends
    from agentsec.isolation.process import ProcessResult

    cleanup_started = asyncio.Event()
    release_cleanup = asyncio.Event()

    async def fake(request):
        if request.argv[3] == "run":
            return ProcessResult(schema_version="0.1", exit_code=0, stdout="", stderr="")
        cleanup_started.set()
        await release_cleanup.wait()
        return ProcessResult(schema_version="0.1", exit_code=0, stdout="", stderr="")

    monkeypatch.setattr(backends, "run_process", fake)
    backend = DockerBackend(DockerProfile(schema_version="0.1", image="local:test"))

    async def run():
        task = asyncio.create_task(backend.execute(process_request()))
        await asyncio.wait_for(cleanup_started.wait(), 2)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release_cleanup.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert backend.pending_cleanup_count == 0
    assert asyncio.run(backend.drain_cleanup())


def test_docker_cancellation_during_run_still_owns_teardown(monkeypatch):
    from agentsec.isolation import backends
    from agentsec.isolation.process import ProcessResult

    run_started = asyncio.Event()
    cleanup_called = asyncio.Event()

    async def fake(request):
        if request.argv[3] == "run":
            run_started.set()
            await asyncio.Event().wait()
        cleanup_called.set()
        return ProcessResult(schema_version="0.1", exit_code=0, stdout="", stderr="")

    monkeypatch.setattr(backends, "run_process", fake)
    backend = DockerBackend(DockerProfile(schema_version="0.1", image="local:test"))

    async def run():
        task = asyncio.create_task(backend.execute(process_request()))
        await asyncio.wait_for(run_started.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert cleanup_called.is_set()
    assert asyncio.run(backend.drain_cleanup())


def test_docker_unconfirmed_cleanup_is_bounded_and_retained(monkeypatch):
    from agentsec.isolation import backends
    from agentsec.isolation.process import ProcessResult

    cleanup_started = asyncio.Event()
    release_cleanup = asyncio.Event()

    class ShortWaitBackend(DockerBackend):
        _cleanup_wait_seconds = 0.02

    async def fake(request):
        if request.argv[3] == "run":
            return ProcessResult(schema_version="0.1", exit_code=0, stdout="", stderr="")
        cleanup_started.set()
        await release_cleanup.wait()
        return ProcessResult(schema_version="0.1", exit_code=0, stdout="", stderr="")

    monkeypatch.setattr(backends, "run_process", fake)
    backend = ShortWaitBackend(DockerProfile(schema_version="0.1", image="local:test"))

    async def run():
        with pytest.raises(RuntimeFailure, match="ISOLATION_CLEANUP_UNCONFIRMED"):
            await backend.execute(process_request())
        assert backend.pending_cleanup_count == 1
        assert await backend.drain_cleanup(timeout_seconds=0.01) is False
        release_cleanup.set()
        await asyncio.sleep(0)
        assert await backend.drain_cleanup(timeout_seconds=1)

    asyncio.run(run())
    assert cleanup_started.is_set()


def test_docker_cleanup_failure_is_explicit_and_never_claimed_success(monkeypatch):
    from agentsec.isolation import backends
    from agentsec.isolation.process import ProcessResult

    calls = []

    async def fake(request):
        calls.append(request)
        if request.argv[3] == "run":
            return ProcessResult(schema_version="0.1", exit_code=0, stdout="", stderr="")
        return ProcessResult(schema_version="0.1", exit_code=1, stdout="", stderr="")

    monkeypatch.setattr(backends, "run_process", fake)
    gateway, sink = runtime(unrestricted())
    call = protect_process(
        gateway,
        protected(),
        ProcessAction(schema_version="0.1", adapter_id="isolated", request=process_request()),
        DockerBackend(DockerProfile(schema_version="0.1", image="local:test")),
    )
    with pytest.raises(RuntimeFailure, match="ISOLATION_CLEANUP_UNCONFIRMED"):
        asyncio.run(call.invoke({}))
    assert len(calls) == 2
    assert any(
        getattr(event.payload, "redacted_summary", "") == "ISOLATION_CLEANUP_UNCONFIRMED"
        for event in sink.events
    )


def test_adapter_and_classification_changes_invalidate_route_identity():
    gateway, _ = runtime(unrestricted())
    call = protect_native(gateway, protected(), echo)
    assert call.tool.execution_binding != call.for_adapter("openai_tools").tool.execution_binding
    assert (
        call.for_adapter("anthropic_tools").tool.execution_binding
        != call.for_adapter("openai_tools").tool.execution_binding
    )
    changed = protect_native(gateway, protected(output_data_labels=frozenset()), echo)
    assert changed.tool.execution_binding != call.tool.execution_binding


def test_http_request_limit_prevents_network(http_server):
    gateway, _ = runtime(unrestricted())
    with pytest.raises(RuntimeFailure):
        asyncio.run(
            protect_http(gateway, protected(), http_config(http_server, request_limit=2)).invoke(
                {"large": "x" * 100}
            )
        )
    assert Handler.hits == []


class CountingApprovalBroker:
    def __init__(self):
        self.presentations = []

    async def decide(self, request, presentation):
        self.presentations.append(presentation)
        return await Broker().decide(request, presentation)


def test_approval_resource_redacted_by_default_and_opt_in_is_explicit():
    contract = unrestricted(
        tools={
            "rules": [
                {
                    "rule_id": "approval",
                    "capability": "web.search",
                    "decision": "REQUIRE_APPROVAL",
                }
            ]
        }
    )
    gateway, sink = runtime(contract)
    broker = CountingApprovalBroker()
    gateway.broker = broker
    secret = "P7_APPROVAL_RESOURCE_CANARY"
    base = dict(
        resource_argument_path=("resource",),
        resource_semantics="opaque_exact",
        trusted_effect_resource=secret,
    )
    asyncio.run(protect_native(gateway, protected(**base), echo).invoke({"resource": secret}))
    assert secret not in broker.presentations[0]
    assert content_digest(secret) in broker.presentations[0]
    assert secret not in "".join(event.model_dump_json() for event in sink.events)

    asyncio.run(
        protect_native(
            gateway,
            protected(**base, approval_display_resource=True),
            echo,
        ).invoke({"resource": secret})
    )
    assert secret in broker.presentations[1]
    assert secret not in "".join(event.model_dump_json() for event in sink.events)


def approval_budget_contract():
    return unrestricted(
        tools={
            "rules": [
                {
                    "rule_id": "approval",
                    "capability": "web.search",
                    "decision": "REQUIRE_APPROVAL",
                }
            ]
        },
        budgets={"max_tool_calls": 1},
    )


def assert_preflight_did_not_enter_gateway(gateway, sink, broker):
    assert broker.presentations == []
    assert not any(
        event.event_type in {EventType.TOOL_REQUESTED, EventType.TOOL_DISPATCHED}
        for event in sink.events
    )
    token, exceeded = gateway.budgets.reserve(tool())
    assert not exceeded
    gateway.budgets.release(token)


@pytest.mark.parametrize(
    "config,arguments,error",
    [
        ({"method": "GET"}, {"unused": "value"}, "HTTP_GET_ARGUMENTS_UNSUPPORTED"),
        ({"request_limit": 1}, {"body": "large"}, "HTTP_REQUEST_LIMIT"),
    ],
)
def test_http_preflight_rejects_before_approval_or_budget(http_server, config, arguments, error):
    gateway, sink = runtime(approval_budget_contract())
    broker = CountingApprovalBroker()
    gateway.broker = broker
    call = protect_http(gateway, protected(), http_config(http_server, **config))
    with pytest.raises(RuntimeFailure, match=error):
        asyncio.run(call.invoke(arguments))
    assert_preflight_did_not_enter_gateway(gateway, sink, broker)
    assert Handler.hits == []


@pytest.mark.parametrize(
    "arguments,error",
    [
        ({"first": "x"}, "INVALID_PROCESS_ARGUMENTS"),
        ({"first": "x", "second": "y", "extra": "z"}, "INVALID_PROCESS_ARGUMENTS"),
        ({"first": "x\0y", "second": "z"}, "INVALID_PROCESS_ARGUMENTS"),
        ({"first": "x" * 65536, "second": "y"}, "PROCESS_REQUEST_LIMIT"),
    ],
)
def test_process_preflight_rejects_before_approval_or_budget(arguments, error):
    gateway, sink = runtime(approval_budget_contract())
    broker = CountingApprovalBroker()
    gateway.broker = broker

    class Backend:
        identity_digest = content_digest("backend")

        async def execute(self, request):
            pytest.fail("invalid invocation reached process backend")

    call = protect_process(
        gateway,
        protected(),
        ProcessAction(
            schema_version="0.1",
            adapter_id="process",
            request=process_request(),
            argument_slots=("first", "second"),
        ),
        Backend(),
    )
    with pytest.raises(RuntimeFailure, match=error):
        asyncio.run(call.invoke(arguments))
    assert_preflight_did_not_enter_gateway(gateway, sink, broker)


def test_resource_coverage_and_exact_extraction():
    gateway, _ = runtime(
        unrestricted(
            tools={
                "rules": [
                    {"rule_id": "base", "capability": "web.search", "decision": "ALLOW"},
                    {
                        "rule_id": "exception",
                        "capability": "web.search",
                        "decision": "DENY",
                        "resource": "blocked",
                    },
                ]
            }
        )
    )
    with pytest.raises(RuntimeFailure, match="ADAPTER_EFFECT_RESOURCE_UNBOUND"):
        protect_native(gateway, protected(), echo)
    metadata = protected(trusted_effect_resource="allowed")
    call = protect_native(gateway, metadata, echo)
    assert asyncio.run(call.invoke({})).success


def test_resource_argument_must_match_trusted_http_effect_target(http_server):
    contract = unrestricted(
        tools={
            "rules": [
                {"rule_id": "base", "capability": "web.search", "decision": "ALLOW"},
                {
                    "rule_id": "production",
                    "capability": "web.search",
                    "decision": "DENY",
                    "resource": "production",
                },
            ]
        }
    )
    gateway, sink = runtime(contract)
    metadata = protected(resource_argument_path=("resource",), resource_semantics="opaque_exact")
    call = protect_http(
        gateway,
        metadata,
        http_config(http_server, trusted_effect_resource="production"),
    )
    with pytest.raises(RuntimeFailure, match="RESOURCE_TARGET_MISMATCH"):
        asyncio.run(call.invoke({"resource": "development"}))
    with pytest.raises(RuntimeFailure):
        asyncio.run(call.invoke({"resource": "production"}))
    assert Handler.hits == []
    assert not any(e.event_type == EventType.TOOL_DISPATCHED for e in sink.events)

    allowed_gateway, _ = runtime(contract)
    allowed = protect_http(
        allowed_gateway,
        metadata,
        http_config(http_server, trusted_effect_resource="development"),
    )
    assert asyncio.run(allowed.invoke({"resource": "development"})).success
    assert Handler.hits[-1][0] == "/fixed"


def test_fixed_http_resource_ignores_untrusted_body_resource_for_authorization(http_server):
    contract = unrestricted(
        tools={
            "rules": [
                {"rule_id": "base", "capability": "web.search", "decision": "ALLOW"},
                {
                    "rule_id": "production",
                    "capability": "web.search",
                    "decision": "DENY",
                    "resource": "production",
                },
            ]
        }
    )
    gateway, sink = runtime(contract)
    call = protect_http(
        gateway,
        protected(),
        http_config(http_server, trusted_effect_resource="production"),
    )
    with pytest.raises(RuntimeFailure):
        asyncio.run(call.invoke({"resource": "development"}))
    assert Handler.hits == []
    assert not any(e.event_type == EventType.TOOL_DISPATCHED for e in sink.events)


def test_fixed_process_resource_is_intersected_with_task_scope():
    contract = unrestricted(
        task_scope={
            "task_id": "task",
            "description": "development-only task",
            "requested_capabilities": ["web.search"],
            "resource_scopes": {"web.search": ["development"]},
        },
        tools={"rules": [{"rule_id": "base", "capability": "web.search", "decision": "ALLOW"}]},
    )
    gateway, sink = runtime(contract)
    call = protect_process(
        gateway,
        protected(),
        ProcessAction(
            schema_version="0.1",
            adapter_id="process",
            request=process_request(argv=(sys.executable, "-c", "print('production')")),
            trusted_effect_resource="production",
        ),
        HostBackend(),
    )
    with pytest.raises(RuntimeFailure):
        asyncio.run(call.invoke({}))
    assert not any(event.event_type == EventType.TOOL_DISPATCHED for event in sink.events)


def test_process_resource_coverage_rejects_unrelated_argument_slot():
    contract = unrestricted(
        tools={
            "rules": [
                {"rule_id": "base", "capability": "web.search", "decision": "ALLOW"},
                {
                    "rule_id": "production",
                    "capability": "web.search",
                    "decision": "DENY",
                    "resource": "production",
                },
            ]
        }
    )
    gateway, _ = runtime(contract)
    metadata = protected(resource_argument_path=("comment",), resource_semantics="opaque_exact")
    action = ProcessAction(
        schema_version="0.1",
        adapter_id="process",
        request=process_request(argv=(sys.executable, "-c", "print('production')")),
        argument_slots=("comment",),
    )
    with pytest.raises(RuntimeFailure, match="ADAPTER_EFFECT_RESOURCE_UNBOUND"):
        protect_process(gateway, metadata, action, HostBackend())
