# Harness-agnostic adapters and isolation

Phase 7 adds async native Python, provider-shaped tool calls, LangChain tools, fixed-endpoint
HTTP and structured process actions. All invoke `RuntimeGateway.call`: native policy,
restrictive identity, approvals, budgets, provenance, response guards and evidence retain one
implementation. Adapter metadata never grants authority. Trusted application configuration,
callables, binaries and contracts must be protected from agent modification.

## Common protected dispatch

`runtime.bindings.ProtectedTool` combines an explicit `ToolDescriptor`, versioned
`ExecutionBinding`, exact resource path/semantics, approval display paths, output labels and
static sink destination. `ProtectedCall` snapshots validated canonical configuration, checks
shared resource/data coverage, validates arguments and invokes the gateway before its private
dispatcher. Its `tool` property returns a fresh copy. There is no unprotected execute method.
Python object privacy is an application boundary convention, not a sandbox for hostile Python
running inside the same interpreter.

`runtime.arguments` rejects remote schema references and extracts exact object keys without
URL/path alias interpretation. `runtime.coverage` checks resource extraction, opaque-exact
exceptions, reviewed sources and classified sinks. MCP imports these same helpers; its
pagination, pins, request IDs, transport and coverage-proof projection remain MCP-specific.

Execution binding hashes commit the entire protected metadata snapshot plus adapter identity,
implementation revision, transport configuration and isolation digest. Changing adapter kind,
HTTP destination/settings, process arguments/env/cwd, Docker profile/runtime or classifications
changes approval identity. `NormalizedAction.execution_binding_digest` is omitted when absent,
preserving historical digests. Dispatch evidence contains only safe `ExecutionBinding` identity
facts. Configuration hashes reveal equality; they do not encrypt low-entropy secrets.

## Native Python and providers

Run the complete local example:

```bash
.venv/bin/python examples/adapters/local_tools.py
```

Use `protect_native(gateway, protected_tool, async_callable)` and `await call.invoke(arguments)`.
The callable receives one JSON object. It returns an explicit `ToolResponse` or a strictly
validated JSON value, normalized to a successful structured response. Unsupported Python values
fail explicitly behind safe gateway upstream-failure reporting. No security capability is
inferred from function names. `native_binding(id, implementation_revision)` requires the operator
to update the revision when replacing implementation; hashes do not attest callable code integrity.

`ProviderTools(provider, tuple_of_calls)` exports declarations and accepts these exact call shapes:

| Provider | Call shape |
| --- | --- |
| `openai` | `{"type":"function","id":"optional","function":{"name":"echo","arguments":"{}"}}` |
| `anthropic` | `{"type":"tool_use","id":"correlation","name":"echo","input":{}}` |
| `gemini` | `{"name":"echo","args":{}}` |

OpenAI declarations use the function-tools wrapper, Anthropic declarations use `input_schema`,
and Gemini returns function declarations for a `functionDeclarations` list. Declarations derive
from protected descriptor snapshots; external declarations are not imported as authority.
Unknown fields/names, duplicate registrations/JSON keys, non-object arguments, malformed JSON
and non-finite JSON fail. IDs are ignored for authority and never persisted. Each invocation is
a new gateway call; provider IDs are not durable idempotency tokens. Provider arguments still
must satisfy the protected input schema. There are no provider SDKs, model clients or API calls.
Provider wrappers rebind adapter identity while retaining the original protected dispatcher.

## LangChain and LangGraph

Install `.[langchain]` and call `as_langchain_tool(protected_call)`. It creates a real async
`StructuredTool` with snapshotted name, description and JSON args schema, and a coroutine that
invokes the protected call. This follows the official
[StructuredTool API](https://reference.langchain.com/python/langchain-core/tools/structured/StructuredTool/from_function).
LangGraph can consume it as a normal tool; graph execution/checkpointing is not implemented.
The narrow direction is protected call → framework tool. To protect existing tool behavior,
register its async callable with explicit protected metadata first. Framework callbacks/config
supply no identity or authority. Do not also expose the original unprotected implementation.
Tracing and framework persistence are application responsibilities; canonical AgentSec evidence
remains minimized. The default core imports no LangChain dependency.

## HTTP

`protect_http(gateway, tool, HttpAction(...))` binds a fixed protected HTTP(S) origin, exact path,
method, headers, timeout, request/response limits and destination category. Non-GET arguments
are a canonical JSON body; GET accepts only `{}`. No variable URL, query or path templating is
implemented. Arguments cannot select a host, port, scheme, trusted headers or sink classification.
URL userinfo/fragments, scheme-relative paths, control characters, ambiguous headers and
proxy/host/framing overrides are rejected. HTTPS uses normal certificate verification.

The standard-library `http.client` transport has no proxy/environment handling, redirects,
retry loop, cookie jar or authentication discovery. Redirect responses fail without following
Location. Responses are bounded while streaming; request bodies are bounded before connection.
Socket timeouts and a streaming deadline bound reads. Cancellation of the worker cannot undo
an already-sent request: the gateway emits unknown-effect evidence and never retries. A worker
may finish after cancellation, under its timeout. Trusted DNS and endpoint operation remain
operator assumptions; this is not a generic SSRF proxy or DNS-rebinding firewall.

Headers/env/body values never enter canonical evidence. Returned body is untrusted tool output;
raw content is returned to the application, while evidence contains its digest and provenance.
Safe errors omit transport exception text. Protected IDs, labels and destination categories must
not themselves contain secrets. Only explicitly configured approval-display fields are shown.

## Structured process and Docker

`ProcessAction` fixes a versioned `ProcessRequest` (absolute executable, argv tuple, absolute cwd,
explicit env, timeout and aggregate output limit). Named argument slots append one literal string
each in fixed order. No argument chooses executable, cwd, env or isolation. No shell interpolation,
parent environment, PATH resolution, stdin or retry exists. Operator-chosen executables can of
course interpret their arguments; declaring a code-execution capability is not an executable
allowlist. Process groups are killed on cancellation, timeout and output overflow. Output is
bounded across stdout plus stderr and released through the gateway's existing provenance path.
This POSIX process lifecycle currently targets Linux/macOS.

Select `HostBackend()` explicitly for unisolated local execution, or
`DockerBackend(DockerProfile(schema_version="0.1", image="local:tag", runtime="runsc"))` for
Docker/gVisor composition. Docker images must already exist (`--pull=never`); no registry trust
claim is made. An operator must pin an appropriate image and absolute Docker CLI path. The
protected profile is snapshotted, and its digest binds approvals. `runsc` must be installed and
registered in Docker by the operator; there is no automatic installation or fallback.

Docker uses network `none`, dropped capabilities, no-new-privileges, non-root numeric user,
read-only rootfs by default, memory/CPU/PID limits, explicit cwd/env/mounts and bounded time/output.
Mounts default read-only; root/system/socket mounts and unsafe mount syntax are rejected.
Profiles cannot request privileged mode, host namespaces, arbitrary daemon arguments or a
Docker socket. Mount contents/symlinks remain trusted operator configuration. Writable mounts
and disabling rootfs read-only are explicit protected choices and change identity.

The Docker client gets an empty environment and private empty config directory, preventing
ambient daemon/context/proxy/credential configuration. No Docker credentials are loaded.
Each action has a random container name; `rm -f` cleanup follows the run, including cancellation.
Cleanup errors after interrupted runs remain explicit failures; an inaccessible daemon cannot
prove cleanup. Exit 125/126/127 fails isolation. No isolation failure invokes the host backend,
including SHADOW/DISABLED. Docker CLI argv contains explicitly configured process env values;
protect host process inspection permissions accordingly. Canonical evidence never records argv/env.

## Evidence, compatibility and boundaries

New route facts are additive schema `0.1`; old actions/events omit absent fields on serialization.
Compiler `phase6-v1` and authored document/effective-policy hashes are unchanged. Refresh generated
schemas for strict readers. Replay substitutes recorded dispatch metadata, including the binding,
and has no live adapter/backend port. It cannot prove historical code/container execution from
hashes. Existing historical bundles and regressions retain their identities.

The gateway owns ENFORCE/SHADOW/DISABLED truthfulness and post-dispatch cancellation ambiguity.
Policy shadowing does not disable transport validation or configured isolation. Synthetic shared
conformance tests prove adapter boundaries, not model robustness, sandbox escape resistance or
complete semantic DLP. Docker/gVisor daemon smoke tests are not required by the default suite.
Phase 8 supply-chain verification and Phase 9 delegation graphs remain outside Phase 7.
