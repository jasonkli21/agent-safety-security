# Harness-agnostic adapters and isolation

Phase 7 adds async native Python, provider-shaped tool calls, LangChain tools, fixed-endpoint
HTTP and structured process actions. All invoke `RuntimeGateway.call`: native policy,
restrictive identity, approvals, budgets, provenance, response guards and evidence retain one
implementation. Adapter metadata never grants authority. Trusted application configuration,
callables, binaries and contracts must be protected from agent modification.

## Common protected dispatch

`runtime.bindings.ProtectedTool` combines an explicit `ToolDescriptor`, versioned
`ExecutionBinding`, exact resource path/semantics, a trusted fixed effect resource when needed,
approval display paths, output labels and static sink destination. `ProtectedCall` snapshots
validated canonical configuration, checks shared resource/data coverage, validates arguments and
invokes the gateway before its private dispatcher. Its `tool` property returns a fresh copy. There
is no unprotected execute method.
Python object privacy is an application boundary convention, not a sandbox for hostile Python
running inside the same interpreter.

`runtime.arguments` rejects remote schema references and extracts exact object keys without
URL/path alias interpretation. For new adapters, a caller-supplied resource value alone does not
prove the effect target. Resource-scoped ENFORCE bindings must include `trusted_effect_resource`
in the fixed HTTP/process configuration. If an argument extraction path is also configured, its
value must equal that fixed resource before the gateway is entered. A route with no supported
fixed-target mapping fails closed during registration. This is a reviewed operator assertion about
the downstream endpoint or executable; AgentSec cannot prove that a remote server honors the
configured route or that an arbitrary executable has no hidden target. Dynamic resource mappings
for those routes are unsupported until a narrowly scoped mapping can be established. MCP retains
its existing discovery-bound exact opaque resource proof. `runtime.coverage` still checks reviewed
sources and classified sinks; MCP imports these helpers while keeping pagination, pins, request
IDs, transport and coverage-proof projection MCP-specific.

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
LangChain callback handlers and tracing execute outside the AgentSec gateway boundary and may
receive raw tool inputs, outputs or errors before authorization, including for a later-denied call.
LangSmith and other tracing integrations can therefore transmit values that canonical AgentSec
evidence redacts. Apply a separate egress policy to callbacks, tracing and framework persistence;
AgentSec does not sandbox arbitrary callbacks. The default core imports no LangChain dependency.

## HTTP

`protect_http(gateway, tool, HttpAction(...))` binds a fixed protected HTTP(S) origin, exact path,
method, headers, timeout, request/response limits and destination category. Non-GET arguments
are a canonical JSON body; GET accepts only `{}`. Pure method/size validation runs before approval,
budget commitment and dispatch evidence. No variable URL, query or path templating is implemented.
Arguments cannot select a host, port, scheme, trusted headers or sink classification. For
resource-scoped rules, configure `trusted_effect_resource` in `HttpAction`; an extracted resource
must match it exactly. This fixed route mapping is trusted operator configuration, not proof of
remote API semantics. If the API uses another request field to select its effect target, the
configuration must bind that field to the same value or the route is not covered.
URL userinfo/fragments, scheme-relative paths, control characters, ambiguous headers and
proxy/host/framing overrides are rejected.

For HTTPS, provide a protected PEM CA bundle as `tls_ca_pem`. The adapter builds an explicit
TLS 1.2+ client context with hostname and certificate verification enabled. It does not load
system/environment CA paths and does not enable `SSLKEYLOGFILE`; changing `SSL_CERT_FILE`,
`SSL_CERT_DIR` or `SSLKEYLOGFILE` cannot change this route's TLS trust or create a key log. The
CA bundle content is part of the protected route digest and never enters evidence.

The standard-library `http.client` transport does not consult HTTP proxy environment variables,
redirects, retry loops, cookie jars or authentication discovery. Redirect responses fail without
following Location. Responses are bounded while streaming; request bodies are bounded and
validated before approval or connection.
Socket timeouts and a streaming deadline bound reads. Cancellation of the worker cannot undo
an already-sent request: the gateway emits unknown-effect evidence and never retries. A worker
may finish after cancellation, under its timeout. Trusted DNS and endpoint operation remain
operator assumptions; this is not a generic SSRF proxy or DNS-rebinding firewall.

Headers/env/body values never enter canonical evidence. The approval presentation shows only a
resource digest by default; full resource display requires the explicit `approval_display_resource`
setting, with bounded/sanitized rendering. Configured `approval_display_paths` remain the only
argument fields shown. Returned body is untrusted tool output; raw content is returned to the
application, while evidence contains its digest and provenance. Safe errors omit transport
exception text. Protected IDs, labels and destination categories must not themselves contain
secrets.

## Structured process and Docker

`ProcessAction` fixes a versioned `ProcessRequest` (absolute executable, argv tuple, absolute cwd,
explicit env, timeout and aggregate output limit). Named argument slots append one literal string
each in fixed order. No argument chooses executable, cwd, env or isolation. No shell interpolation,
parent environment, PATH resolution, stdin or retry exists. Operator-chosen executables can of
course interpret their arguments; declaring a code-execution capability is not an executable
allowlist. Slot, NUL and argv-size checks run before approval, budget commitment and dispatch
evidence. For resource-scoped rules, `ProcessAction.trusted_effect_resource` is a reviewed
operator assertion about the executable's fixed effect target. Arbitrary executables and unrelated
argument slots cannot establish resource correspondence; unsupported routes fail ENFORCE coverage.
Process groups are killed on cancellation, timeout and output overflow, including cancellation
during asynchronous subprocess acquisition. Output is bounded across stdout plus stderr and
released through the gateway's existing provenance path. This POSIX process lifecycle currently
targets Linux/macOS.

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
Each action has a random container name. A separate bounded cleanup task runs `rm -f`; cancellation
is shielded while cleanup is observed. If daemon confirmation does not arrive within the bound,
the call reports `ISOLATION_CLEANUP_UNCONFIRMED`, retains task/config ownership, and emits a
trace-integrity signal. `pending_cleanup_count` exposes retained work and
`await backend.drain_cleanup()` lets orderly application shutdown wait for it. A later successful
drain does not rewrite earlier unknown-effect evidence. An inaccessible daemon cannot prove
cleanup. Exit 125/126/127 fails isolation. No isolation failure invokes the host backend,
including SHADOW/DISABLED. Docker CLI argv contains explicitly configured process env values;
protect host process inspection permissions accordingly. Canonical evidence never records argv/env.

## Evidence, compatibility and boundaries

New route facts are additive schema `0.1`; old actions/events omit absent fields on serialization.
Compiler `phase6-v1` and authored document/effective-policy hashes are unchanged. Refresh generated
schemas for strict readers. Replay substitutes recorded dispatch metadata, including the binding,
and has no live adapter/backend port. `ReplayResult.diff` compares the scripted policy/evidence
trace; separate `route_comparison` is `UNKNOWN` without candidate metadata. Pass a protected,
content-free `CandidateRouteManifest` to compare recorded routes with the candidate deployment.
Historical dispatches without route facts remain `INCOMPLETE` for candidate route comparison.
Replay cannot prove historical code/container execution from hashes. Existing historical bundles
and regressions retain their identities.

The gateway owns ENFORCE/SHADOW/DISABLED truthfulness and post-dispatch cancellation ambiguity.
Policy shadowing does not disable transport validation or configured isolation. Synthetic shared
conformance tests prove adapter boundaries, not model robustness, sandbox escape resistance or
complete semantic DLP. Docker/gVisor daemon smoke tests are not required by the default suite.
Phase 8 supply-chain verification and Phase 9 delegation graphs remain outside Phase 7.

## Phase 8 trust composition

The optional operator-owned supply-chain guard restricts protected implementations through
RuntimeGateway; it never grants contract or delegated authority. Metadata pins and Ed25519
signatures do not attest runtime code. For stdio MCP, startup happens before tool admission and
trust-enabled ENFORCE requires an externally controlled launch boundary; local file observations
do not bind a file to the launched process or callable. Existing approval, evidence, provenance,
TLS and isolation boundaries remain active. See [supply-chain trust](supply-chain-trust.md) for
exact mode behavior and proof limits. Independent Phase 7 acceptance is still unconfirmed.


## Phase 9 local graph composition

Explicit `phase9-v1` operator-created ENFORCE sessions now add bounded single-parent graphs,
all-ancestor authority/approval/data ceilings, atomic recursive budgets and protected adjacent
messages. Standalone `phase6-v1` behavior and historical digests retain their existing meaning.
The gateway guard applies to direct calls and adapter rebinding. Phase 8 pins restrict tools;
they do not authenticate peers or approve delegation. See [local multi-agent security](multi-agent-security.md)
for ownership, evidence-before-import, finality, source replay blockers, DRAFT graph promotion,
unsupported modes and exact limitations. Earlier one-hop/future-graph statements describe their
original phase boundary. Independent Phase 7–8 acceptance remains unconfirmed.
