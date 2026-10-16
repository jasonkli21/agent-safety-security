# MCP runtime gateway (Phase 2)

Install Python 3.12+ and the optional official SDK extra:

```bash
python -m pip install -e '.[dev,mcp]'
agentsec protect mcp --contract examples/mcp/contract.yaml --config examples/mcp/gateway.yaml --check
```

From the repository root, configure an MCP host to launch:

```bash
.venv/bin/agentsec protect mcp \
  --contract examples/mcp/contract.yaml \
  --config examples/mcp/gateway.yaml \
  --evidence-out /tmp/agentsec-runtime-new.jsonl
```

The evidence path must not already exist. Omit it for ephemeral in-memory evidence. All human
status/error output goes to stderr; stdout belongs to MCP. `--check` validates configuration
and contract coverage without connecting, discovering tools, or checking metadata pins.
Startup/setup failures exit 1; invalid command usage exits 2. Individual call failures return
MCP `isError` results containing stable codes, without stopping an otherwise usable session.
The synthetic server never searches the web, sends email, or writes files.

Use absolute command/script/config paths when launching outside the repository root. The
example's `.venv/bin/python` command assumes the repository root as working directory.
Streamable HTTP upstreams use `transport: streamable_http` and `url: https://host/mcp`;
HTTP ingress and authentication configuration are outside Phase 2. HTTP upstream support uses
the SDK transport; the credential-free acceptance tests exercise memory and stdio transports.

## Authority and coverage

Bindings identify a discovered tool's capability, side-effect class, destructive flag, optional
risk/data labels and resource key path. They grant no permission. A missing binding makes the
tool invisible and uncallable in ENFORCE. Stale bindings, duplicate names and failed metadata
pins refuse ENFORCE startup. SHADOW reports unbound/stale/pin gaps and forwards discovered
unbound tools with a synthetic `mcp.unbound` capability and explicit DENY decision.

The native policy supports exact capability and optional exact opaque resource strings.
Precedence is DENY > REQUIRE_APPROVAL > ALLOW > DEFAULT_DENY; matched IDs include all matching
rules. Task requested capabilities and per-capability resource sets are additional ceilings.
No path, URL, email, wildcard or Unicode equivalence is inferred. Identity, agent, environment,
task and delegation consistency checks fail closed; they do not authenticate the MCP host.

Configured data rules, prose invariants, acts-on-behalf-of identity, model-call, cost and
agent-delegation budgets are unsupported. Even configured zero budgets count as active.
ENFORCE refuses these contracts; SHADOW lists gaps and evaluates only the supported subset.
Existing general contracts remain unchanged; the runtime example deliberately uses the subset.

## Discovery and schemas

The gateway discovers all paginated tools once before serving. It stores canonical serialized
snapshots and returns copies, preserving names, descriptions and schemas. Input/output schema
hashes and description hashes participate in the complete action digest; optional pins use
those same hashes. No live refresh occurs. Restart to adopt new metadata; approvals cannot
survive a session. The upstream is trusted to execute its discovered semantics; a snapshot
cannot stop a compromised server changing its implementation behind unchanged metadata.

Draft 2020-12 input validation precedes policy. Resource paths are nonempty arrays of exact
object keys; missing/non-string/empty resource values fail. Schema references must be local
fragments; remote/file references refuse startup in every mode to avoid implicit retrieval.
Invalid arguments never dispatch, including SHADOW and DISABLED. These are protocol safety
rejections rather than simulated policy decisions.

The adapter uses SDK typed requests with a legacy-compatible upstream session. It bypasses
the SDK high-level automatic retries, metadata refresh and output validation so the runtime
owns exact dispatch and response inspection. Each accepted invocation attempts upstream once.
A host retry is a new action requiring fresh authorization, budget and approval. There is no
durable distributed idempotency guarantee or automatic retry after ambiguous transport errors.

## Approvals and budgets

ENFORCE approval requests expire after the contract timeout. The local POSIX `/dev/tty` broker
serializes prompts on a separate terminal, clears stale input, displays only the immutable action
digest/tool/capability, and accepts the exact word `approve`; all other input denies. It never
reads protocol stdin or writes protocol stdout. No terminal, timeout, broker failure, malformed
result, cancellation, changed binding or expired/reused approval prevents dispatch. The terminal
principal is an operational local identity, not an authenticated remote approver.

Complete arguments, resource, principal, agent/environment/task, capability/tool identity,
metadata hashes and effective policy hash bind the action. Evidence summaries do not substitute
for that digest. Redemption consumes the grant once; cleanup invalidates pending grants.
SHADOW records approval requirements without prompting or manufacturing approval decisions.

Budgets are session-local. Tool attempts, EXTERNAL_WRITE attempts and destructive attempts
reserve counters atomically before approval, commit immediately at dispatch, and release on
pre-dispatch rejection/cancellation. Upstream tool/transport errors still count. Concurrent
pending approvals occupy reservations, but no lock spans human or network I/O. Evidence failure
before dispatcher entry refunds the committed slot; a failure after entry preserves the attempt.
Elapsed monotonic time is checked at reserve and commit, including time spent awaiting approval;
it limits starting calls and does not forcibly undo/interrupt a call already in progress.
SHADOW emits budget signals while continuing and counting actual attempts. DISABLED passes
protocol-safe calls without policy evaluation or budget/approval enforcement.

## Responses, evidence and limitations

Returns carry upstream success/error and a full response hash. Successful structured output
must match a declared output schema, including missing structured output. ENFORCE withholds
violations behind `OUTPUT_SCHEMA_VIOLATION`; SHADOW signals and forwards protocol-valid output.
Upstream declared tool errors remain errors and are exempt from success-output validation.
No semantic content classifier, provenance propagation or verified effect is claimed.

Canonical request/decision/approval/dispatch/return events remain distinct. A dispatch's new
`enforcement_mode` defaults to ENFORCE for older artifacts. SHADOW preserves the real policy
decision, including DENY/ERROR; DISABLED has no policy decision ID. Phase 1's evaluator rejects
non-enforcing dispatch trajectories rather than scoring them as authorized execution.

Default evidence omits complete arguments, argument keys, responses, resource and task-scope
values. Hashes disclose equality and can be guessed; they are not encryption. Configured
identity/capability/rule IDs are trusted metadata and must not contain secrets. SDK and upstream
stderr diagnostics are suppressed by the CLI to avoid raw-wire exception leaks; safe errors
remain available. Contracts/configuration/evidence and upstream executables must be protected
from agent writes. Environment values are explicit: the adapter replaces SDK-inherited safe
variables with empty strings, then applies `upstream.env`; it never inherits arbitrary secrets.
Use explicit environment entries if a tool requires PATH, HOME or other process context.

Evidence writes are synchronous, local and not transactional with external effects. ENFORCE
poisons the session on a sink failure and refuses subsequent dispatch; a post-dispatch failure
cannot undo effects. SHADOW reports evidence failure and continues without claiming complete
capture. Dispatch evidence records an attempted invocation, not delivery, success or verified
effect. Cancellation after entry records an unknown-effect signal and never retries. Process
crashes may leave incomplete streams. There is no tamper resistance, sandbox, remote identity
verification, taint analysis, hosted approval service or Phase 3 compiler.
