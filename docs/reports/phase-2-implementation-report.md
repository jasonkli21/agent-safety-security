# Phase 2 MCP runtime implementation report

## Summary and commit identity

Implemented the Phase 2 MCP enforcement boundary, preserving the Phase 1 review fixes, and
addressed the six findings in the independent Phase 2 review. The remediation is ready for a
follow-up independent review; it is not a general data-flow security system.

- Baseline HEAD: `0213c1407d233b15666fe1f3300b933a5b04e558`
  (`fix: address phase 1 review findings`), branch `main`.
- The plan's older baseline `0a3e2a8` was reconciled with the sink-capture preflight fix and
  evaluation gate-status fix. Both remain covered by the passing regression suite.
- Final HEAD: the single `feat: implement phase 2 MCP runtime gateway` commit containing this
  report, directly atop the baseline. Its exact SHA is in the completion response; embedding
  that commit's own content-addressed SHA here would be self-referential.
- Follow-up: all independent-review fixes, focused regressions, generated schema changes,
  documentation and this report update are in one commit directly atop the reviewed Phase 2
  HEAD. The exact SHA is provided in the completion response.
- The supplied untracked Phase 2 plan is included in this commit. The unrelated untracked
  `PHASE-0-SOL-MEDIUM-PROMPT.md` is preserved untouched and excluded.

## Prerequisites and scope reconciliation

The repository contained the independent review-fixes report but no separate final independent
Phase 1 attestation. The user's explicit instruction to implement Phase 2 with the supplied
implementation-ready plan authorized activation of Phase 2. This supersedes the older phase
boundary; it does not fabricate an independent sign-off. Before editing, inspected the reviewed
fixes and reran the baseline: 381 tests, Ruff and strict mypy passed. Final regression preserves
those semantics; the obsolete protect-command-absence parameter is retired. Phase 2 still requires its own independent review before Phase 3.

## Components and files

- `policy/native.py`: protocol-independent exact-rule policy engine.
- `policy/coverage.py`: conservative unsupported-semantics analysis.
- `adapters/mcp/coverage.py`: binding/discovery-aware resource extraction and exact-semantics
  coverage, kept outside the protocol-independent policy core.
- `runtime/`: typed results/errors, budget and approval ledgers, terminal broker, ordered
  event recorder and async gateway orchestration. No MCP imports occur here or in policy/domain.
- `adapters/mcp/`: strict versioned operational config, immutable serialized discovery
  snapshot, argument/resource normalization, official SDK connections/typed dispatch, and ingress.
- `cli/protect.py`: `agentsec protect mcp`, static `--check`, optional exclusive JSONL output,
  stderr-only operational diagnostics and optional-dependency errors.
- `domain/events.py`: explicit dispatch enforcement mode, conditional decision references,
  explicit redaction metadata, field digests and full policy-input fingerprints;
  `eval/trajectory.py` validates the redaction representation and rejects non-enforcing dispatches.
- `evidence/jsonl.py`: additive exclusive-create option; original Phase 1 truncation default
  is unchanged. Phase 2 cannot overwrite existing evidence or protected inputs.
- Exporter and two generated schema files: new MCP config and updated security event.
- `examples/mcp/`: safe synthetic server, subset contract and operational gateway config.
- Focused policy/runtime unit tests and real SDK memory/stdio integration tests.
- README, AGENTS, focused security/evidence/evaluation docs, architecture/runtime guide,
  report index, CI extra installation, and source packaging for the example server.

## Independent review findings addressed

| Finding | Resolution |
| --- | --- |
| P2-R01 | MCP composition coverage requires an extractor for every discovered tool covered by resource-specific policy or task resource scope. ENFORCE refuses startup; SHADOW reports the exact gap and records a policy ERROR for affected calls. |
| P2-R02 | A stricter resource DENY/REQUIRE_APPROVAL beneath general ALLOW requires `resource_semantics: opaque_exact`. Default-deny exact allowlists remain supported without a generic canonicalizer. |
| P2-R03 | `TOOL_REQUESTED` carries `redacted_fields`, resource/task digests and `policy_input_digest`; trajectory validation preserves the request-to-decision link. |
| P2-R04 | `RuntimeEvents.emit()` poisons on every ordinary sink `Exception`; a failure-callback exception cannot replace the evidence failure. |
| P2-R05 | `RuntimeGateway.call()` requires an explicit `bound` argument. |
| P2-R06 | TTY approvals show the human tool name, capability, bounded resource, configured display paths, hidden-argument warning and exact digest. Persisted summaries remain privacy-minimized. |

The plan's retry requirement was narrowed to session request-ID reuse, cancellation evidence and
budget counting. Repeated MCP request IDs are rejected; new-ID retries remain new authorization
attempts. No review finding was rejected or deferred.

## Enforcement semantics

ENFORCE only dispatches explicitly bound discovered tools with valid complete input arguments
and a supported native policy decision. Exact capabilities and resource strings match rules;
DENY > REQUIRE_APPROVAL > ALLOW > DEFAULT_DENY. All matching rule IDs are retained, and reason
codes are deterministic. A task's capabilities/resources are ceilings. Principal, full agent,
environment, task-scope and delegation consistency are checked. These are local configured
identity checks, not host authentication. Unbound tools are hidden and rejected at call time;
unknown names, duplicate discovery names, stale bindings and configured metadata pin mismatches
cannot silently gain authority. Exceptions/malformed policy decisions yield ERROR and no dispatch.

Resource-specific policy and task resource scopes require an extractor for every discovered
tool with the capability. ENFORCE refuses startup if extraction is unavailable. A resource
DENY/REQUIRE_APPROVAL below general ALLOW also requires `resource_semantics: opaque_exact`, an
operator assertion; no generic path or URL canonicalizer is claimed. SHADOW emits exact gaps and
records ERROR for calls with uncovered resource inputs or semantics instead of treating
`resource=None` as observed absence.

Input and declared successful structured output use Draft 2020-12. Invalid input produces a
signal and safe MCP error before PDP/dispatch. Resource extraction uses exact object-key paths
and requires a nonempty string. Nonlocal schema references refuse setup in all modes, preventing
implicit filesystem/network resolution. Output violation retains the actual return hash and
success flag, emits a signal, and is withheld in ENFORCE. Upstream declared errors remain errors
and skip success-output validation. Upstream transport failure remains distinct from input,
policy, approval, budget and output errors. No semantic content classifiers or verified effects
are invented.

## Coverage and unsupported semantics

Configured data rules, prose invariants, acts-on-behalf-of identity, and non-null model-call,
cost or delegated-agent budgets are coverage gaps, including explicit zero. ENFORCE refuses
startup before serving. SHADOW lists gaps and records a generic coverage signal; it only
calculates supported semantics. Rule matching, task ceilings, tool/write/destructive/session
runtime budgets and approval timeout are supported. Tool risk/data labels classify operational
metadata; there is no provenance-dependent enforcement. General Phase 0/1 examples were not
weakened to make startup succeed.

## Approval and budget counting

Complete validated arguments and resource, identity/environment/task, capability/tool,
input/output schema hash, description hash and effective policy hash bind each action.
Approval requests have contract-derived expiry. Broker results are strictly revalidated,
checked for identity/time/outcome, and redeemed once against the exact digest. No reusable
approval cache exists. A new host invocation creates a new approval even for identical args.
Cancellation, malformed/denied/expired/replayed approval, missing TTY or timeout cannot dispatch.
Pending grants are invalidated on every exit path.

The POSIX `/dev/tty` broker serializes terminal prompts, clears stale terminal input, displays
the human tool name, capability, bounded resource, explicitly configured display paths and
exact digest, with a warning for hidden arguments; it accepts only `approve`. The presentation
is ephemeral and separate from the persisted approval summary. It never consumes protocol stdin
or writes protocol stdout. Local-terminal identity is operational, not cryptographically verified.
Tests use injected brokers and exercise unavailable terminal behavior without interactive input.

Tool-call, EXTERNAL_WRITE and destructive budgets reserve atomically, including concurrent
pending requests. Pre-dispatch rejection/cancellation releases the reservation. Commit occurs
synchronously at dispatcher entry; an upstream attempt consumes its slot even on tool/transport
error or cancellation. Failed pre-dispatch evidence refunds the slot. A post-dispatch failure
preserves it. No lock spans human approval/network I/O. Monotonic elapsed time is checked at
reserve and commit after approval; running calls are not forcibly interrupted at expiry.
SHADOW records exceeded budgets, forwards, and counts actual attempts.

## Modes and canonical evidence

Defaulted `TOOL_DISPATCHED.enforcement_mode` preserves old artifacts as ENFORCE. SHADOW retains
the real DENY/ERROR/REQUIRE_APPROVAL decision and references it at dispatch; it never fabricates
ALLOW or a human grant. Approval requirements are observed without prompting in SHADOW.
DISABLED makes no policy decision and has null decision/approval references. Non-enforcing
dispatches are rejected by Phase 1 trajectory evaluation, preserving its authorization contract.
ENFORCE/SHADOW require a decision ID in both Pydantic validation and exported JSON Schema.

Schema version remains `0.1` for these additive pre-1.0 changes. Older strict consumers need
updated schemas for the optional dispatch mode and request redaction/fingerprint fields; existing
fixtures were migrated and still validate. The config is a new versioned `0.1` artifact. All
generated schemas came from the exporter.

Request, decision, approval, dispatch and return remain separate. Runtime evidence removes
resource, argument summaries and task-scope details; it explicitly marks redacted fields and
records field digests plus a `policy_input_digest` over the full request evaluated by policy.
Full values remain ephemeral for policy and action binding. It records response hashes, not raw
responses. Configured IDs are trusted metadata. Any ordinary sink `Exception` poisons ENFORCE;
failure callbacks cannot obscure that state. A post-dispatch failure cannot erase an effect.
SHADOW reports failure and continues without claiming complete capture. Dispatch records are
attempted invocation evidence, not delivery receipts. Local writes are not transactional with
external effects and may leave partial files.

## Security/privacy assumptions

The operator protects contracts, operational classifications, evidence and executable paths
from agent writes. Tool descriptions never grant authority. Immutable serialized metadata is
copied into each call; refresh requires a new session and new approvals. The upstream must
honor its discovered semantics: a snapshot cannot constrain a malicious implementation.

Stdio uses argv through the official SDK, without shell launch. Every SDK-inherited safe env
variable is explicitly replaced with empty text, then operator env entries are applied;
arbitrary parent secrets are never inherited. The CLI suppresses raw SDK/upstream diagnostics,
using safe codes on stderr. Protocol stdout remains clean. HTTP uses SDK Streamable HTTP;
there is no HTTP ingress, OAuth or bespoke framing. Ephemeral evidence is memory-only unless
an exclusive new JSONL file is requested. Digests reveal equality and do not encrypt/authenticate.

## Deviations and rationale

- Activated the supplied plan under the user's explicit Phase 2 instruction despite the older
  independent-verification boundary; no missing final independent attestation is claimed.
- Minimum optional extra is `mcp>=2.3,<3`, verified against official SDK 2.3.0. The adapter uses
  that version's typed low-level server and request APIs rather than historical v1 decorators.
- Upstream sessions use SDK legacy-compatible negotiation. High-level `Client.call_tool`
  retries, metadata refresh and automatic output validation are deliberately bypassed using
  the official typed `session.send_request`: one authorized attempt and runtime-owned response
  inspection are essential for exact approvals and truthful shadow behavior. Modern/default
  host negotiation and legacy hosts are both exercised at ingress.
- The response guard lives in the protocol-independent runtime, using a typed adapter result;
  a separate response-only adapter module would duplicate this logic.
- Budget exhaustion is an explicit PEP rejection/signal after the native policy decision;
  the engine's ALLOW is not rewritten to claim it evaluated session state.
- Omit task-scope/resource evidence fields entirely rather than trusting arbitrary raw values
  or argument keys as safe summaries. The follow-up review fix adds explicit redaction metadata,
  component digests and a policy-input fingerprint without persisting those raw fields.
- DISABLED nullable decision identity and an explicit dispatch mode are the smallest truthful
  representation; the evaluator conservatively rejects non-enforcing trajectories.
- Added exclusive-create evidence output to avoid truncation/collision hazards. Phase 1 export
  behavior remains unchanged. SDK and upstream diagnostics are suppressed by default because
  their exceptions can contain raw payloads.
- Added binding-aware resource coverage after discovery. Raw exact matching is trusted below a
  broader ALLOW only when the operator declares `opaque_exact`; default-deny resource allowlists
  remain available without a generic canonicalizer.
- The core runtime now requires explicit `bound` proof. Sink append catches every ordinary
  `Exception`, poisons the recorder, and safely ignores failure-callback exceptions.
- Approval TTY presentation receives configured display fields separately from persisted event
  summaries. MCP request IDs are rejected when reused in the same session; host retries with a
  new ID still require new authorization, budget and approval.
- The Phase 2 plan now scopes retry guarantees to request identity and unknown-effect evidence;
  it does not claim exactly-once external effects or distributed idempotency.
- No refresh, cross-session approval cache, distributed idempotency, HTTP ingress, general
  plugin system, provenance engine, compiler or Phase 3 placeholders were added.

## Verification

The first table records verification of the original Phase 2 implementation commit. The
follow-up fixes were verified separately below. Commands ran from the repository root in the
existing Python 3.12.13 environment.
SDK integration dependencies were installed once using uv with an explicit temporary cache.
Core/default tests block socket connections; no credentials or model/network calls are used.

| Exact command | Result |
| --- | --- |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 95 files |
| `.venv/bin/mypy src` | PASS, 57 source files, strict |
| `.venv/bin/pytest -q` | PASS, 443 tests |
| `.venv/bin/pytest tests/integration/test_mcp_gateway.py tests/unit/test_runtime_policy.py tests/unit/test_runtime_state.py -q` | PASS, 61 focused tests |
| `.venv/bin/pytest tests/integration/test_mcp_gateway.py::test_stdio_smoke -q` | PASS, real gateway and upstream subprocesses |
| `.venv/bin/agentsec examples validate` | PASS, original 3 contracts and 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS, all 6 original expected outcomes match |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS, 16 schemas; freshness and independent schema validation pass in pytest |
| `.venv/bin/agentsec protect mcp --contract examples/mcp/contract.yaml --config examples/mcp/gateway.yaml --check` | PASS, ENFORCE diagnostic only on stderr |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel |
| `git diff --check` | PASS |

Also ran an import-blocking Python probe simulating an absent optional MCP package: base CLI,
example validation and static gateway checking succeed; actual protection exits 1 with the
installation hint. Source build log: `/private/tmp/agentsec-phase2-build.log` (not committed).
The no-isolation build was required and passed; no isolated dependency-fetch build was needed.

Focused tests prove rule precedence/task ceilings/identity, unsupported coverage refusal,
thread-concurrent reservation limits, elapsed-time recheck, exact/expired/denied/future/reused
approval, cancellation cleanup, budget counting on upstream failure, policy/evidence fail-close,
pre/post-dispatch sink failure, explicit discovery/pinning, defensive metadata snapshots,
invalid arguments, allow/deny/approval/budget MCP paths, shadow DENY and approval/budget bypass
truthfulness, DISABLED behavior, output withholding/shadow forwarding, declared tool errors,
strict config and environment handling, dependency/static CLI behavior and stdio cleanliness.
The smoke test relays SDK-parsed stdout and asserts no parse errors while a real SDK host
lists/calls the gateway and reads canonical evidence. No SDK framing was reimplemented.

## Independent review remediation verification

Exact commands run for this follow-up commit:

| Exact command | Result |
| --- | --- |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 96 files |
| `.venv/bin/mypy src` | PASS, 58 source files |
| `.venv/bin/pytest tests/integration/test_mcp_gateway.py tests/unit/test_runtime_state.py tests/unit/test_runtime_policy.py -q` | PASS, 69 focused tests |
| `.venv/bin/pytest -q` | PASS, 451 tests |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts and 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS, all 6 expected outcomes match |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS, generated schemas refreshed |
| `.venv/bin/agentsec protect mcp --contract examples/mcp/contract.yaml --config examples/mcp/gateway.yaml --check` | PASS, ENFORCE static coverage check |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel |
| `git diff --check` | PASS |

Focused regressions cover missing extraction in ENFORCE and SHADOW, strict resource semantics
under a broad grant, safe default-deny allowlists, explicit policy-input redaction/digests,
arbitrary sink exceptions, missing core binding proof, approval presentation privacy, cancellation
after dispatcher entry, and repeated MCP request IDs.

## Known limitations and Phase 3 readiness

- A follow-up independent review of these remediations is still needed; there is no production
  security certification.
- HTTP upstream is wired through the SDK but not covered by a live HTTP acceptance server;
  acceptance coverage is credential-free SDK memory plus real stdio subprocesses.
- Only tool calls cross this boundary. Resources, prompts, model calls and non-MCP actions
  are not proxied/enforced. No host authentication, sandbox, content classifier or taint flow.
- Local state resets on restart; a repeated MCP request ID is rejected for the session lifetime,
  while a logical host retry with a new ID is a new attempt. No automatic upstream retries occur.
  Ambiguous cancellation/transport errors cannot prove an external effect absent.
- Session snapshots bind metadata but cannot force an upstream executable to behave honestly.
- Local terminal approval is POSIX-specific and identifies the local controlling-terminal user.
- Synchronous evidence is not tamper-resistant or transactionally coupled to dispatch. Crashes
  and post-dispatch failures can produce incomplete evidence; in-memory capture is not durable.
- Session time limits restrict starting new dispatches, not reversing or forcibly stopping work.
- Raw action/resource context is intentionally unavailable from minimized JSONL alone.

Phase 3 can build on shared canonical actions and the tested native boundary after independent
Phase 2 follow-up review and a reviewed Phase 3 plan. No compiler or policy-derived scenario work
was pulled into this implementation.
