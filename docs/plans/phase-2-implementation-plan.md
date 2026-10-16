# Agent Safety & Security Platform — Phase 2 Detailed Implementation Plan

**Phase:** 2 — MCP Runtime Gateway
**Status:** Implementation-ready plan
**Repository:** `jasonkli21/agent-safety-security`
**Repository baseline inspected:** `0a3e2a8d4dedc0b8ae28c029efdbdf92ea8ca7de` (`feat: implement phase 1 local security evaluation lab`)
**Depends on:** Phase 0 foundation; Phase 1 implementation; independent Phase 1 review/fixes merged before Phase 2 implementation begins
**Primary goal:** add the first real production-shaped enforcement boundary: an MCP gateway that discovers upstream tools, normalizes tool calls into the canonical security model, evaluates deterministic policy, handles exact-action approvals, enforces supported budgets, dispatches only when authorized, inspects responses, and records canonical evidence.

---

## 1. Current repository baseline

The current `main` branch has Phase 0 plus the first Phase 1 implementation. Relevant existing foundations include:

- strict Pydantic v2 domain/security artifacts and schema version `0.1`;
- `AgentSecurityContract`, `ToolRule`, `DataRule`, `Budgets`, `TaskScope`, `ToolDescriptor`, `PolicyRequest`, `PolicyDecision`, approvals, provenance references, and typed security events;
- deterministic contract/document hashing and `effective_policy_hash`;
- `NormalizedAction` plus exact `action_digest` binding complete arguments, tool metadata hashes, identity, environment, task/delegation, and effective policy;
- the synchronous `PolicyEngine` port, but no production implementation;
- typed events that distinguish request → policy decision → approval → dispatch → return → verified effect;
- Phase 1 evaluation observations, causal validation, JSONL evidence, reports, and deterministic fixture target;
- 367 passing tests and 99% reported line coverage in the Phase 1 implementation report;
- explicit documentation that Phase 1 does **not** protect a production agent and that Phase 2 remains blocked pending Phase 1 review/fixes.

Phase 2 must preserve the semantic distinctions established by Phases 0–1. In particular, the runtime must not collapse “requested”, “allowed”, “approved”, “dispatched”, and “returned” into a single generic tool-call event.

### 1.1 Baseline caveat

This plan was written against commit `0a3e2a8`. Phase 1 was still awaiting independent review at that commit. Before implementation starts:

1. inspect the then-current `main`;
2. verify Phase 1 review fixes have landed;
3. reconcile this plan with any corrected domain/event/evidence semantics;
4. do not reintroduce a behavior that Phase 1 review intentionally changed.

If a Phase 1 fix materially changes an assumption in this document, update the implementation rather than forcing the old assumption.

---

## 2. Phase 2 objective

Phase 2 turns the project from an evaluation-only system into a real enforcement data plane for MCP tool calls.

The target path is:

```text
MCP host / agent
      │
      │ tools/list, tools/call
      ▼
agentsec MCP gateway (PEP)
      │
      ├─ discover + bind upstream tools
      ├─ validate call arguments
      ├─ build canonical NormalizedAction + PolicyRequest
      ├─ evaluate native deterministic policy
      ├─ enforce runtime budgets
      ├─ obtain exact-action approval when required
      ├─ emit canonical evidence
      └─ dispatch only when authorized
      │
      ▼
upstream MCP server
      │
      ▼
response guard + evidence
      │
      ▼
MCP host / agent
```

A developer should be able to replace an MCP server command/endpoint with an `agentsec protect mcp ...` gateway configuration and receive real runtime enforcement without modifying agent code.

The central invariant is:

> **In `ENFORCE`, no upstream tool dispatch may occur unless the exact action was authorized by a supported policy decision and, when required, an unexpired one-shot approval bound to that exact action.**

Phase 2 is successful when this invariant is true under normal execution, errors, cancellation, unsupported policy semantics, tool metadata changes, and budget exhaustion.

---

## 3. Scope boundaries

### 3.1 In scope

Phase 2 implements:

- an MCP runtime adapter / policy enforcement point (PEP);
- upstream MCP tool discovery;
- canonical tool identity and metadata hashing;
- explicit binding from MCP tools to canonical capabilities/risk metadata;
- a native deterministic `PolicyEngine` implementation for the supported contract subset;
- default deny for unknown/unbound tools in `ENFORCE`;
- task-scope checks for configured capabilities/resources;
- JSON-Schema argument validation before policy/dispatch;
- exact-action approval with a local terminal broker;
- one-shot approval redemption and expiry enforcement;
- enforceable MCP-observable budgets;
- canonical runtime event emission to the existing evidence sink abstraction;
- structural response inspection and output-schema validation when an upstream output schema exists;
- `ENFORCE`, `SHADOW`, and explicit `DISABLED` modes;
- startup enforcement-coverage analysis so unsupported active contract semantics cannot be silently treated as protected;
- a focused `agentsec protect mcp` CLI;
- deterministic local/in-process MCP integration tests plus a small number of subprocess/CLI smoke tests;
- runtime documentation and a Phase 2 implementation report.

### 3.2 Explicitly out of scope

Do **not** implement in Phase 2:

- Phase 3 policy-to-evaluation compilation or generated negative tests;
- a full generic contract compiler;
- automatic capability inference from tool descriptions using an LLM;
- prompt-injection classifiers or LLM judges;
- provenance propagation / taint tracking;
- general enforcement of `DataRule` without trustworthy labels/provenance;
- incident objects or replay bundles;
- multi-agent delegated-authority chains;
- OAuth/OIDC or workload identity;
- hosted approval UI / team workflows;
- Cedar/OPA;
- sandbox/container isolation;
- generic HTTP/API/function-call gateways;
- automatic tool-risk classification;
- cryptographic signatures or tamper-evident audit chains;
- hidden background daemons;
- Streamable HTTP **ingress** unless it is trivial after the stdio path is correct. The required Phase 2 protected client-facing path is MCP stdio; upstream may be stdio or Streamable HTTP through the official SDK abstraction.

Do not pull Phase 3+ functionality forward merely because the gateway creates a convenient place to put it.

---

## 4. Important design decisions

## 4.1 Use the official MCP SDK behind a narrow adapter

Use the current official Python MCP SDK rather than implementing JSON-RPC/MCP framing manually.

As of the plan date, the official Python SDK supports:

- stdio clients;
- Streamable HTTP clients;
- in-process server/client connections useful for tests;
- compatibility across current and older MCP protocol revisions through its client abstraction.

Do not let SDK-specific request/result classes leak into `agentsec.domain` or `agentsec.policy`.

Recommended packaging:

```toml
[project.optional-dependencies]
mcp = ["mcp>=2,<3"]
```

The normal validation/evaluation install should remain usable without the MCP extra. `agentsec protect mcp` must fail with a concise dependency/setup error if the extra is absent.

Keep the SDK in one adapter package so a future SDK major-version migration is localized.

## 4.2 Phase 2 uses a runtime-safe subset of the contract

The current contract already contains concepts the gateway cannot truthfully enforce yet, especially provenance-dependent data rules, model-cost budgets, and natural-language invariants.

Phase 2 must therefore calculate **enforcement coverage** before claiming active protection.

In `ENFORCE`:

- unsupported **active** security semantics must cause startup refusal;
- the gateway must not silently ignore a configured rule/budget/invariant and still present itself as enforcing the contract.

In `SHADOW`:

- startup may continue;
- unsupported semantics must be reported explicitly as coverage gaps;
- the gateway records what the supported policy subset would decide but does not block the call.

In `DISABLED`:

- no policy protection is claimed;
- operational pass-through may occur with minimal lifecycle evidence if configured.

A dedicated Phase 2 runtime example contract may omit semantics not yet enforceable. Do not weaken the existing general examples solely to make the gateway start.

## 4.3 Tool capability binding must be explicit

MCP discovery provides names, descriptions, and JSON schemas, but it does not reliably provide the project’s canonical capability (`email.send`, `web.fetch`, etc.) or side-effect class.

Do **not** infer those security facts from prose descriptions.

Add a strict operational gateway configuration containing a per-tool binding, conceptually:

```yaml
schema_version: "0.1"
server_id: local-tools
upstream:
  transport: stdio
  command: python
  args: [examples/mcp/upstream_server.py]
tools:
  send_email:
    capability: email.send
    side_effect_class: EXTERNAL_WRITE
    destructive: false
    resource_argument: recipient
```

This config maps protocol-level identity into canonical domain identity. It does **not** grant authority; the contract remains the authority source.

Rules:

- every callable protected tool must have exactly one binding in `ENFORCE`;
- unknown/unbound discovered tools are not dispatchable in `ENFORCE`;
- stale bindings for tools that are no longer discovered are startup errors in `ENFORCE`;
- duplicate/ambiguous tool names or bindings are rejected;
- a binding may contain only operational classification needed by Phase 2; do not duplicate allow/deny/approval decisions from the contract;
- use a simple key-path representation for `resource_argument` rather than introducing JSONPath/JMESPath.

## 4.4 Discovered metadata is mutable security input

For each upstream tool, construct a canonical `ToolDescriptor` from:

- stable gateway `server_id`;
- MCP tool name;
- MCP description;
- input schema;
- output schema when present;
- explicit binding capability/side-effect/risk metadata.

Derived `schema_hash` and `description_hash` must feed `NormalizedAction` and approval binding.

Tool metadata can change while the gateway is running. Phase 2 should use a **discovery snapshot** for each gateway session and avoid silently substituting new metadata mid-call.

Minimum behavior:

- discovery occurs before serving calls;
- the protected snapshot is immutable for the session unless an explicit refresh path is implemented;
- a refresh that changes schema/description hashes must invalidate any outstanding approvals and require calls to be normalized against the new descriptor;
- if the upstream reports a tool at call time that was not in the protected snapshot, fail closed in `ENFORCE`.

Supply-chain trust scoring belongs later; Phase 2’s responsibility is to avoid metadata TOCTOU.

## 4.5 Policy remains protocol independent

Implement the first real native policy engine under `agentsec.policy`, not inside the MCP adapter.

The adapter builds a `PolicyRequest`; the native engine decides; the adapter enforces.

The policy engine must not import MCP classes.

---

## 5. Proposed package layout

Add only modules needed by real Phase 2 behavior:

```text
src/agentsec/
├── policy/
│   ├── __init__.py
│   ├── ports.py                 # existing
│   ├── native.py                # deterministic contract subset
│   └── coverage.py              # supported/unsupported semantics analysis
├── runtime/
│   ├── __init__.py
│   ├── models.py                # runtime/session status, budgets, config-neutral types
│   ├── budgets.py               # concurrency-safe runtime counters/limits
│   ├── approvals.py             # broker port + exact one-shot redemption state
│   ├── terminal_approval.py     # local terminal adapter
│   ├── events.py                # runtime event factory/recorder helpers
│   └── gateway.py               # protocol-independent orchestration service
├── adapters/
│   └── mcp/
│       ├── __init__.py
│       ├── config.py            # strict gateway/upstream/tool-binding config
│       ├── discovery.py         # MCP -> ToolDescriptor snapshot
│       ├── normalize.py         # MCP call -> canonical action/request
│       ├── response.py          # structural response guard
│       ├── upstream.py          # official SDK client abstraction
│       └── server.py            # client-facing MCP gateway adapter
├── evidence/
│   └── ...                      # reuse existing sinks; extend only if necessary
└── cli/
    ├── main.py
    └── protect.py               # focused protect command group
```

Names may be adjusted to fit the repository after inspection. Preserve these boundaries even if exact filenames change:

1. policy semantics independent of MCP;
2. runtime orchestration independent of MCP wire classes;
3. MCP translation isolated in an adapter;
4. approvals/budgets have explicit state owners;
5. evidence remains canonical domain events.

---

## 6. Gateway configuration

Add a strict versioned Phase 2 configuration artifact for operational MCP wiring.

Suggested top-level shape:

```text
McpGatewayConfig
- schema_version
- gateway_id
- server_id
- mode: ENFORCE | SHADOW | DISABLED
- upstream
- tool_bindings
- evidence?
- approval?
```

### 6.1 Upstream configuration

Support:

```text
stdio:
  command
  args[]
  cwd?
  env: explicit map only

streamable_http:
  url
  optional explicit headers/auth wiring later
```

Security requirements:

- never invoke a stdio command through a shell;
- pass command/args as an argv sequence;
- do not inherit the entire parent environment by default;
- explicitly allow/pass required environment variables;
- reject NULs and malformed config;
- do not log secrets from environment/header values;
- validate URL scheme for HTTP mode;
- rely on the official SDK’s redirect/session/protocol handling rather than reimplementing it.

### 6.2 Tool binding

Suggested fields:

```text
McpToolBinding
- upstream_name
- capability
- side_effect_class
- destructive
- data_access_labels[]
- risk_tags[]
- resource_argument_path[]?
- expected_schema_hash?
- expected_description_hash?
```

Expected hashes are optional pinning controls. If configured and discovery differs, `ENFORCE` startup fails and `SHADOW` reports a supply-chain-change signal/coverage issue without falsely treating the pin as satisfied.

Do not let a tool binding override the discovered input/output schema or description; it classifies the discovered tool.

### 6.3 Schema export

If gateway config/binding models are public persisted artifacts, export generated JSON Schema through the existing schema exporter and freshness tests. Do not hand-edit schema files.

---

## 7. Native Phase 2 policy engine

Implement a deterministic `NativePolicyEngine(PolicyEngine)` that consumes the existing `AgentSecurityContract` and `PolicyRequest`.

### 7.1 Identity/environment preconditions

The engine should reject/error a request if canonical runtime identity does not match the loaded contract’s protected identity/environment.

At minimum verify:

- request principal matches the contract identity principal expected by this gateway session;
- request agent ID/environment match the contract agent;
- request environment matches contract environment;
- request `effective_policy_hash` is represented on the produced decision via the existing field.

Do not add authentication claims Phase 2 cannot verify. These are configuration/runtime consistency checks, not proof of human identity.

### 7.2 Tool-rule matching

Supported rule semantics:

- exact capability match;
- an optional exact resource selector;
- a rule with `resource = null` applies to that capability generally;
- a resource-specific rule applies only to an exactly normalized resource value;
- if multiple rules match, apply documented decision precedence:

```text
DENY > REQUIRE_APPROVAL > ALLOW > DEFAULT_DENY
```

Reason codes/matched rule IDs must be deterministic.

Unknown capability/tool/binding must not become ALLOW by fallback.

### 7.3 Task scope

If `contract.task_scope` exists:

- a configured `requested_capabilities` set acts as an additional ceiling;
- a requested capability outside that set is denied with `OUTSIDE_TASK_SCOPE`;
- if `resource_scopes` contains the capability, the normalized resource must be present and exactly within the allowed set;
- missing resource when the scope requires one is outside task scope;
- task scope cannot convert a denied capability into allowed authority.

Task scope is a ceiling, not a grant.

### 7.4 Data rules and invariants

Do not claim to enforce provenance-dependent `DataRule` or natural-language `Invariant` in Phase 2.

The coverage analyzer must surface them as unsupported active semantics for `ENFORCE`, unless a narrowly defined data rule is provably irrelevant to this runtime configuration. Prefer conservative refusal over fragile “probably irrelevant” reasoning.

Phase 4 remains the provenance/data-flow milestone.

### 7.5 Deterministic errors

Internal policy evaluation errors produce canonical `PolicyOutcome.ERROR` with `POLICY_ENGINE_ERROR` and are fail-closed by the PEP in `ENFORCE`.

Malformed canonical requests should never fall through to ALLOW.

---

## 8. Argument validation and normalization

For every `tools/call`:

1. resolve the tool from the immutable discovery snapshot;
2. resolve its explicit binding;
3. validate the raw argument object against the discovered Draft 2020-12 input schema;
4. extract the configured resource, if any;
5. build complete `NormalizedAction` using **full validated arguments**;
6. compute `action_digest`;
7. build privacy-minimized `PolicyRequest.arguments_summary`;
8. emit `TOOL_REQUESTED`;
9. evaluate policy.

### 8.1 Argument summary

Do not copy arbitrary full arguments into `PolicyRequest.arguments_summary` merely because the field exists.

Recommended summary contains bounded structural facts needed for explanation, for example:

- sorted top-level keys;
- scalar type markers;
- content hashes for selected values;
- extracted resource separately in `PolicyRequest.resource`.

The exact-action approval still uses full arguments in the ephemeral `NormalizedAction` digest.

### 8.2 Schema failure

Invalid arguments:

- must not reach the upstream server;
- produce a stable runtime error / MCP error result;
- record a policy/security lifecycle event sufficient to explain non-dispatch;
- must not be misreported as an upstream tool failure.

Whether invalid schema creates a `PolicyDecision(ERROR)` or an adapter rejection before PDP should be consistent and documented. Preferred approach: reject before PDP and emit a `SECURITY_SIGNAL(ARGUMENT_VIOLATION)` plus terminal call error, because the canonical request is not valid enough for meaningful authorization.

---

## 9. Runtime budgets

Implement only budgets the MCP gateway can observe faithfully.

Required Phase 2 budgets:

- `max_tool_calls` — count successful upstream dispatch attempts, not mere requests;
- `max_external_writes` — count dispatches for tools classified `EXTERNAL_WRITE`;
- `max_destructive_calls` — count dispatches for tools marked destructive / destructive side-effect class;
- `max_runtime_seconds` — session/run elapsed monotonic time from gateway start/run start.

Do not claim Phase 2 enforcement for:

- `max_model_calls`;
- `max_cost_usd`;
- `max_delegated_agents`.

Those configured fields are coverage gaps in `ENFORCE`.

### 9.1 Reservation semantics

Budget checks must be concurrency-safe and must avoid races that let two simultaneous calls exceed a limit.

Use a reserve/commit/release model or an equivalent lock-protected atomic check:

```text
check remaining
  ↓
reserve slot
  ↓
policy/approval succeeds
  ↓
dispatch begins
  ↓
commit dispatch count
```

If policy or approval fails before dispatch, release the reservation.

If the upstream call is attempted and fails, it still consumed a tool dispatch budget because the privileged dispatch occurred.

Document the exact counting boundary and test it.

### 9.2 Budget exhaustion

Budget exhaustion must:

- produce a DENY decision or a deterministic PEP denial with `BUDGET_EXCEEDED`;
- never call upstream in `ENFORCE`;
- record the attempted request and non-dispatch outcome;
- in `SHADOW`, record the would-deny decision but still dispatch, while keeping shadow counters truthful.

---

## 10. Approval broker and exact-action redemption

Phase 0/1 already define the exact-action digest and one-shot approval semantics. Phase 2 makes them real.

### 10.1 Approval flow

For `REQUIRE_APPROVAL`:

1. construct `ApprovalRequest` bound to the exact `action_digest`;
2. use contract default timeout to compute expiry;
3. emit `APPROVAL_REQUESTED`;
4. invoke the configured broker;
5. emit `APPROVAL_DECIDED`;
6. require `APPROVE`;
7. atomically redeem the approval exactly once for the same action digest before dispatch;
8. emit `TOOL_DISPATCHED` with the approval ID;
9. never allow a changed tool schema/description, arguments, resource, capability, principal, environment, or policy hash to reuse the approval.

### 10.2 Terminal broker

Implement a local terminal broker suitable for a stdio MCP gateway without corrupting the MCP protocol stream.

Requirements:

- never write prompts to MCP stdout;
- never read approval input from the MCP protocol stdin;
- use a controlling terminal/TTY when available;
- write human-facing approval text to the TTY/stderr path only;
- show a redacted immutable action summary, not raw secret-bearing arguments by default;
- support approve/deny with explicit input;
- enforce timeout/expiry;
- if no usable TTY exists, approval is unavailable and `ENFORCE` fails closed for that action;
- tests use an injected fake broker, not real interactive prompts.

Keep the broker behind a port so future UI/team integrations do not alter PEP semantics.

### 10.3 Cancellation and failure

Cancellation, broker exception, closed TTY, timeout, or malformed broker result must not dispatch in `ENFORCE`.

An approval created for a cancelled request must not remain redeemable by a future call.

---

## 11. Enforcement modes

Use the existing `EnforcementMode` enum.

### 11.1 ENFORCE

- supported policy is authoritative;
- policy engine error = deny/fail closed;
- unsupported active contract semantics = startup refusal;
- invalid args = no dispatch;
- unknown/unbound tool = no dispatch;
- approval unavailable/denied/expired = no dispatch;
- budget exhausted = no dispatch;
- response schema violation = withhold the invalid upstream result and return a safe gateway error;
- evidence failure handling must not silently turn into fail-open behavior.

### 11.2 SHADOW

- calculate the same policy/budget/approval requirement where possible;
- record what would have happened;
- do not block solely because of policy/budget/approval decision;
- still preserve protocol-safety validation needed to communicate with upstream;
- do not misleadingly emit a canonical `TOOL_DISPATCHED` that claims an enforcing ALLOW decision if dispatch occurred only because shadow mode bypassed a deny.

The event model currently binds dispatch to a policy decision ID but does not encode “shadow bypass.” If needed, add the smallest explicit runtime field/event representation necessary so evidence remains truthful. Do not overload `ALLOW` to mean “DENY but shadow forwarded.” Any domain schema change must be reviewed, versioned appropriately, and reflected in generated schemas.

### 11.3 DISABLED

- explicit pass-through mode;
- no statement that policy protection is active;
- may still perform MCP translation and basic protocol safety;
- avoid generating fake policy decisions merely for symmetry.

### 11.4 Truthful evidence is more important than schema convenience

If the current canonical events cannot truthfully represent a Phase 2 runtime transition, make a minimal additive domain change rather than encoding a lie.

This is one of the most important review points for Phase 2.

---

## 12. MCP tool discovery behavior

### 12.1 Startup discovery

Before accepting protected tool calls:

1. connect upstream;
2. discover tools;
3. validate unique names;
4. build descriptors;
5. match bindings;
6. verify optional pinned hashes;
7. compute policy coverage;
8. start serving only if mode-specific startup checks pass.

### 12.2 Client-facing tools/list

Preferred Phase 2 semantics:

- expose only tools that have valid bindings in `ENFORCE`;
- preserve discovered name/description/input schema exactly unless the gateway must adapt a protocol-version representation;
- do not rewrite descriptions to claim permissions;
- do not rely on list filtering as authorization—the call path always enforces again;
- in `SHADOW`, it is acceptable to expose all discovered tools, but unbound/unsupported tools must be clearly treated as shadow-only and recorded if called.

If exact list-filter behavior conflicts with the official SDK server abstraction, prioritize call-time enforcement correctness and document the deviation.

---

## 13. Response guard

Phase 2 response inspection is deterministic and structural, not semantic content moderation.

For every upstream return:

- correlate it to the exact dispatch ID/request/tool;
- compute a response hash for evidence;
- record success/error status;
- if the tool descriptor has an output schema and the result exposes structured output, validate it;
- reject/withhold structurally invalid output in `ENFORCE`;
- in `SHADOW`, record the violation and forward when protocol-safe;
- never interpret instruction-like tool text as authority;
- do not persist full raw responses by default.

Do not add secret classifiers, prompt-injection classifiers, or taint propagation in this phase.

### 13.1 Error separation

Keep distinct:

- gateway/policy failure;
- approval failure;
- argument validation failure;
- upstream transport/protocol failure;
- upstream tool-declared error;
- output-schema violation.

All should produce stable diagnostics without leaking raw sensitive payloads.

---

## 14. Evidence and runtime lifecycle

Reuse the existing `SecurityEvent` model and evidence sinks wherever truthful.

A protected session/run should have:

```text
RUN_STARTED
  ├─ TOOL_REQUESTED
  ├─ POLICY_EVALUATED
  ├─ [APPROVAL_REQUESTED]
  ├─ [APPROVAL_DECIDED]
  ├─ [TOOL_DISPATCHED]
  ├─ [TOOL_RETURNED]
  ├─ [SECURITY_SIGNAL]*
  └─ ...
RUN_FINISHED or RUN_TERMINATED
```

### 14.1 Event construction

Create one small runtime event factory/recorder responsible for:

- run/trace IDs;
- monotonic sequence assignment;
- clock injection;
- actor/subject consistency;
- append ordering;
- evidence sink errors.

Do not duplicate event-creation logic across MCP handlers.

### 14.2 Evidence sink failure

Define explicit behavior before implementation.

Recommended:

- in `ENFORCE`, if evidence is configured as required and the sink cannot record security-critical lifecycle events, fail closed for new privileged dispatches;
- avoid retroactively claiming an action did not dispatch if the sink failed after the upstream call began;
- surface partial-evidence state clearly;
- in `SHADOW`, record/report the sink failure but do not convert policy semantics into enforcement;
- default local CLI can use in-memory + optional JSONL, preserving the Phase 1 privacy discipline.

Do not attempt transactional remote audit storage in Phase 2.

---

## 15. Runtime session and concurrency model

The official MCP SDK is asynchronous; Phase 2 runtime orchestration may therefore be async even though the core `PolicyEngine.decide` remains synchronous.

Requirements:

- one upstream client/session per gateway instance unless the SDK strongly recommends a different lifecycle;
- per-call immutable normalization state;
- concurrency-safe budget and approval redemption state;
- no global mutable current-request variables;
- cancellation must unwind reservations and not leave approvals reusable;
- event sequencing must remain deterministic per run even when calls are concurrent;
- no lock should be held across interactive approval or upstream network I/O unless required for atomic state mutation;
- protect against double-dispatch if a client retries a request after cancellation/error.

Phase 2 does not need a generic distributed concurrency framework. Keep synchronization local and explicit.

---

## 16. CLI

Add a focused command group, for example:

```bash
agentsec protect mcp \
  --contract path/to/contract.yaml \
  --config path/to/mcp-gateway.yaml \
  --evidence-out path/to/runtime.jsonl
```

Configuration file should carry most stable operational settings. Avoid a CLI with dozens of flags.

CLI requirements:

- validate contract and gateway config before launching upstream;
- print human diagnostics to stderr only while stdio MCP protocol is active;
- stdout is reserved for MCP protocol frames in stdio mode;
- stable nonzero exit codes for startup/config/dependency failures;
- no raw secret/argument dump in errors;
- explicit banner/logging that indicates `ENFORCE`, `SHADOW`, or `DISABLED` without contaminating stdout;
- a `--check` or equivalent dry startup-validation mode is useful if it can validate config/coverage without running a long-lived gateway.

Do not add background-process management or service installation.

---

## 17. Example protected MCP server

Add one deliberately small local example server used by docs/tests.

Suggested tools:

```text
search(query)                  -> READ / web.search
send_email(recipient, body)    -> EXTERNAL_WRITE / email.send
write_file(path, content)      -> INTERNAL_WRITE / filesystem.write
```

The example should demonstrate:

- ALLOW;
- DENY/default deny;
- REQUIRE_APPROVAL;
- task-scope/resource restriction;
- budget exhaustion;
- invalid argument rejection;
- response-schema violation in a controlled test-only variant.

Keep it synthetic and credential-free. It should never send real email, access real files outside a temp fixture, or make network requests.

---

## 18. Focused testing strategy

Phase 2 is security-sensitive, but test volume should remain targeted. The goal is strong boundary coverage, not maximizing test count or line coverage.

### 18.1 Unit tests — policy

Cover the decision table, not every permutation:

- exact allow;
- explicit deny precedence;
- approval precedence;
- default deny;
- general + resource-specific rules;
- task-scope capability/resource ceiling;
- identity/environment mismatch;
- deterministic reason/matched-rule output;
- policy error never becomes allow.

### 18.2 Unit tests — coverage

Cover:

- supported tool rules/task scope/tool budgets;
- unsupported data rule/invariant/model-cost/delegation budgets;
- `ENFORCE` refusal;
- `SHADOW` gap reporting;
- no accidental “fully enforced” status when unsupported semantics exist.

### 18.3 Unit tests — runtime state

Cover:

- budget atomic reservation under concurrent calls;
- failed/denied call does not consume dispatch budget;
- attempted upstream dispatch does consume budget even if upstream errors;
- approval exact digest match;
- approval expiry;
- one-shot redemption;
- cancellation releases reservation and invalidates pending approval.

### 18.4 Adapter tests

Cover:

- strict tool binding/discovery;
- stale/unbound tool handling;
- input-schema validation before dispatch;
- no shell execution for stdio config;
- environment allow-list behavior;
- response-schema validation;
- stdout remains protocol-clean.

### 18.5 End-to-end MCP tests

Use the official SDK’s in-process transport where possible. A compact table of end-to-end cases is enough:

1. allowed tool dispatches and returns;
2. denied tool never reaches upstream;
3. approval-required tool dispatches only after exact approval;
4. expired/denied approval never dispatches;
5. budget-exhausted call never dispatches;
6. shadow-denied call still dispatches but evidence remains truthful;
7. metadata/schema mismatch fails startup in enforce mode;
8. invalid output schema is withheld in enforce mode.

Add only a few real subprocess stdio smoke tests to catch wire/stdout/lifecycle mistakes that in-process tests cannot.

### 18.6 Regression tests

All Phase 0 and Phase 1 tests must continue to pass. Existing eval semantics and schemas should remain unchanged unless a justified additive runtime evidence change is required.

### 18.7 What not to do

Avoid:

- hundreds of near-duplicate schema cases;
- exhaustive generated permutations when a decision table is clearer;
- testing private SDK implementation details;
- brittle timing sleeps for approval/budget tests—inject clocks/events instead;
- coverage-chasing tests with no security assertion.

---

## 19. Implementation sequence

### Step 0 — Reconcile reviewed baseline

- inspect current `main` and Phase 1 review/fix reports;
- run current fast checks;
- update this plan’s assumptions if necessary before coding;
- preserve unrelated user changes.

**Exit:** implementation starts from a known reviewed baseline.

### Step 1 — Add MCP extra and adapter shell

- add optional MCP SDK dependency;
- create adapter package and strict dependency error path;
- add gateway config models/load/validation/schema export.

**Exit:** config can be validated without starting a gateway.

### Step 2 — Discovery + tool bindings

- connect to a synthetic/in-process upstream;
- discover tools;
- build immutable `ToolDescriptor` snapshot;
- bind tools explicitly;
- verify optional metadata pins;
- define list exposure behavior.

**Exit:** a protected tool registry exists before any call can be served.

### Step 3 — Policy coverage + native engine

- implement coverage analysis;
- implement runtime-safe contract subset;
- deterministic decision/reason behavior;
- enforce task-scope ceiling/default deny.

**Exit:** protocol-independent policy tests pass.

### Step 4 — Runtime orchestrator + evidence factory

- create request/session context;
- normalize arguments/action/request;
- emit request + decision events;
- implement fail-closed error paths;
- reuse evidence sinks.

**Exit:** allowed/denied canonical flows work without real MCP forwarding.

### Step 5 — Budgets

- add atomic budget state;
- integrate pre-dispatch reservation/commit/release;
- implement elapsed runtime budget.

**Exit:** concurrent calls cannot overshoot configured supported budgets.

### Step 6 — Approvals

- add broker port + fake broker;
- add terminal adapter;
- bind exact action digest;
- expiry and one-shot redemption;
- cancellation cleanup.

**Exit:** approval-required actions cannot dispatch without exact valid approval.

### Step 7 — Real MCP forwarding

- expose client-facing stdio MCP server/gateway;
- support stdio upstream and SDK-backed Streamable HTTP upstream if straightforward;
- forward allowed calls only;
- preserve SDK protocol handling.

**Exit:** a normal MCP host can use the gateway instead of the upstream server.

### Step 8 — Response guard

- correlate return to dispatch;
- hash response;
- validate structured output when schema is declared;
- implement enforce/shadow behavior;
- emit return/security evidence.

**Exit:** structurally invalid upstream output cannot silently pass as valid in enforce mode.

### Step 9 — Modes + coverage truthfulness

- verify ENFORCE/SHADOW/DISABLED semantics end-to-end;
- make shadow evidence explicit/truthful;
- add the smallest additive domain field/event change if existing events cannot represent shadow dispatch honestly.

**Exit:** no mode lies about why a call dispatched.

### Step 10 — CLI + examples + docs

- add `agentsec protect mcp`;
- synthetic example server/config/contract;
- runtime guide;
- README/AGENTS phase status;
- implementation report.

**Exit:** documented local manual journey works without credentials/network.

### Step 11 — Focused verification

Run at minimum:

```bash
ruff check .
ruff format --check .
mypy src
pytest -q
agentsec examples validate
agentsec eval examples
agentsec schema export --out schemas/generated
python -m build --no-isolation
```

Also run the Phase 2 MCP integration subset explicitly and one stdio smoke command.

Do not add broad unrelated test suites merely to increase counts.

---

## 20. Acceptance criteria

Phase 2 is complete only when all of the following are true.

### 20.1 Security boundary

- A real MCP tool call passes through an `agentsec` PEP before upstream dispatch.
- `ENFORCE` never dispatches a denied/default-denied/invalid/unbound/budget-exhausted action.
- Policy-engine failure fails closed.
- Unsupported active contract semantics prevent an `ENFORCE` startup rather than being silently ignored.

### 20.2 Exact approval

- `REQUIRE_APPROVAL` creates an exact-action-bound request.
- approval expiry is enforced;
- one approval is redeemable once;
- changed arguments/resource/tool metadata/policy hash cannot reuse approval;
- approval unavailable/denied/cancelled never dispatches in enforce mode.

### 20.3 Tool integrity

- upstream tools are discovered before serving calls;
- bindings are explicit;
- metadata hashes are used in normalized actions;
- configured hash mismatches fail closed in enforce mode;
- unknown tools are not silently authorized.

### 20.4 Budgets

- supported tool/write/destructive/runtime budgets are enforced at the documented counting boundary;
- concurrent calls cannot race past a limit;
- unsupported budgets are reported as coverage gaps.

### 20.5 Evidence

- runtime emits truthful canonical request/decision/approval/dispatch/return evidence;
- shadow forwarding is distinguishable from an enforcing allow;
- raw arguments/responses are not persisted by default;
- evidence failures do not accidentally make enforcement fail open.

### 20.6 MCP behavior

- normal MCP clients can list/call protected tools through the gateway;
- no human log/prompt corrupts stdio stdout;
- allowed upstream success/error results remain protocol-compatible;
- structural output violations follow documented mode semantics.

### 20.7 Quality

- all pre-existing tests pass;
- focused new tests cover the boundary and known bypass classes;
- type/lint/schema/build checks pass in the available environment;
- docs clearly state what Phase 2 does and **does not** enforce;
- implementation report records deviations, commands/results, limitations, and Phase 3 readiness.

---

## 21. Security review checklist for the implementation

The implementation review must examine at least:

- fail-open paths on exception/cancellation/timeout;
- policy/dispatch TOCTOU;
- approval digest mismatch/reuse;
- metadata refresh/stale approval behavior;
- argument schema bypasses;
- tool alias/name collisions;
- incorrect default-allow fallbacks;
- task-scope treated as grant instead of ceiling;
- budget races/off-by-one counting;
- shadow events that falsely look enforced;
- stdout contamination in stdio mode;
- shell/env injection in upstream launch;
- sensitive data in logs/events/errors;
- response-schema bypass;
- evidence sink failure behavior;
- concurrent request event ordering/correlation;
- unsupported contract semantics falsely labeled “enforced.”

This checklist is a minimum, not a limit. The review must independently look for defects the plan failed to anticipate.

---

## 22. Phase 3 handoff boundary

Phase 2 intentionally leaves the project with a narrow but real runtime boundary. Phase 3 should then unify specification, evaluation, and runtime semantics more deeply.

Phase 3 candidates include:

- formal contract compilation into a normalized effective policy;
- deriving evaluation obligations from the same rules enforced at runtime;
- generated negative tests from allow/deny/approval contracts;
- drift checking between evaluation and runtime policy;
- broader supported contract semantics;
- stronger policy coverage/posture reporting.

Do not implement those in Phase 2.

The key Phase 2 deliverable is simpler and foundational:

> **A trustworthy MCP action boundary that can prove why an exact action was or was not dispatched, without overstating what parts of the security contract it enforces.**
