# Agent Safety & Security Platform — Phase 7 Detailed Implementation Plan

**Phase:** 7 — Harness-Agnostic Adapters & Isolation Integration
**Status:** Implementation-ready plan
**Repository:** `jasonkli21/agent-safety-security`
**Repository baseline inspected:** `4dd82ea844638c536792cdb0efef206f6cacd6e9` (`fix: address phase 6 identity review findings`)
**Depends on:** Phases 0–6, including the Phase 6 independent-review correction pass
**Primary goal:** prove that the security lifecycle is genuinely protocol/harness independent by placing multiple real action surfaces behind the same runtime policy/evidence/identity/provenance boundary, while composing safely with external execution isolation instead of turning AgentSec into a sandbox or agent framework.

---

## 1. Current repository baseline

Phase 7 starts from the post-Phase-6-review-fix state, not from the original roadmap in isolation.

At the inspected baseline, `main` already provides:

1. **Canonical contracts, compiler, and policy semantics**
   - strict YAML/JSON parsing;
   - deterministic document/effective-policy identity;
   - `CompiledSecurityPlan`;
   - runtime/evaluation/conformance sharing compiled semantics;
   - semantic diff and explicit unsupported coverage.

2. **Protocol-independent runtime enforcement core**
   - `src/agentsec/runtime/gateway.py` is explicitly protocol-independent;
   - `RuntimeGateway.call(...)` owns policy evaluation, approvals, budgets, provenance, evidence, final authority freshness, exactly-one dispatch semantics, response validation, and mode behavior;
   - `ToolDescriptor`, `PolicyRequest`, `NormalizedAction`, `ToolResponse`, `RuntimeFailure`, and evidence payloads are canonical types.

3. **One mature runtime adapter: MCP**
   - discovery snapshots;
   - strict tool bindings;
   - resource extraction;
   - metadata pins;
   - source/sink classifications;
   - ENFORCE/SHADOW/DISABLED semantics;
   - stdio and streamable-HTTP upstream support.

4. **Tracked provenance/data-flow controls**
   - monotonic labels;
   - exposed-context snapshots;
   - source/sink coverage;
   - data-flow policy that only restricts existing authority.

5. **Replay, incidents, and regression**
   - strict offline replay;
   - source/current plan distinction;
   - incident classification;
   - safe regression promotion;
   - no live tool/model execution during replay.

6. **Identity/delegation/least privilege**
   - trusted static or pinned signed-JWT workload identity;
   - direct one-hop OBO delegation;
   - authority/task/capability/resource intersections;
   - freshness at startup, per call, and post-approval;
   - authority-bound approvals/evidence/replay.

7. **Phase 6 independent-review fixes**
   - Phase 6 requests now require trusted authority even for direct principals;
   - protected authority recovered during replay is not copied into public ACTIVE regressions;
   - policy-time authority scope violations classify correctly;
   - several current-state docs were refreshed.

### 1.1 Baseline caveat that Phase 7 must resolve before feature work

`docs/reports/phase-6-review-fixes-report.md` states that the focused tests, full test suite, Ruff, formatting, and mypy were **not run** in the fix session. `AGENTS.md` also still describes Phase 6 as “awaiting independent review.”

Therefore Phase 7 implementation must begin with a repository preflight:

```bash
pytest -q
ruff check .
ruff format --check .
mypy src
agentsec examples validate
agentsec eval examples
agentsec regression run --root examples/regressions
python -m build --no-isolation
git diff --check
```

Use the project environment/commands actually present at implementation time.

If the post-review-fix baseline fails before Phase 7 changes:

- do not bury the failure under Phase 7 changes;
- determine whether it is caused by the Phase 6 review-fix commit or by environment/setup;
- fix only prerequisite regressions necessary to establish a green baseline;
- record that work distinctly in the Phase 7 implementation report;
- do not reinterpret Phase 6 semantics for convenience.

### 1.2 Baseline reconciliation rule

Before implementation, inspect current HEAD and reconcile this plan with newer commits. At minimum read:

1. `AGENTS.md`
2. `docs/prd.md`
3. `docs/architecture.md`
4. `docs/plans/phase-6-implementation-plan.md`
5. `docs/reports/phase-6-implementation-report.md`
6. `docs/reports/phase-6-review-fixes-report.md`
7. `docs/runtime-mcp.md`
8. `docs/identity-delegation.md`
9. `docs/provenance-data-flow.md`
10. `docs/evidence-model.md`
11. `docs/replay-incidents.md`
12. `docs/contract-conformance.md`
13. the compiler/policy/runtime/adapter/evidence/replay code
14. current tests, examples, and generated schemas

Do not force stale filenames or APIs if the repository advances after this plan.

---

## 2. Phase 7 objective

The PRD defines Phase 7 as **Harness-Agnostic Adapters & Isolation Integration**:

- Python/native dispatch;
- OpenAI/Anthropic/Gemini-style tools;
- LangGraph/LangChain;
- HTTP;
- shell/coding-agent actions;
- composition with Docker/gVisor/WASM/microVM-style isolation.

The architecture already says MCP is the **first adapter, not the platform boundary**, and defines the real protected boundary as:

> untrusted or probabilistic intent → privileged side effect

The concrete Phase 7 objective is:

> **Make `RuntimeGateway` and the canonical security model usable across multiple action/harness surfaces through a small, typed adapter contract; ensure every adapter normalizes into the same protected dispatch semantics before execution; bind approvals/evidence to the actual execution route; and integrate code/process execution with explicit isolation without implementing a new sandbox platform.**

The core invariant is:

```text
provider / harness / protocol-specific action
    ↓ normalize once
canonical protected tool invocation
    ↓
same authority + policy + approval + budget + provenance + evidence boundary
    ↓
adapter-specific dispatcher
    ↓
optional isolation boundary
    ↓
side effect
```

No adapter may become a second policy engine.

---

## 3. Phase boundary

### 3.1 In scope

Phase 7 should implement:

- a small protocol-independent adapter/execution-binding model;
- a reusable protected native Python dispatch API built on `RuntimeGateway`;
- generic resource extraction and adapter binding validation where semantics are shared;
- provider-shaped tool adapters for OpenAI-, Anthropic-, and Gemini-style tool declarations/calls without requiring model API calls;
- a narrow LangChain/LangGraph integration that wraps tools/actions rather than replacing those frameworks;
- a protected outbound HTTP action adapter with fixed trusted endpoint configuration;
- a protected process/coding-action adapter using argv execution, never implicit shell interpolation;
- an isolation port used by the process adapter;
- one concrete Docker-backed isolation integration;
- Docker runtime selection sufficient to compose with gVisor/runsc when installed;
- explicit no-isolation/host-execution representation where needed, never silent fallback;
- execution-route binding into approval/evidence identity;
- replay/regression compatibility for additive Phase 7 evidence;
- contract/runtime conformance checks where adapter coverage can be proven deterministically;
- focused negative tests for adapter bypasses and isolation failures;
- examples and focused docs;
- Phase 7 implementation report;
- stale phase-boundary documentation updates.

### 3.2 Explicitly out of scope

Do **not** pull later phases or adjacent products into Phase 7:

- a general agent framework;
- a hosted gateway/control plane;
- a dynamic third-party plugin marketplace/API;
- a full OpenAI/Anthropic/Gemini model client abstraction;
- model invocation routing;
- automatic agent-framework instrumentation of arbitrary code;
- browser automation;
- a generic transparent HTTP proxy;
- arbitrary user-supplied URLs as trusted destinations;
- shell-string execution via `shell=True`;
- a terminal emulator;
- a complete coding agent;
- filesystem virtualization as a new product;
- implementing a container runtime;
- implementing gVisor, WASM, Firecracker, Kata, or a microVM monitor;
- Kubernetes orchestration;
- network policy control plane;
- seccomp/AppArmor profile authoring system;
- signed image/tool provenance;
- registry trust and supply-chain verification (Phase 8);
- multi-agent delegation graphs (Phase 9);
- new Cedar/OPA/general policy language;
- recursive delegated-agent budgets;
- dynamic OIDC discovery/revocation;
- relaxing direct Phase 6 authority requirements;
- automatic tool trust based on provider/framework name.

Phase 7 may define an isolation interface because it is required by a real Docker implementation. It must not create empty placeholder backends for future runtimes.

---

## 4. Design decisions

### 4.1 Reuse `RuntimeGateway`; do not create a parallel enforcement pipeline

`RuntimeGateway.call(...)` already contains the security-critical lifecycle.

Phase 7 should evolve its call surface only enough to make adapter use less error-prone. New adapters must not independently reimplement:

- identity checks;
- policy evaluation;
- approval creation/redemption;
- budgets;
- provenance snapshots;
- evidence ordering;
- data-flow checks;
- response schema checks;
- post-approval freshness;
- enforcement-mode behavior.

A compatibility path for existing MCP callers should remain while MCP migrates to the common adapter-facing abstraction.

### 4.2 Separate authorization identity from execution-route identity

A canonical tool/capability answers “what action is this?”

The adapter/execution binding answers “through what protected route will it execute?”

Those concepts should not be conflated.

Recommended additive model:

```text
ExecutionBinding
- schema_version
- adapter_kind
- adapter_id
- adapter_version
- binding_digest
- isolation? / isolation_digest?
```

Exact naming may change, but preserve these semantics:

- protected configuration creates the binding;
- model/tool arguments cannot choose a trusted adapter ID;
- the binding does not grant authority;
- it is stable for the protected runtime session;
- it can be safely summarized in evidence;
- the exact execution binding participates in the normalized action/approval digest for new Phase 7 adapters.

This prevents an approval for one execution route from being silently reused for another route that happens to share the same tool ID/capability/arguments.

### 4.3 Adapter metadata is restrictive/descriptive, never a grant

Framework/provider metadata may supply:

- tool name;
- description;
- JSON schema;
- provider call ID;
- structured arguments.

It must never implicitly supply:

- allowed capability;
- principal;
- delegation;
- data labels;
- trusted destination class;
- approval exemption;
- trusted resource semantics;
- isolation trust.

Those come from protected configuration or canonical runtime state.

### 4.4 Snapshot mutable framework metadata

Provider/LangChain tool descriptions and schemas may be mutable.

At registration/startup:

- normalize;
- validate;
- hash;
- snapshot;
- use the snapshot for the runtime session.

Do not silently adopt mid-session mutations.

Phase 8 will add stronger supply-chain/change-detection semantics. Phase 7 should not claim that a snapshot proves the underlying implementation has not changed.

### 4.5 Isolation is a separately controlled execution primitive

Policy authorization and isolation answer different questions:

```text
Policy: may this action execute?
Isolation: under what containment does this process execute?
```

A policy ALLOW never disables required isolation.

An isolation backend never grants a capability.

For process/code execution:

- the selected backend comes from protected config;
- backend startup failure has no unsafe host fallback;
- ENFORCE must fail closed when configured containment is unavailable;
- SHADOW means policy shadowing, not “ignore isolation configuration”;
- DISABLED means AgentSec policy is disabled, not “pretend configured Docker isolation succeeded.”

### 4.6 One concrete isolation path is enough for Phase 7

Implement a real Docker-backed backend with a typed command builder and process invocation.

Support gVisor composition by allowing a protected Docker runtime selection such as `runsc`.

Do not implement WASM or microVM backends in this phase. The isolation interface should make them possible later without changing policy/runtime semantics, but they are not required for the Phase 7 exit gate.

### 4.7 No compiler-version bump unless contract semantics change

Phase 7 is primarily operational/adaptor behavior.

If no authored security-contract semantics change:

- keep the current compiler semantics/version;
- do not alter `effective_policy_hash`;
- do not turn execution adapter configuration into contract policy accidentally.

If implementation discovers a genuine need to make isolation or adapter identity an authored policy semantic, that is an architecture change: document it explicitly and bump/version compatibility deliberately rather than sneaking it in.

---

## 5. Target architecture

Recommended shape:

```text
                        Agent / Framework / Model
                                  │
          ┌───────────────────────┼────────────────────────┐
          ▼                       ▼                        ▼
     Native Python         Provider-shaped calls     LangChain/LangGraph
          │                       │                        │
          └──────────── normalize / register ──────────────┘
                                  │
                                  ▼
                         Protected Tool Binding
                      ToolDescriptor + execution facts
                                  │
                                  ▼
                         RuntimeGateway / PEP
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
              Policy          Approval          Evidence
                 │                │                │
                 └────────────────┼────────────────┘
                                  ▼
                              Dispatcher
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
             callable           HTTP          process/code
                                                   │
                                                   ▼
                                            IsolationBackend
                                                   │
                                         ┌─────────┴─────────┐
                                         ▼                   ▼
                                      Docker             Docker+runsc
```

MCP remains a sibling adapter and should reuse the same shared binding/invocation primitives where doing so reduces duplicated security semantics.

---

## 6. Canonical adapter-facing models

Exact names may adapt to current code, but prefer a small number of explicit models over generic dictionaries.

### 6.1 `ExecutionBinding`

Recommended fields:

```text
ExecutionBinding
- schema_version
- adapter_kind            # stable identifier: native/http/process/openai_tools/...
- adapter_id              # protected configuration identity
- adapter_version         # implementation/version string
- binding_digest          # digest of security-relevant execution binding
- isolation_summary?      # safe facts only
```

`binding_digest` should cover the protected execution properties relevant to approval/evidence identity.

Do not include unstable timestamps.

Do not include bearer credentials, secret headers, full environment variables, request bodies, or raw process output.

### 6.2 `ProtectedTool`

Recommended semantics:

```text
ProtectedTool
- descriptor: ToolDescriptor
- execution_binding: ExecutionBinding
- resource extraction metadata
- approval display paths
- sink destination classification
- output label classification
- coverage state
```

This is operational/runtime configuration, not an authored contract grant.

### 6.3 Dispatcher port

Use one minimal async dispatcher shape, for example:

```python
class ToolDispatcher(Protocol):
    async def dispatch(
        self,
        tool: ProtectedTool,
        arguments: dict[str, JsonValue],
    ) -> ToolResponse: ...
```

or retain callables if that remains simpler.

The critical constraint is that adapters enter `RuntimeGateway` before dispatcher execution.

### 6.4 Isolation models

Recommended:

```text
ProcessRequest
- argv
- cwd?
- env
- stdin?
- timeout
- output_limit

ProcessResult
- exit_code
- stdout/stderr or bounded structured representation
- timed_out
- backend facts

IsolationBackend
- execute(ProcessRequest) -> ProcessResult
- describe() -> safe IsolationSummary
```

No shell string.

No implicit environment inheritance.

No raw secret-bearing environment in evidence.

---

## 7. Workstream 0 — Preflight and semantic inventory

Before refactoring:

1. establish a green post-Phase-6-review-fix baseline;
2. inventory every `RuntimeGateway.call(...)` caller;
3. inventory MCP-only coverage/resource extraction logic;
4. identify which logic is protocol-specific and which is generic;
5. inventory evidence/replay serialization assumptions that depend on current `NormalizedAction` or dispatch payloads;
6. confirm generated schema compatibility;
7. document any stale Phase 6 boundary text before Phase 7 begins.

Deliverable: a short implementation-report subsection recording what was generic versus MCP-specific.

---

## 8. Workstream 1 — Common protected dispatch/binding layer

### 8.1 Introduce the smallest useful common abstraction

Create a typed runtime-facing abstraction that bundles:

- canonical tool descriptor;
- execution binding;
- resource extraction;
- approval display paths;
- data destination;
- output labels;
- coverage status.

Prefer a module such as:

```text
src/agentsec/runtime/bindings.py
```

or another name consistent with the repository.

Do not create a dynamic plugin registry.

### 8.2 Extract generic resource lookup

MCP currently has exact object-key resource paths. If the same semantics are needed by native/provider/HTTP/process adapters:

- extract one exact-key traversal helper;
- preserve current null/missing/non-string behavior;
- do not introduce path/URL/email canonicalization;
- return stable explicit errors.

MCP should use the shared helper after extraction.

### 8.3 Extract shared binding coverage where real

Move only truly protocol-independent checks out of MCP, such as:

- capability/resource coverage needed by compiled rules;
- destination-classification coverage;
- output-label review coverage;
- approval-display path validity if common.

Keep MCP discovery pagination, request-ID semantics, upstream transport, and metadata discovery in MCP.

### 8.4 Bind execution route into exact actions

For Phase 7-protected dispatches, extend `NormalizedAction` additively with an execution-binding identity/digest.

Requirements:

- approvals bind to it;
- action digests bind to it;
- evidence can correlate it;
- old serialized actions/bundles remain readable;
- historical digests remain stable when the field is absent;
- no existing Phase 5/6 artifact is silently rehashed.

If MCP is migrated to the new field, do so deliberately and update compatibility tests. It is acceptable for existing historical MCP artifacts to omit it.

---

## 9. Workstream 2 — Native Python protected dispatch SDK

This is the foundational Phase 7 adapter.

### 9.1 Registration

Provide an API that lets application code register a Python callable with explicit protected metadata:

- stable tool ID;
- capability;
- JSON input/output schema;
- description;
- side-effect class;
- destructive flag;
- resource extraction path;
- destination/output labels;
- approval-display paths.

Do not infer security-critical capability/risk/authority from a Python function name.

### 9.2 Invocation

Provide async-first protected invocation:

```text
registered tool
  → argument schema validation
  → RuntimeGateway
  → callable dispatcher
  → ToolResponse
```

If a sync convenience API is added:

- do not hide event-loop misuse;
- keep the security path identical;
- avoid nested-loop hacks.

### 9.3 Return normalization

Define deterministic conversion from supported Python returns to `ToolResponse`.

Prefer a narrow supported set rather than `Any`.

Examples:

- explicit `ToolResponse`;
- JSON-compatible structured value with documented success semantics.

Reject unsupported return types explicitly.

### 9.4 Exceptions

Callable exceptions must become safe `RuntimeFailure`/upstream failure semantics.

Do not serialize raw exception messages into canonical evidence by default.

---

## 10. Workstream 3 — OpenAI/Anthropic/Gemini-style tool adapters

The goal is tool-call/harness compatibility, **not** model networking.

### 10.1 Scope

Implement strict translations for representative tool declaration and tool-call shapes:

- OpenAI-style function tools;
- Anthropic-style tools/tool-use blocks;
- Gemini-style function declarations/calls.

Use provider-neutral protected metadata for authorization.

### 10.2 Requirements

- strict tool-name lookup;
- duplicate/ambiguous names rejected;
- malformed JSON arguments rejected;
- unknown tool call rejected;
- provider call IDs treated only as correlation metadata;
- provider arguments never carry principal/delegation/trusted labels;
- JSON Schema normalized/validated before registration;
- remote `$ref` retrieval is not introduced;
- provider description/schema snapshot hashes are retained in the canonical descriptor;
- calls dispatch through the native protected registry/`RuntimeGateway`.

### 10.3 Dependency discipline

Prefer adapters over simple JSON-compatible provider shapes if this avoids three large SDK dependencies.

Only add a vendor SDK dependency if it materially improves correctness and the adapter is genuinely coupled to a stable typed SDK surface.

No API key or network access is required for default tests.

---

## 11. Workstream 4 — LangChain / LangGraph integration

### 11.1 Boundary

Integrate at the **tool execution boundary**, not by forking or reimplementing graph execution.

A reasonable Phase 7 shape is:

```text
LangChain BaseTool / StructuredTool
    ↓ wrapped once
AgentSec-protected tool
    ↓
RuntimeGateway
    ↓
original tool implementation
```

LangGraph can consume the wrapped tools through its normal tool-node path.

### 11.2 Requirements

- optional dependency extra if needed;
- snapshot name/description/schema at wrapping time;
- preserve async execution;
- no framework callback may bypass the protected dispatcher;
- no agent state field is trusted as identity or authority;
- framework config/metadata is not an authorization grant;
- tool errors map safely;
- wrappers remain local and testable without model API calls.

### 11.3 Do not overbuild

Do not add:

- graph checkpointing;
- LangSmith integration;
- model invocation wrappers;
- arbitrary callback interception;
- global monkeypatching.

One clear protected-tool integration is sufficient.

---

## 12. Workstream 5 — Protected HTTP action adapter

HTTP is a high-risk boundary. Avoid a generic forward proxy.

### 12.1 Trusted endpoint configuration

The protected config should define the destination, for example:

```text
method
base_url / origin
relative path template
timeout
headers from protected config
response size limit
destination category
```

Agent arguments may fill documented body/query/path fields, but must not silently replace:

- scheme;
- host;
- port;
- credentials;
- proxy settings;
- trusted destination category.

### 12.2 Security requirements

- disable redirects by default;
- no automatic retries;
- no proxy/environment credential inheritance (`trust_env=False` or equivalent);
- reject URL userinfo/fragments;
- bounded request/response sizes;
- explicit timeout;
- safe header handling;
- never persist authorization headers/raw secrets in evidence;
- local tests use a synthetic local server only;
- no external network requirement.

If redirect support is added, every redirect target must be revalidated as a new protected destination. The simpler Phase 7 choice is to reject/disable redirects.

### 12.3 Data-flow integration

Map protected HTTP destination configuration to existing data-flow sink classification.

Do not let the model label a destination as trusted.

Returned body/artifacts should inherit untrusted tool-output semantics unless explicitly and safely classified.

### 12.4 Resource semantics

If path/query/body fields form the policy resource:

- extraction must be deterministic;
- exact opaque resource semantics only;
- no hidden URL normalization claim;
- encode/construct transport safely after authorization;
- ensure the resource bound into approval is the same semantic value used to build the request.

---

## 13. Workstream 6 — Process/coding-action adapter

### 13.1 Execution model

Never invoke an untrusted shell string.

Use:

```text
executable + argv[]
```

with `shell=False` or platform-equivalent semantics.

Protected config owns:

- executable/template;
- allowed argument slots;
- cwd;
- explicit environment;
- timeout;
- output bound;
- isolation backend.

### 13.2 Environment discipline

Match or exceed the MCP stdio posture:

- do not inherit arbitrary parent environment;
- pass only explicitly configured values plus a documented minimal safe baseline if required;
- reject invalid names/NUL;
- never expose secrets in approval/evidence;
- avoid PATH-based ambiguity where practical by resolving/pinning executables from protected config.

### 13.3 Coding-agent meaning in Phase 7

“Coding-agent actions” means the security layer can protect structured process/code execution requested by a coding harness.

It does **not** mean implementing a coding agent, shell planner, patch engine, repository agent, or terminal protocol.

### 13.4 Output

Capture output with hard bounds.

Return:

- success/exit status;
- structured exit metadata;
- bounded response body/hash;
- untrusted output labels.

Timeout/cancellation must not cause a second dispatch.

---

## 14. Workstream 7 — Isolation integration

### 14.1 Isolation port

Define the interface needed by the real process adapter.

The interface should be:

- async;
- typed;
- explicit about timeout/cancellation;
- able to return safe backend facts;
- independent of policy core;
- usable by tests with a deterministic fake.

### 14.2 Docker backend

Implement a Docker CLI or mature-library-backed execution path.

Secure defaults should include where supported:

- no network by default;
- read-only root filesystem where compatible;
- drop capabilities;
- no-new-privileges;
- bounded memory;
- bounded CPU;
- bounded PIDs;
- bounded wall-clock time;
- explicit mounts;
- mounts read-only by default;
- explicit environment only;
- no Docker socket mount;
- no privileged mode;
- no host PID/network namespace;
- bounded stdout/stderr;
- one container/process execution per invocation unless a deliberate reusable lifecycle is designed and justified.

Do not claim Docker is an impenetrable sandbox.

### 14.3 gVisor composition

Allow protected Docker runtime selection, e.g. `runsc`, without changing policy semantics.

Record safe runtime/backend identity in the execution-binding digest/evidence.

Tests should validate command construction and failure behavior without requiring gVisor on CI.

### 14.4 No unsafe fallback

If the configured Docker/gVisor path cannot start:

```text
configured isolated execution
    ≠
silent host execution
```

Fail with a stable code.

### 14.5 WASM/microVM boundary

Do not implement these backends in Phase 7.

Document that the new isolation port is the intended composition point and that a future backend must preserve:

- exact action binding;
- no policy bypass;
- explicit backend identity;
- safe evidence;
- no hidden privilege expansion.

---

## 15. Workstream 8 — MCP convergence without regression

Phase 7 is not complete if every new adapter uses common primitives but MCP remains a semantically divergent implementation where the divergence is unnecessary.

Refactor MCP only where safe:

- use shared resource extraction;
- use shared protected binding object;
- use shared execution-binding identity if introduced;
- use shared adapter coverage checks where identical.

Do **not** destabilize:

- MCP discovery/pagination;
- JSON-RPC request-ID handling;
- stdout/stderr ownership;
- upstream transport behavior;
- pinning;
- schema safety;
- SHADOW truthfulness;
- existing stdio/HTTP handling.

Run existing MCP-focused tests after each convergence step.

---

## 16. Workstream 9 — Evidence, replay, regression, and conformance

### 16.1 Evidence

Add safe execution-route facts.

Evidence must answer:

- which adapter path was selected;
- which protected binding was used;
- whether isolation was configured/used;
- which safe backend/profile identity applied.

Evidence must **not** include by default:

- HTTP authorization headers;
- bearer/API keys;
- full URLs containing secrets;
- raw request bodies;
- raw process environment;
- unbounded stdout/stderr;
- Docker credentials;
- provider API credentials.

### 16.2 Mode truthfulness

Preserve the existing distinction:

- ENFORCE = policy actively blocks;
- SHADOW = records decision but does not block on policy;
- DISABLED = no policy decision.

Isolation configuration has its own truth and must not be mislabeled because policy is SHADOW/DISABLED.

### 16.3 Replay

Replay remains offline.

Phase 7 replay must not:

- call HTTP;
- execute Python functions;
- launch processes/containers;
- invoke LangChain;
- contact model providers.

Additive execution-binding evidence may be compared, but historical Phase 5/6 artifacts must not become unreadable merely because they lack Phase 7 adapter fields.

If a replay claim specifically depends on Phase 7 execution/isolation facts that are absent, report an explicit incomplete/unknown result rather than inventing them.

### 16.4 Regression

Incident promotion must not embed protected adapter secrets.

Safe adapter identity/digests may be promoted if they contain no sensitive operational material.

### 16.5 Conformance

Add deterministic adapter conformance coverage for the shared protected-dispatch semantics, such as:

- DENY never reaches dispatcher;
- REQUIRE_APPROVAL binds exact execution route;
- expired authority after approval never reaches dispatcher;
- budget failure never reaches dispatcher;
- data-flow denial never reaches dispatcher;
- one adapter cannot substitute another under the same approval;
- isolation startup failure never falls back to host execution.

Do not claim these synthetic tests prove provider/model robustness or container escape resistance.

---

## 17. Workstream 10 — CLI, examples, and documentation

### 17.1 Library-first

Phase 7 should primarily expose reusable Python APIs.

Do not force every adapter into a CLI subcommand if that adds little value.

### 17.2 Useful CLI additions

Reasonable additions include an offline adapter/config validation command if there is a concrete shared config artifact.

Any check command must:

- perform no live external dispatch;
- not read model/provider API keys;
- distinguish static validation from live enforcement.

### 17.3 Examples

Add small, deterministic examples for:

1. native Python callable protected by an ALLOW/DENY contract;
2. provider-shaped tool call normalized and blocked/allowed without model API access;
3. LangChain tool wrapping if optional dependency is installed;
4. HTTP adapter against a local synthetic server;
5. process adapter with deterministic fake isolation and/or Docker command construction;
6. Docker/gVisor configuration documentation without requiring gVisor in default tests.

Examples must not perform real external side effects.

### 17.4 Documentation

Create a focused Phase 7 doc, recommended:

```text
docs/adapters-isolation.md
```

Update as needed:

- `README.md`;
- `AGENTS.md`;
- `docs/README.md`;
- `docs/architecture.md`;
- `docs/runtime-mcp.md`;
- `docs/evidence-model.md`;
- `docs/replay-incidents.md`;
- `docs/contract-conformance.md`;
- `docs/reports/README.md`;
- optional dependency/install docs.

Do not rewrite the PRD merely to match implementation shortcuts.

---

## 18. Security invariants

Phase 7 must add tests for these invariants.

### 18.1 No adapter bypass

Every privileged adapter dispatch in ENFORCE goes through the same protected runtime boundary.

There must be no public convenience method that calls the underlying function/HTTP/process executor while being presented as protected.

### 18.2 No metadata-derived authority

Provider/framework metadata never grants capability, principal, delegation, trusted destination, or approval exemption.

### 18.3 Exact execution-route approval binding

An approval for:

```text
tool X + args Y + HTTP binding A
```

cannot authorize:

```text
tool X + args Y + process binding B
```

or a changed isolation profile.

### 18.4 No policy widening

Adapter config may narrow/prove execution coverage; it must not turn DENY/default-deny into ALLOW.

### 18.5 No user-controlled trust root

Arguments cannot choose:

- principal;
- delegation;
- adapter identity;
- trusted destination classification;
- protected headers;
- isolation backend;
- Docker runtime;
- host mounts;
- capability.

### 18.6 No secret leakage

Secrets must not appear in:

- action summaries;
- canonical evidence;
- exception text intentionally exposed to agents;
- replay/regression material;
- generated examples/tests.

### 18.7 No unsafe isolation fallback

Failure to create configured isolation fails safely.

### 18.8 No hidden retries

HTTP/process/provider wrappers must not create a second privileged effect after an ambiguous first attempt unless a future explicit retry/idempotency design exists.

### 18.9 Cancellation preserves uncertainty

If cancellation occurs after dispatcher entry and the side effect may have happened, record the uncertainty and do not retry automatically.

### 18.10 Core remains framework-independent

`domain/`, compiler, and policy core must not import:

- MCP;
- OpenAI;
- Anthropic;
- Gemini;
- LangChain/LangGraph;
- httpx;
- Docker SDK.

Framework dependencies live in adapters.

---

## 19. Error semantics

Add stable, safe errors where needed.

Recommended categories/codes include:

```text
UNKNOWN_ADAPTER_TOOL
INVALID_ADAPTER_ARGUMENTS
ADAPTER_SCHEMA_MISMATCH
ADAPTER_BINDING_MISMATCH
EXECUTION_BINDING_CHANGED
HTTP_DESTINATION_INVALID
HTTP_REDIRECT_BLOCKED
HTTP_RESPONSE_TOO_LARGE
PROCESS_CONFIG_INVALID
PROCESS_TIMEOUT
PROCESS_OUTPUT_TOO_LARGE
ISOLATION_REQUIRED
ISOLATION_UNAVAILABLE
ISOLATION_START_FAILED
```

Exact names should fit existing conventions.

Do not surface raw upstream exception strings as security decisions.

---

## 20. Compatibility and versioning

### 20.1 Existing contracts

Existing Phase 0–6 contracts should continue to load without migration if Phase 7 adds no contract semantics.

### 20.2 Existing compiler identity

Keep `phase6-v1` if compiled policy semantics are unchanged.

A Phase 7 feature name is not itself a reason to bump the compiler version.

### 20.3 Existing evidence/replay

New fields must be additive with safe defaults/absence handling.

Golden historical bundles must retain their canonical identities.

### 20.4 Existing MCP behavior

MCP behavior is a regression surface, not a disposable prototype.

Phase 7 must preserve existing MCP guarantees unless a deliberate, documented bug fix tightens them.

---

## 21. Dependency strategy

Core remains small.

Reasonable optional extras:

```text
http        # e.g. httpx
langchain   # langchain-core and/or langgraph only if required
docker      # only if a library is chosen instead of CLI
```

Prefer:

- standard library subprocess for Docker CLI if sufficient;
- provider JSON-shape adapters over mandatory provider SDKs;
- optional framework dependencies;
- no external service in default tests.

Every new dependency must have:

- a concrete correctness/interoperability benefit;
- bounded version range;
- no mandatory network behavior;
- no secret requirement for core tests.

---

## 22. Testing strategy

Testing should be security-focused and proportionate, not combinatorial for its own sake.

### 22.1 Unit tests

Cover:

- strict adapter/binding parsing;
- execution-binding digest stability;
- action digest changes when adapter/isolation binding changes;
- resource extraction;
- provider call normalization;
- malformed/unknown provider calls;
- native callable return/error normalization;
- HTTP URL/config validation;
- no redirects/retries/env proxy inheritance;
- process argv construction;
- env/cwd validation;
- isolation config validation;
- Docker command construction;
- no unsafe fallback;
- additive serialization compatibility.

### 22.2 Integration tests

Use only local deterministic fixtures:

- native callable;
- provider-shaped call → protected native callable;
- LangChain wrapped local tool;
- local HTTP server;
- synthetic process;
- fake isolation backend;
- optional Docker smoke test only if explicitly gated by availability.

### 22.3 Cross-adapter conformance matrix

At minimum prove shared semantics across two or more non-MCP adapters:

| Scenario | Native | HTTP | Process | Expected |
| --- | --- | --- | --- | --- |
| explicit ALLOW | yes | yes | yes | dispatch once |
| explicit DENY | yes | yes | yes | no dispatch |
| REQUIRE_APPROVAL | yes | yes | yes | exact approval |
| expired authority | yes | yes | yes | no dispatch |
| budget exhausted | yes | yes | yes | no dispatch |
| changed execution binding | yes | yes | yes | approval mismatch/no dispatch |
| data-flow deny where applicable | — | yes | yes | no dispatch |

Do not multiply every existing policy test across every adapter if a shared-core test already proves the semantics.

### 22.4 Full regression gates

Run the repository’s standard full suite after focused tests.

---

## 23. Acceptance criteria

Phase 7 is complete only when all of the following are true:

1. At least three non-MCP action surfaces use the same `RuntimeGateway` security path.
2. Native Python protected dispatch works without external services.
3. OpenAI-/Anthropic-/Gemini-style tool calls can be normalized and protected without model API access.
4. LangChain/LangGraph can use AgentSec-protected tools through a narrow integration.
5. HTTP actions cannot escape the protected configured destination through arbitrary user-controlled URLs or redirects.
6. Process execution uses argv, not implicit shell interpolation.
7. Process/code execution can run through a real Docker isolation backend.
8. Docker runtime selection can compose with gVisor/runsc configuration.
9. Isolation failure does not silently fall back to host execution.
10. Approval/action identity binds the execution route for Phase 7 adapters.
11. Existing MCP security behavior remains green.
12. Existing Phase 5/6 replay artifacts remain readable.
13. Replay never performs live Phase 7 side effects.
14. Evidence does not leak provider keys, HTTP auth headers, process env secrets, or raw protected configuration.
15. Current documentation no longer says Phase 6 is the active implementation phase.
16. Phase 8 supply-chain and Phase 9 multi-agent semantics remain unimplemented.
17. Full tests/lint/format/type-check/build/regression gates pass.

---

## 24. Verification commands

Adapt to the repository’s actual environment, but the final implementation report should include exact commands and results for at least:

```bash
pytest -q <focused Phase 7 tests>
pytest -q <MCP/runtime/identity/replay compatibility tests>
pytest -q
ruff check .
ruff format --check .
mypy src
agentsec examples validate
agentsec eval examples
agentsec schema export --out schemas/generated
agentsec regression run --root examples/regressions
python -m build --no-isolation
git diff --check
```

If optional LangChain/http/Docker extras are added, include an install/verification command that does not require external credentials.

Docker/gVisor availability must not be mandatory for the default unit suite.

---

## 25. Mandatory implementation self-review

Before declaring Phase 7 complete, inspect specifically for:

- any adapter method that can bypass `RuntimeGateway`;
- provider/framework metadata accidentally becoming authorization;
- action-digest omissions that allow execution-route substitution;
- changed isolation config not invalidating approval identity;
- HTTP host/scheme/port override through arguments;
- HTTP redirect or proxy-env escape;
- secret header leakage;
- double dispatch/retry after ambiguous failure;
- process shell interpolation;
- environment inheritance;
- attacker-controlled cwd/executable/backend;
- Docker privileged mode/host namespaces/socket mounts;
- silent isolation fallback;
- cancellation ambiguity;
- evidence-mode mislabeling;
- historical replay breakage;
- duplicate policy semantics in adapters;
- MCP regressions;
- accidental Phase 8 tool-trust or Phase 9 delegation work.

Record this self-review in the implementation report. It is not a substitute for independent review.

---

## 26. Required implementation report

Create:

```text
docs/reports/phase-7-implementation-report.md
```

Include:

1. baseline commit and preflight results;
2. current-state reconciliation;
3. architecture changes;
4. common adapter/binding layer;
5. native Python adapter;
6. provider-shaped adapters;
7. LangChain/LangGraph integration;
8. HTTP adapter;
9. process/coding adapter;
10. isolation backend and Docker/gVisor composition;
11. MCP convergence/regression notes;
12. evidence/replay/regression/conformance changes;
13. schema/version/hash compatibility;
14. dependencies;
15. exact verification commands/results;
16. security self-review;
17. deliberate deviations;
18. known limitations;
19. independent-review readiness;
20. Phase 8 boundary/readiness.

---

## 27. Known limitations that should remain explicit

Even after Phase 7:

- policy cannot prove a callable/tool implementation is benign;
- metadata hashes are not signatures;
- Docker is not a formal security boundary against all hostile kernels/runtime exploits;
- gVisor availability/configuration is external;
- no WASM/microVM backend is implemented;
- HTTP DNS/network infrastructure can still be compromised outside AgentSec’s model;
- no full semantic secret classifier exists;
- framework wrappers cannot protect side effects that bypass the wrapped tool boundary;
- direct raw network/process access by the host agent outside AgentSec remains outside the adapter’s control;
- no hosted identity/approval/control plane exists;
- no Phase 8 supply-chain attestation exists;
- no Phase 9 transitive multi-agent authority exists.

Do not overclaim protection beyond the action boundaries actually wrapped.

---

## 28. Phase 7 exit statement

Phase 7 succeeds when AgentSec is no longer “an MCP gateway with a generic-looking core.”

It should be demonstrably true that:

> **Different agent frameworks and action transports normalize into one security boundary, receive the same policy/identity/approval/data-flow treatment, emit the same evidence semantics, and can compose with explicit execution isolation without trusting the model or harness to enforce those rules.**

That is the foundation required before Phase 8 makes tool/server identity and supply-chain trust materially stronger.
