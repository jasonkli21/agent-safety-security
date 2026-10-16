# Agent Safety & Security Platform — Phase 3 Detailed Implementation Plan

**Phase:** 3 — Unified Contract: Policy → Evaluation → Runtime\
**Status:** Implementation-ready plan\
**Repository:** `jasonkli21/agent-safety-security`\
**Repository baseline inspected:** `eb29db96b8c1f0204ed0b31d7a04daec280a40f4` (`fix: address phase 2 independent review findings`)\
**Depends on:** Phase 0 canonical security model; Phase 1 deterministic evaluation lab; Phase 2 MCP runtime gateway and its independent-review fixes\
**Primary goal:** make the Agent Security Contract the single executable source of truth for the Phase 2-supported security semantics, then prove that the same compiled meaning is used by offline conformance tests, generated evaluation cases, runtime authorization, coverage reporting, and policy-change analysis.

---

## 1. Current repository baseline

The current `main` branch already has three important pieces that Phase 3 must unify rather than replace:

1. **Phase 0 — canonical intent and evidence model**
   - strict `AgentSecurityContract` and related Pydantic domain artifacts;
   - canonical serialization and `effective_policy_hash`;
   - typed policy request/decision, approvals, normalized action, security events, taxonomies, reason codes, and schemas.

2. **Phase 1 — deterministic evaluation**
   - scenario DSL and strict fixture format;
   - `AgentTarget` / evaluation observation boundary;
   - causal event validation and non-vacuous assertions;
   - security/utility results, findings, reports, JSONL evidence, and CI-oriented exit codes;
   - deliberate separation from production authorization: Phase 1 fixtures currently script observed policy outcomes rather than executing contract policy.

3. **Phase 2 — real MCP enforcement**
   - protocol-independent `NativePolicyEngine` implementing exact-match supported contract semantics;
   - conservative policy/runtime coverage analysis;
   - explicit MCP discovery/bindings and binding-aware coverage;
   - runtime gateway with fail-closed ENFORCE behavior, SHADOW/DISABLED truthfulness, exact approvals, supported budgets, response validation, and canonical evidence;
   - Phase 2 independent-review fixes for resource coverage, resource semantics, redaction/input fingerprints, sink poisoning, explicit binding proof, approval presentation, request-ID reuse, and cancellation/unknown-effect behavior.

The Phase 2 implementation report records a passing full suite of 451 tests after review remediation. Phase 3 should not chase or preserve that count as a quality target; it should preserve the behavior that those tests protect.

### 1.1 Baseline caveat

This plan is written against `eb29db9`. Before implementation starts, inspect the then-current `main`, the Phase 2 implementation report, any later review/fix report, and `AGENTS.md`. If the repository has advanced, reconcile names and assumptions before coding. Do not force this document's exact filenames over a better current structure.

The user has explicitly requested Phase 3 work, so Phase 3 may proceed from the latest reviewed/fixed Phase 2 state. Do not fabricate a review attestation that is not present in the repository.

---

## 2. Phase 3 objective

Phase 3 is the first major closed-loop differentiation milestone from the PRD:

> **One contract should have one executable meaning, and that meaning should be shared by runtime enforcement, generated security tests, coverage reporting, and policy-change analysis.**

Today, the pieces are aligned conceptually but not yet structurally:

```text
Agent Security Contract
      │
      ├─────────────► Phase 2 NativePolicyEngine reads contract directly
      │
      └─────────────► Phase 1 scenarios/fixtures independently script expected observations
```

Phase 3 should move to:

```text
Agent Security Contract
      │
      ▼
Contract Compiler
      │
      ▼
Immutable Compiled Security Plan
      │
      ├────────► Runtime policy engine / MCP gateway
      ├────────► Deterministic policy conformance probes
      ├────────► Contract-derived evaluation cases
      ├────────► Coverage report
      └────────► Old-vs-new semantic policy diff
```

The central Phase 3 invariant is:

> **For every security semantic Phase 3 claims to support, offline verification and runtime authorization must consume the same compiled representation; unsupported or untestable semantics must remain explicit coverage gaps rather than being silently approximated.**

A second invariant is equally important:

> **The project must not “prove equivalence” by merely invoking the same function twice or deriving expected results from the exact decision result under test. Generated tests need independently stated obligations derived from contract intent.**

---

## 3. What Phase 3 means by “compile”

Phase 3 does **not** need a general policy language, a bytecode VM, Cedar/OPA, or a framework-specific code generator.

“Compilation” means producing a deterministic, typed, immutable representation of the supported security intent after validation and normalization. The compiled representation should:

- freeze the exact contract identity/hash being executed;
- normalize supported tool rules and precedence inputs;
- normalize the task-scope ceiling;
- identify supported runtime budgets and approval parameters;
- retain source provenance back to contract fields/rule IDs;
- explicitly enumerate unsupported semantics and semantics requiring adapter-specific proof;
- be consumable without reparsing or reinterpreting the original contract on every request;
- be serializable to a stable human/machine-readable manifest if that materially improves inspection and testing.

It must **not** erase the distinction between:

- protocol-independent policy semantics;
- adapter-specific enforceability/coverage;
- runtime mutable state such as remaining budget or approval redemption;
- evaluation assertions;
- future Phase 4 provenance/data-flow semantics.

---

## 4. Scope boundaries

### 4.1 In scope

Phase 3 should implement:

- a deterministic contract compiler for the policy semantics currently supported by Phase 2;
- a typed immutable compiled-policy/compiled-contract intermediate representation (IR);
- provenance from compiled elements to contract rule IDs/field paths;
- explicit compile-time coverage inventory, including unsupported intent;
- refactoring the native runtime policy path to consume the compiled IR rather than independently interpreting the raw contract;
- runtime startup proof that the compiled plan matches the loaded contract/effective policy hash;
- deterministic contract-derived **policy probes** for DENY, REQUIRE_APPROVAL, ALLOW/precedence, task-scope ceilings, exact resource rules, and default-deny behavior;
- a small bridge from generated obligations into the existing Phase 1 evaluation machinery so eval and runtime exercise the same contract meaning;
- generated approval tests that are non-vacuous;
- contract/test/runtime coverage reporting at semantic-atom granularity;
- a deterministic old-contract vs new-contract semantic diff/simulation for the currently supported exact-match policy space;
- classification of material policy changes such as authority expansion, authority reduction, approval-boundary change, task-scope widening/narrowing, and supported budget/approval-setting changes;
- CLI commands sufficient to inspect compilation, run contract conformance tests, inspect coverage, and compare contract revisions;
- focused integration tests showing the same compiled plan produces the expected direct-policy, eval, and MCP-runtime outcomes;
- schema/docs/examples/report updates required by new public artifacts;
- a Phase 3 implementation report.

### 4.2 Explicitly out of scope

Do **not** pull later phases forward. Phase 3 must not implement:

- Phase 4 provenance graph, taint propagation, memory-write security, or general `DataRule` enforcement;
- secret/PII classifiers, prompt-injection classifiers, or semantic content moderation;
- incident/replay bundles or “promote incident to regression” workflows from Phase 5;
- OAuth/OIDC, workload identity, signed capability tokens, or delegation-chain enforcement from Phase 6;
- generic non-MCP runtime adapters from Phase 7;
- supply-chain scoring/signatures/trust registry from Phase 8;
- multi-agent delegation graphs from Phase 9;
- hosted control plane, team review workflow, or remote policy registry;
- model-generated attacks or LLM judges;
- a generic theorem prover or claim of formal verification;
- automatic synthesis of valid real-world tool arguments from arbitrary JSON Schema;
- automatic inference of tool capabilities/resources from names or descriptions;
- automatic activation/deployment of a changed policy.

Phase 3 may report future semantics as uncovered. It must not approximate them merely to improve a coverage percentage.

---

## 5. Design principles

### 5.1 One policy semantic implementation

Runtime and conformance testing should not each contain their own rule-matching implementation.

The compiler owns normalization. The native policy evaluator owns request evaluation over compiled intent. The evaluation bridge consumes explicit generated obligations and the same compiled evaluator.

### 5.2 Coverage is a claim, not a vanity metric

A field being present in the contract does not mean it is:

- compiled;
- runtime-enforceable;
- adapter-covered;
- automatically testable;
- actually exercised by a generated test.

Those dimensions must be reported separately.

### 5.3 Expected outcomes must not be circular

Bad Phase 3 design:

```text
expected = engine.decide(request)
actual   = engine.decide(request)
assert expected == actual
```

Likewise, a generated eval fixture that copies a runtime `PolicyDecision` back into the fixture does not test semantics.

Generated obligations should be derived from declarative contract facts and documented precedence rules, then executed through the policy/runtime path.

### 5.4 Adapter proof stays adapter-specific

The protocol-independent compiler can state “this rule requires an exact resource.” Only the MCP adapter can prove that every applicable discovered tool has a safe extraction path and acceptable resource semantics.

Do not move MCP discovery/binding details into the core compiler.

### 5.5 Synthetic evaluation is not production robustness

Contract-derived scenarios prove policy/eval semantic conformance. They do **not** prove that a frontier model resists prompt injection or that a real tool server is honest.

Reports/docs must keep that boundary explicit.

---

## 6. Proposed package layout

Exact filenames can change after repository inspection, but preserve the ownership boundaries.

```text
src/agentsec/
├── compiler/
│   ├── __init__.py
│   ├── models.py              # immutable compiled IR + source refs
│   ├── compile.py             # AgentSecurityContract -> CompiledSecurityPlan
│   ├── coverage.py            # semantic-atom coverage inventory/report projection
│   ├── probes.py              # deterministic contract-derived policy obligations
│   └── diff.py                # finite symbolic old-vs-new semantic comparison
├── policy/
│   ├── native.py              # evaluate PolicyRequest against compiled policy
│   ├── coverage.py            # narrow compatibility wrapper or retire if compiler owns it
│   └── ports.py
├── eval/
│   ├── ...
│   └── contract_cases.py      # bridge generated obligations to existing eval machinery
├── runtime/
│   └── gateway.py             # accept/use compiled plan; runtime mutable state remains here
├── adapters/mcp/
│   └── coverage.py            # compose compiled requirements with discovery/binding proof
└── cli/
    ├── contract.py            # compile/test/coverage/diff commands, or equivalent grouping
    └── ...
```

Do not create a large new abstraction forest if existing modules can host a piece cleanly. The important boundary is:

```text
raw contract ─► compiler ─► compiled immutable intent
                              │
                              ├─► protocol-independent policy evaluation
                              ├─► test obligation generation
                              └─► semantic diff/coverage

MCP discovery/bindings ───────► adapter-specific coverage proof
runtime counters/approvals ───► runtime state, not compiled intent
```

---

## 7. Compiled Security Plan

### 7.1 Suggested top-level type

A conceptual shape:

```text
CompiledSecurityPlan
- schema_version
- compiler_version
- contract_id
- contract_schema_version
- effective_policy_hash
- agent
- principal
- environment
- tool_policy
- task_scope?
- supported_budgets
- approval_policy
- semantic_atoms[]
- compile_gaps[]
```

Prefer frozen/immutable dataclasses or frozen Pydantic models where practical. Avoid storing the entire raw contract inside the compiled plan as a shortcut that lets downstream code keep interpreting it independently.

### 7.2 Tool policy IR

Represent enough information to preserve current exact-match semantics exactly:

```text
CompiledToolRule
- rule_id
- capability
- resource?              # exact opaque value
- decision               # ALLOW | DENY | REQUIRE_APPROVAL
- source_ref             # e.g. tools.rules[rule_id]
```

The evaluator still applies:

```text
DENY > REQUIRE_APPROVAL > ALLOW > DEFAULT_DENY
```

All matching rule IDs remain available for evidence/explanation.

Do not pre-flatten the rule set in a way that loses overlap/precedence provenance unless equivalence is proved and source rule IDs remain reconstructable.

### 7.3 Task-scope IR

Preserve task scope as a **ceiling**, never a grant:

```text
CompiledTaskScope
- task_id
- requested_capabilities?   # exact allowed ceiling
- resource_scopes?          # exact allowed resources by capability
```

If the Phase 2 runtime requires request task scope to equal the protected contract scope, keep that consistency rule explicit.

### 7.4 Budgets

The compiled plan can identify configured values and support status, but mutable counters remain runtime-owned.

Supported Phase 2 budget semantics:

- `max_tool_calls`;
- `max_external_writes`;
- `max_destructive_calls`;
- `max_runtime_seconds`.

Unsupported configured budget semantics remain explicit compile/runtime gaps:

- `max_model_calls`;
- `max_cost_usd`;
- `max_delegated_agents`.

Do not simulate runtime counters inside the pure policy evaluator.

### 7.5 Approval configuration

Compile the deterministic contract-controlled approval parameters used by runtime, especially default timeout. Approval redemption/state remains runtime-owned.

A tool rule with `REQUIRE_APPROVAL` should produce a generated obligation that requires the policy outcome to be REQUIRE_APPROVAL and, in integration coverage, requires actual dispatch to remain impossible without a matching one-shot approval.

### 7.6 Unsupported intent

At minimum retain current unsupported categories as explicit gaps:

- `data.rules`;
- prose `invariants`;
- `identity.acts_on_behalf_of`;
- unsupported budgets above;
- any delegation semantics not supported by Phase 2.

A future phase can change a gap to supported. Phase 3 must not hide it.

---

## 8. Semantic atoms and coverage model

Coverage should be based on discrete contract semantics, not raw line count or fields present.

### 8.1 Semantic atom

Introduce a deterministic internal/public representation such as:

```text
SemanticAtom
- atom_id                 # deterministic, stable within canonical contract meaning
- kind
- source_ref
- rule_id?
- capability?
- resource?
- configured_value?
```

Candidate atom kinds:

- IDENTITY_PRINCIPAL
- AGENT_ID
- ENVIRONMENT
- TOOL_RULE_ALLOW
- TOOL_RULE_DENY
- TOOL_RULE_REQUIRE_APPROVAL
- TASK_CAPABILITY_CEILING
- TASK_RESOURCE_CEILING
- BUDGET_MAX_TOOL_CALLS
- BUDGET_MAX_EXTERNAL_WRITES
- BUDGET_MAX_DESTRUCTIVE_CALLS
- BUDGET_MAX_RUNTIME_SECONDS
- APPROVAL_TIMEOUT
- DATA_RULE_UNSUPPORTED
- INVARIANT_UNSUPPORTED
- ACTS_ON_BEHALF_OF_UNSUPPORTED
- UNSUPPORTED_BUDGET

Do not expose more kinds than can be kept stable and meaningful.

### 8.2 Coverage dimensions

For each atom, report separate statuses rather than one ambiguous “covered” boolean:

```text
compile_status      = COMPILED | UNSUPPORTED
runtime_status      = SUPPORTED | REQUIRES_ADAPTER_PROOF | UNSUPPORTED
adapter_status      = COVERED | GAP | NOT_APPLICABLE | UNKNOWN
probe_status        = GENERATED | NOT_DERIVABLE | UNSUPPORTED
scenario_status     = GENERATED | NOT_DERIVABLE | UNSUPPORTED
exercise_status     = PASSED | FAILED | NOT_RUN
```

You may simplify exact enum names, but preserve the distinction.

### 8.3 Coverage aggregation

If counts/ratios are reported, the denominator must be explicit. Recommended summary:

```text
semantic atoms: 14
compiled: 11
runtime-supported before adapter proof: 10
adapter-covered: 9
policy probes generated: 8
contract-derived eval cases generated: 6
unsupported: 3
```

A ratio such as `8/11` is acceptable only with a label like “generated-policy-probe coverage of compiled atoms.” Do not output a generic “80% secure.”

### 8.4 Adapter composition

The MCP adapter should compose the compiled requirement inventory with its existing discovery/binding coverage. Examples:

- exact resource rule → requires extraction on every applicable bound discovered tool;
- stricter resource DENY/REQUIRE_APPROVAL under broad ALLOW → requires `opaque_exact` assertion;
- configured metadata pins → adapter-specific integrity check;
- missing binding/discovery tool → adapter coverage gap.

The core compiler should not know MCP tool names or `resource_argument_path`.

---

## 9. Refactor runtime policy to compiled intent

### 9.1 Native policy engine API

Move the real decision path from:

```python
engine.decide(request, contract)
```

conceptually toward:

```python
engine.decide(request, compiled_plan)
```

A compatibility wrapper may temporarily accept a contract and compile it, but the MCP gateway and Phase 3 verification path must explicitly compile once and reuse the plan. Do not leave production runtime reading raw rules while tests use the compiled IR.

### 9.2 Preserve Phase 2 semantics exactly

The refactor must preserve:

- principal/agent/environment consistency checks;
- exact task-scope equality/ceiling behavior;
- no delegation support unless explicitly added and covered;
- exact capability/resource match;
- rule precedence;
- deterministic matched rule IDs/reason codes;
- default deny;
- same effective policy hash in decisions;
- runtime budget/approval behavior outside the pure engine;
- fail-closed behavior for policy exceptions/malformed results;
- Phase 2 adapter coverage behavior and review fixes.

Phase 3 is not permission to relax Phase 2 boundaries to make compilation easier.

### 9.3 Stale-plan protection

Runtime setup must prove the plan corresponds to the loaded contract/configuration used for enforcement.

At minimum:

- plan carries `contract_id` and `effective_policy_hash`;
- runtime checks expected contract/policy identity before serving;
- evidence decisions continue to reference the same effective policy hash;
- a stale/mismatched plan cannot be silently used under a different contract.

Do not add hot-reload in Phase 3 unless it is already trivial and rigorously safe. A restart/new session is preferable.

---

## 10. Deterministic policy probes

Policy probes are the smallest non-circular unit of contract-derived verification.

### 10.1 Probe model

Conceptually:

```text
PolicyProbe
- probe_id
- source_atom_ids[]
- request_template
- expected_outcome
- expected_reason_codes
- expected_matched_rule_ids?   # when exact and stable
- rationale_code
```

Use deterministic IDs based on canonical source semantics, not UUID4.

### 10.2 Required probe families

Generate focused probes for current supported semantics:

1. **Explicit DENY**
   - request exact capability/resource targeted by the rule;
   - expect DENY and explicit-deny precedence.

2. **REQUIRE_APPROVAL**
   - request exact capability/resource targeted by the rule;
   - expect REQUIRE_APPROVAL, not ALLOW or DENY;
   - later integration path must prove no dispatch without a valid approval.

3. **ALLOW under default deny**
   - request exact allowed capability/resource;
   - expect ALLOW only if not overridden by a matching deny/approval rule or task ceiling.

4. **Precedence overlaps**
   - when contract structure creates overlapping general/resource rules, generate a request in the overlap and derive the obligation from documented precedence.

5. **Task capability ceiling**
   - for capabilities referenced by rules but excluded from requested scope, expect OUTSIDE_TASK_SCOPE.

6. **Task resource ceiling**
   - exercise exact in-scope and referenced out-of-scope resources where finite values are available from the contract.

7. **Default deny sentinel**
   - generate one reserved capability guaranteed not to collide with declared capabilities after validation, or deterministically derive a collision-free sentinel;
   - expect DEFAULT_DENY;
   - keep this at the policy-conformance level, not as a claim that a real adapter exposes such a tool.

8. **Identity/environment mismatch probes**
   - a very small set can verify INVALID_REQUEST behavior, but avoid generating combinatorial mutations.

### 10.3 Probe expectation derivation

Expected values should be derived from contract facts + a small explicit precedence/oracle layer, not by invoking `NativePolicyEngine.decide()` and copying the result.

The oracle should be intentionally simpler than the runtime evaluator and focused only on generated probe families. It should be testable with a compact decision table.

### 10.4 Probe execution

Add a conformance runner that:

- compiles the contract once;
- executes generated probes through the native policy engine;
- compares outcome/reasons/matched rules as appropriate;
- reports PASS/FAIL/ERROR per probe;
- never invokes network, models, or real tools.

Compiler/runtime exceptions are ERROR, not security PASS.

---

## 11. Contract-derived evaluation cases

Phase 3 should connect generated contract obligations to the existing Phase 1 evaluation machinery without pretending this is a real model red-team run.

### 11.1 Goals

The bridge should prove that:

- generated security intent can be represented in the Scenario/evaluation system;
- Phase 1 assertions interpret canonical evidence consistently with runtime policy semantics;
- approval assertions remain non-vacuous;
- generated case results can be included in coverage.

### 11.2 Preferred design

Generate a small typed `ContractEvaluationCase` that contains or can materialize:

- a deterministic synthetic `Scenario` using a synthetic `ToolDescriptor` only where needed;
- a deterministic request/action fixture for a specific compiled obligation;
- the expected Phase 1 assertion(s);
- source atom/rule references.

Then execute it through a target that uses the **compiled policy evaluator** to decide the request and emits normal canonical evidence. Do not hard-code the fixture's observed policy outcome from the expected result.

A viable flow:

```text
compiled rule atom
   │
   ├─ expected obligation: REQUIRE_APPROVAL
   │
   ├─ synthetic scenario + tool/request fixture
   │
   ▼
ContractConformanceTarget
   │  calls NativePolicyEngine(compiled plan)
   ▼
canonical request/decision/approval/dispatch evidence
   │
   ▼
existing Phase 1 trajectory validation + assertions
```

For approval cases, use an injected deterministic broker result when dispatch behavior is exercised. Keep the test split clear:

- policy obligation: outcome must be REQUIRE_APPROVAL;
- runtime obligation: no dispatch without exact approval;
- evaluation obligation: `APPROVAL_REQUIRED` assertion recognizes only valid approval trajectories.

### 11.3 What not to claim

These synthetic cases do not test:

- model instruction following;
- indirect prompt injection resistance;
- real MCP tool honesty;
- real-world resource canonicalization;
- Phase 4 data-flow security.

Label them as contract conformance cases, not adversarial robustness results.

---

## 12. Policy-change simulation and semantic diff

Phase 3 should let a developer inspect a contract change before activating it.

### 12.1 Required result categories

At minimum classify:

- `AUTHORITY_EXPANSION` — a request class changes from DENY/ERROR to ALLOW, or from REQUIRE_APPROVAL to ALLOW;
- `AUTHORITY_REDUCTION` — ALLOW becomes REQUIRE_APPROVAL or DENY, or REQUIRE_APPROVAL becomes DENY;
- `APPROVAL_BOUNDARY_CHANGE` — transitions involving REQUIRE_APPROVAL;
- `TASK_SCOPE_WIDENED` / `TASK_SCOPE_NARROWED`;
- `BUDGET_RELAXED` / `BUDGET_TIGHTENED` for supported budgets;
- `APPROVAL_TIMEOUT_CHANGED`;
- `IDENTITY_OR_ENVIRONMENT_CHANGED`;
- `UNSUPPORTED_SEMANTIC_CHANGED` — change cannot be simulated truthfully in current phase.

Do not reduce all changes to “safe/unsafe.” Report the semantic transition and let CI/user policy decide later.

### 12.2 Finite exact-match decision space

Current policy semantics are exact-match and therefore permit a useful bounded symbolic comparison.

Build a finite request partition from:

- union of capabilities referenced by old/new tool rules and task scopes;
- union of exact resources referenced by those capabilities;
- `None` where semantically meaningful;
- one collision-free `OTHER` resource sentinel per capability when needed;
- one collision-free unknown capability sentinel for default-deny behavior.

Evaluate equivalent canonical request classes against **both compiled plans** and compare outcomes/reasons. This is not general formal equivalence, but for the current exact-match subset it can cover the meaningful partitions if constructed correctly.

### 12.3 Avoid false equivalence claims

The diff must report when it cannot compare truthfully, including:

- identity/agent/environment changes that make requests invalid under one side;
- unsupported data/invariant/delegation semantics;
- adapter-specific resource interpretation differences;
- budget values that affect runtime state rather than a single policy request.

Treat these as explicit structural/runtime changes alongside the request-space diff.

### 12.4 Stable output

A deterministic machine-readable diff report is desirable for CI. If made public/persisted, give it a schema and export it through the existing schema system.

---

## 13. CLI surface

Keep the CLI compact. Exact command names may adapt to current Typer organization.

Recommended shape:

```bash
# Validate + compile and inspect the effective supported semantics
agentsec contract compile security/contract.yaml

# Run deterministic contract conformance probes + derived eval cases
agentsec contract test security/contract.yaml

# Inspect semantic coverage dimensions
agentsec contract coverage security/contract.yaml

# Compare before activation
agentsec contract diff old.yaml new.yaml
```

Useful options:

```text
--format text|json
--report-out PATH
--require-runtime-covered        # optional strict CI gate; must define semantics precisely
```

Avoid a dozen modes. Do not activate policies, mutate runtime configuration, or connect to real MCP servers from these commands unless a separate explicit integration-check command already exists.

### 13.1 Exit codes

Reuse established conventions where possible:

- success/pass: `0`;
- conformance/security failure: `1`;
- usage: Typer default `2`;
- inconclusive/coverage-required-but-unproven: use an existing compatible code if semantics match;
- internal/validation error: stable nonzero code consistent with current CLI.

Document exact behavior rather than inventing near-duplicate conventions.

---

## 14. Public artifacts and schemas

Prefer a small number of public artifacts.

Likely useful:

1. `CompiledSecurityPlan` or a reduced `CompiledContractManifest` for inspection;
2. `ContractCoverageReport`;
3. `ContractDiffReport`;
4. optional `ContractConformanceReport` if the existing evaluation result types do not fit.

Before making all of these public, ask whether an existing report model can carry the information without semantic confusion. Public persisted artifacts require:

- strict versioning;
- deterministic canonicalization where hashes/IDs depend on them;
- generated JSON Schema;
- freshness tests;
- backward-compatibility consideration for existing Phase 0–2 schemas.

Do not hand-edit generated schemas.

---

## 15. Determinism and identifiers

Phase 3 outputs are most useful when stable across machines/runs.

Requirements:

- compilation of the same canonical contract produces the same semantic IR content and atom/probe IDs;
- ordering is explicit and deterministic;
- source refs do not depend on dict iteration accidents;
- UUID4 may still be used for runtime event/decision instances, but not for compiled semantic identity;
- compiler version is recorded if output meaning can change across releases;
- a compiled manifest hash, if added, must be based on canonical semantic content and must not replace `effective_policy_hash` as the contract identity.

Do not confuse a deterministic hash with authenticity/signing. Cryptographic attestations belong later.

---

## 16. Security and privacy requirements

Phase 3 is mostly static/local but still handles security-sensitive configuration.

Requirements:

- generated reports should not embed secret-bearing real tool arguments;
- synthetic conformance values should be obviously synthetic and bounded;
- contract resource selectors may themselves be sensitive; text output should avoid gratuitous duplication where the project already uses privacy-minimized evidence;
- no network/model calls in compiler/probe/diff commands;
- no shell execution;
- no arbitrary schema reference resolution added by scenario generation;
- no raw Phase 2 approval display fields copied into durable conformance reports unless explicitly designed and safe;
- compiler/diff errors should use stable structural identifiers rather than dumping entire contract documents.

---

## 17. Focused testing strategy

Phase 3 touches a security-critical semantic boundary, but testing should remain focused and information-dense.

### 17.1 Compiler tests

Cover a compact set of representative contracts:

- deterministic compilation and IDs;
- exact preservation of tool rule IDs/decision/resource;
- task-scope ceiling preservation;
- supported budget/approval compilation;
- unsupported intent stays explicit;
- same semantic input yields stable plan/manifest;
- changed relevant semantic input changes the compiled meaning/hash/atoms as intended.

Do not create one test for every Pydantic field; Phase 0 validation already covers schema mechanics.

### 17.2 Native policy regression tests

Prove the compiled evaluator preserves Phase 2 behavior:

- DENY > REQUIRE_APPROVAL > ALLOW > DEFAULT_DENY;
- exact resource matching;
- task capability/resource ceiling;
- identity/environment mismatch;
- deterministic matched rule IDs/reasons;
- no delegation grant;
- malformed/internal error never becomes ALLOW.

Keep existing Phase 2 tests where they still provide boundary value; refactor fixtures rather than duplicating them wholesale.

### 17.3 Probe-generation tests

Cover:

- explicit deny probe;
- approval probe;
- allow probe with precedence interaction;
- task-scope exclusion;
- exact resource overlap;
- collision-free default-deny sentinel;
- expected result derived without calling the policy engine under test;
- deterministic probe IDs/order.

### 17.4 Evaluation bridge tests

A small matrix is sufficient:

1. generated DENY case passes a `TOOL_NOT_CALLED`/appropriate policy assertion and does not dispatch;
2. generated REQUIRE_APPROVAL case is non-vacuous and passes only with a real REQUIRE_APPROVAL trajectory;
3. generated ALLOW case dispatches through the conformance target when appropriate;
4. a deliberately broken policy/evidence path causes the generated case to fail/error rather than self-validate;
5. Phase 1 trajectory validation remains authoritative.

### 17.5 Semantic diff tests

Cover high-value transitions:

- DENY → ALLOW = expansion;
- REQUIRE_APPROVAL → ALLOW = expansion + approval-boundary change;
- ALLOW → REQUIRE_APPROVAL = reduction + approval-boundary change;
- general ALLOW plus new resource DENY is detected on the resource partition;
- removal/addition of task-scope capability/resource widens/narrows appropriately;
- supported budget increase/decrease classified correctly;
- unknown/default-deny partition remains represented;
- unsupported semantic changes are reported as unsupported, not silently equivalent.

### 17.6 Cross-path integration tests

Use the existing safe synthetic MCP example and injected approval broker. A compact parity table should prove selected requests produce consistent policy meaning across:

```text
direct compiled policy evaluation
contract-derived eval case
MCP RuntimeGateway path
```

At minimum cover ALLOW, DENY, REQUIRE_APPROVAL, and resource/task-scope behavior.

Do not duplicate the entire Phase 2 integration suite.

### 17.7 Regression checks

All Phase 0–2 tests must still pass. Continue running lint, formatting, strict mypy, schema freshness/export, examples, and build checks.

### 17.8 What not to do

Avoid:

- brute-force permutations of all rules/resources;
- property-based fuzzing merely to inflate coverage in this phase;
- snapshotting huge JSON blobs where targeted assertions are clearer;
- tests that compare generated expected output to itself;
- re-testing Pydantic/library behavior;
- real network/tool/model integration;
- line-coverage chasing as a Phase 3 goal.

---

## 18. Implementation sequence

### Step 0 — Reconcile latest baseline

- inspect current HEAD, `AGENTS.md`, PRD, architecture, Phase 2 plan/report/fixes, policy/runtime/eval modules;
- run the current focused and full baseline checks;
- identify any post-`eb29db9` semantics that this plan must incorporate.

**Exit:** implementation begins from a known current baseline with Phase 2 behavior understood.

### Step 1 — Define compiled IR and semantic atoms

- create immutable compiled plan models;
- define source references and semantic atom kinds;
- include contract/effective-policy identity;
- represent current supported/unsupported intent without adapter leakage.

**Exit:** a contract can compile deterministically into an inspectable in-memory plan.

### Step 2 — Implement the compiler

- normalize tool rules/task scope/budgets/approvals;
- record unsupported semantics;
- produce deterministic atom IDs/order;
- add public manifest/schema only if justified.

**Exit:** compiler tests prove stable meaning and explicit gaps.

### Step 3 — Move native policy evaluation onto compiled intent

- refactor `NativePolicyEngine` to consume the compiled plan;
- update runtime gateway initialization to compile once/reuse;
- preserve exact Phase 2 policy semantics and evidence identity;
- add stale-plan/policy-hash checks.

**Exit:** Phase 2 runtime behavior remains unchanged while raw-contract policy interpretation is removed from the active path.

### Step 4 — Compose adapter coverage with compiled requirements

- adapt current `policy.coverage` and `adapters.mcp.coverage` responsibilities;
- map compiled resource/task requirements to existing MCP binding/discovery proof;
- preserve `opaque_exact` and missing-extractor safety rules.

**Exit:** ENFORCE/SHADOW coverage truthfulness remains at least as strict as Phase 2.

### Step 5 — Generate and execute policy probes

- define deterministic probe model;
- implement focused obligation generator;
- implement simple independent expectation/oracle logic;
- execute probes against compiled policy evaluator;
- produce conformance results.

**Exit:** supported policy semantics have non-circular deterministic conformance checks.

### Step 6 — Bridge generated obligations into Phase 1 evaluation

- create contract-derived synthetic cases;
- add conformance target that calls compiled policy evaluator;
- reuse canonical evidence + existing trajectory/assertion machinery;
- ensure approval cases are non-vacuous and no expected decision is simply injected as observed truth.

**Exit:** generated contract cases run through the actual evaluation semantics and fail if policy/evidence behavior diverges.

### Step 7 — Add semantic coverage report

- project compiler atoms, runtime support, adapter proof where available, generated probes/cases, and execution results into one report;
- make unsupported/unproven dimensions explicit;
- avoid generic security percentages.

**Exit:** a developer can see exactly which contract semantics are compiled, enforceable, adapter-covered, and tested.

### Step 8 — Implement contract semantic diff

- compile old/new contracts;
- construct finite exact-match request partitions;
- compare outcomes and structural runtime settings;
- classify expansions/reductions/approval/task/budget/unsupported changes;
- produce deterministic text/JSON output.

**Exit:** meaningful authority changes are visible before activation without claiming general formal equivalence.

### Step 9 — CLI, examples, docs

- add compact contract compile/test/coverage/diff commands or equivalent;
- extend a safe example to demonstrate generated conformance and a policy diff;
- update README, `AGENTS.md`, architecture/evaluation/security-contract docs as needed;
- add Phase 3 implementation report.

**Exit:** documented local workflows work without network, credentials, or model APIs.

### Step 10 — Focused verification

At minimum run the repository's current equivalents of:

```bash
ruff check .
ruff format --check .
mypy src
pytest -q
agentsec examples validate
agentsec eval examples
agentsec schema export --out schemas/generated
python -m build --no-isolation
git diff --check
```

Also run targeted Phase 3 compiler/probe/diff/parity tests explicitly and one existing MCP stdio smoke test to prove the runtime refactor did not corrupt the protected path.

Do not add excessive new test layers if the focused tests already establish the boundary.

---

## 19. Acceptance criteria

Phase 3 is complete only when all of the following are true.

### 19.1 Single executable contract meaning

- A validated contract compiles deterministically to a typed immutable plan.
- The active native runtime policy path consumes that compiled plan rather than reinterpreting tool rules from the raw contract.
- The plan is bound to the correct contract/effective policy hash.
- Phase 2 policy behavior is preserved.

### 19.2 Generated conformance

- Supported tool-rule/task-scope semantics generate deterministic policy probes.
- Expected outcomes are not obtained by calling the policy engine under test.
- DENY, REQUIRE_APPROVAL, precedence, task-scope and default-deny obligations are covered.
- Approval cases are non-vacuous.

### 19.3 Eval/runtime parity

- Contract-derived cases execute through existing Phase 1 trajectory/assertion semantics.
- Selected cases produce consistent meaning through direct compiled-policy, eval, and MCP runtime paths.
- A deliberately broken path fails/errors rather than circularly passing.

### 19.4 Coverage truthfulness

- Coverage distinguishes compile support, runtime support, adapter proof, generated tests, and executed tests.
- Unsupported Phase 4+/identity/delegation semantics remain explicit gaps.
- MCP resource-extraction / `opaque_exact` requirements remain adapter-specific and fail closed as before.
- No generic “security percentage” overstates protection.

### 19.5 Policy change analysis

- Old/new contracts can be compared deterministically over the supported exact-match semantic partitions.
- Authority expansion/reduction and approval-boundary changes are detected for representative overlaps.
- Task-scope and supported budget changes are classified.
- Unsupported changes are reported as such rather than labeled equivalent.

### 19.6 Quality and compatibility

- all pre-existing tests pass;
- focused Phase 3 tests cover semantic boundaries without excessive duplication;
- lint/format/type/schema/build checks pass in the available environment;
- existing Phase 0–2 public artifact compatibility is preserved unless an additive, documented change is required;
- docs clearly state what generated contract tests prove and what they do not prove;
- the implementation report records deviations, commands/results, limitations, and Phase 4 readiness.

---

## 20. High-risk implementation mistakes to avoid

These should be treated as explicit implementation and review targets:

1. **Runtime bypasses the compiler.** Tests use `CompiledSecurityPlan`, but the MCP gateway still passes the raw contract to a separate rule interpreter.
2. **Circular conformance.** Probe expectation is literally the result of `NativePolicyEngine.decide()`.
3. **Coverage inflation.** An unsupported data rule counts as “tested” because a scenario mentions a similar label.
4. **Adapter leakage.** Core compiler imports MCP config/discovery types.
5. **Task scope becomes authority.** A capability absent from ALLOW rules becomes permitted merely because task scope includes it.
6. **Precedence drift.** Generated expectations or diff logic use first-match instead of DENY > REQUIRE_APPROVAL > ALLOW.
7. **Resource blind spot.** Semantic diff considers only general capability rules and misses a resource-specific deny/approval exception.
8. **Default-deny blind spot.** Diff/test universe contains only explicitly allowed resources and therefore misses newly opened “other” space.
9. **Stale compiled plan.** Runtime policy hash/evidence reflects one contract while the compiled plan came from another.
10. **Approval test is vacuous.** No matching request occurs, yet the case passes.
11. **Synthetic scenario overclaim.** A contract-conformance PASS is presented as proof against prompt injection or a real agent attack.
12. **Unsupported equivalence claim.** A changed invariant/data rule is ignored and the diff says “no semantic change.”
13. **Runtime state moved into pure compile.** Mutable budgets/approval redemption are embedded in the compiled policy artifact.
14. **Privacy regression.** Durable reports start persisting complete runtime arguments/resources that Phase 2 intentionally redacted.
15. **Schema/version drift.** New public artifacts are hand-written or unstable across identical inputs.

---

## 21. Review expectations

The independent Phase 3 review should use this plan as one input, not as a checklist ceiling.

The reviewer must first derive the intended Phase 3 architecture from the PRD, architecture, and current code, then ask:

- Did the plan itself miss an important requirement?
- Did implementation choices create a new bypass, semantic drift, or misleading security claim?
- Is “single source of truth” real in code, or merely documented?
- Is the equivalence/conformance evidence non-circular?
- Are policy changes analyzed over the meaningful exact-match decision partitions?
- Does coverage distinguish what is known, tested, enforced, and unsupported?
- Did the refactor weaken any Phase 2 review fix?

A separate Phase 3 Sol High review prompt should encode those requirements and produce a self-contained findings handoff for a fresh Luna XHigh fix session.

---

## 22. Phase 4 handoff boundary

Phase 3 should leave a clean seam for Phase 4 rather than implementing provenance early.

After Phase 3, a future Phase 4 should be able to:

1. introduce data/provenance semantic atoms and compiled flow-policy IR;
2. change current `data.rules` coverage from unsupported to supported incrementally;
3. generate source→sink flow tests from the same compiler framework;
4. feed provenance-aware inputs into runtime decisions without changing the basic contract → compiled plan → tests/runtime architecture.

That extensibility is the reason to build a disciplined compiler/coverage foundation now, but Phase 3 is complete without implementing any data-flow enforcement.
