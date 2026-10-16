# Agent Safety & Security Platform — Phase 5 Detailed Implementation Plan

**Phase:** 5 — Incident Replay & Security Regression
**Status:** Implementation-ready plan
**Repository:** `jasonkli21/agent-safety-security`
**Repository baseline inspected:** `be727ecf6aacc144a96cb6ceb2c9db7eaf1d918c` (`fix: address phase 4 review findings`)
**Depends on:** Phases 0–4, including the Phase 4 independent-review corrections
**Primary goal:** close the first complete security lifecycle loop by turning trustworthy evidence from a prior run into a portable, integrity-checked incident/replay artifact, deterministically re-executing the security-relevant parts without invoking real side effects, comparing semantics across versions, and promoting expressible incidents into local/CI regressions.

---

## 1. Current repository baseline

Phase 5 begins from the hardened post-Phase-4 state, not from the original roadmap in isolation.

Current `main` already provides:

1. **Strict canonical contracts and schemas**
   - canonical serialization and explicit document/effective-policy identities;
   - strict parsing, unknown-field rejection, typed security models, generated JSON Schemas.

2. **Deterministic evaluation and evidence**
   - typed `SecurityEvent` streams;
   - explicit lifecycle distinctions between request, policy decision, approval, dispatch, return, exposure, termination, and verified effect;
   - JSONL evidence I/O;
   - trajectory validation;
   - deterministic fixture-backed evaluation with security/utility assertions and findings.

3. **A real runtime enforcement boundary**
   - MCP gateway with ENFORCE/SHADOW/DISABLED semantics;
   - exact-action approvals and budget ledgers;
   - protected runtime-owned mutable state;
   - content-minimized evidence;
   - fail-closed critical evidence behavior.

4. **A unified compiled security plan**
   - one compiled representation used by native policy/runtime/conformance;
   - exact contract/compiler/plan identity;
   - semantic coverage and diff;
   - explicit unsupported intent rather than false coverage.

5. **Tracked provenance/data-flow security**
   - immutable content-free artifact refs and lineage;
   - monotonic labels;
   - concurrency-safe exposed-context frontiers;
   - source/sink classification and reachability proof;
   - exact data-flow policy decisions and evidence causality.

6. **A clean reviewed Phase 4 baseline**
   - the Phase 4 follow-up reports 553 passing tests plus Ruff, formatting, mypy, schemas, examples, contract tests, package build, and focused integration verification;
   - the review fixes separated classification completeness from runtime reachability, strengthened trajectory reconstruction, corrected no-return transport evidence, and fixed data-rule semantic diff paths.

### 1.1 Baseline reconciliation rule

Before implementation, inspect the then-current HEAD and reconcile this plan with any newer changes. At minimum read:

1. `AGENTS.md`
2. `docs/prd.md`
3. `docs/architecture.md`
4. this Phase 5 plan
5. `docs/evidence-model.md`
6. `docs/evaluation.md`
7. `docs/scenario-format.md`
8. `docs/contract-conformance.md`
9. `docs/runtime-mcp.md`
10. `docs/provenance-data-flow.md`
11. `docs/reports/phase-4-implementation-report.md`
12. the current event/evidence/eval/runtime/compiler/CLI code

Do not force stale filenames or APIs if the repository has advanced.

`AGENTS.md` currently describes Phase 4 as awaiting independent review even though `main` already contains `be727ec` review fixes. Phase 5 implementation should update phase-boundary documentation to match reality once this plan is accepted.

---

## 2. Phase 5 objective

The PRD defines Phase 5 as **Incident Replay & Security Regression**:

- replay bundles;
- deterministic tool substitution;
- trace diffing;
- incident classification;
- “promote to regression” workflow;
- CI integration.

The architecture assigns the replay engine responsibility for packaging trace dependencies, substituting deterministic/mock tools, re-executing a scenario, comparing behavior, and promoting incidents to regressions.

The concrete Phase 5 objective is:

> **Given a trustworthy prior security trace plus the security artifacts required to interpret it, preserve the source facts immutably, make replayability and fidelity explicit, deterministically re-execute the security-relevant behavior without real external side effects, compare the resulting semantics, classify evidence-backed incidents, and turn safely expressible incidents into repeatable regression cases.**

Phase 5 is the first phase that completes this loop:

```text
contract
   │
   ├── evaluation
   └── runtime enforcement
          │
          ▼
      evidence
          │
          ▼
      incident
          │
          ▼
    replay bundle
          │
     ┌────┴────┐
     ▼         ▼
historical   candidate/current
replay       replay
     └────┬────┘
          ▼
      trace diff
          │
          ▼
 promote to regression
          │
          ▼
      local + CI gate
```

---

## 3. Core design decisions

### 3.1 Replay is security-semantic replay, not deterministic model replay

Phase 5 must not claim that an LLM's hidden reasoning, token stream, or free-form output can be reproduced from the current evidence.

The initial replay boundary is:

- structured security requests;
- policy decisions;
- approval decisions where reconstructible;
- budget-relevant dispatch behavior;
- deterministic substituted tool-return metadata;
- provenance/exposure facts;
- security signals;
- termination/effect-verification facts where available;
- scenario assertions and resulting findings.

The platform may later support richer model/provider replay, but Phase 5 must label that as outside its fidelity boundary.

### 3.2 Replay must never invoke real side effects

A replay run must not:

- connect to the original MCP server;
- send mail/messages;
- mutate calendars/files/cloud resources;
- execute arbitrary shell/code through original tools;
- perform live payments or infrastructure actions.

Tool execution is replaced by a deterministic substitute sourced from the replay bundle.

Any code path that can accidentally fall through to a live adapter is a critical bug.

### 3.3 Historical evidence is immutable input

Source evidence is never rewritten to look like the replay succeeded.

A replay produces a new result with new identity. The bundle retains:

- source run/trace identity;
- source evidence digest;
- source contract/policy identity;
- source event references;
- incident evidence references.

Replay output has separate replay IDs/results.

### 3.4 Source semantics and candidate/current semantics are distinct

Phase 5 must distinguish:

1. **source/historical semantics** — what the bundle says happened and, when sufficiently bound, the compiled plan that interprets the source;
2. **candidate/current semantics** — what the current implementation/contract produces when replayed.

Do not overwrite one with the other. Trace diff exists specifically to compare them.

### 3.5 Replayability is explicit, not guessed

Some existing traces do not contain everything needed for exact replay:

- evidence may contain redacted fields;
- runtime evidence does not persist raw tool-response bytes;
- model-internal state is absent;
- older events may not bind an exact compiled-plan digest;
- tool descriptors/discovery metadata may not be present.

The bundle builder must report a typed replayability/fidelity assessment. Missing information may reduce fidelity or make a case non-replayable; it must never be silently synthesized.

Recommended fidelity levels:

```text
POLICY
SECURITY_RUNTIME
```

`POLICY` can re-evaluate reconstructible structured authorization inputs.

`SECURITY_RUNTIME` additionally has enough trusted tool/runtime metadata to reproduce approval/budget/provenance/substituted-return behavior.

Do not define a `FULL_MODEL` or equivalent claim in Phase 5.

### 3.6 Default bundles remain content-minimized

A replay bundle must not become a covert raw-trace archive.

Default behavior:

- include canonical structured security artifacts;
- include content-free artifact refs and response digests;
- do not recover plaintext from hashes;
- do not persist raw tool responses merely to improve replay fidelity;
- preserve existing redaction boundaries;
- reject attempts to claim exact reconstruction when redacted input is material.

If a future opt-in richer capture is added, it requires an explicit threat/privacy design and is not part of this phase.

### 3.7 Incident classification is evidence-backed and deterministic

Phase 5 should classify incidents from canonical findings, security signals, explicit invariant violations, and operator-supplied category where necessary.

Do not use an LLM classifier as authority.

If evidence supports multiple categories, retain them or require explicit selection. Do not invent one "best" category by heuristics that cannot be explained.

### 3.8 Promotion must not guess the fix

"Promote to regression" means preserving the unsafe/security-relevant condition as a future test, not automatically rewriting policy.

The workflow may automatically generate an ACTIVE regression only when a safe expectation can be expressed deterministically from existing assertion semantics. Otherwise it must create a DRAFT/NEEDS_REVIEW case or refuse promotion with a stable reason.

Examples of safe automatic expectations include cases where the intended invariant is structurally explicit, such as:

- an unauthorized/high-risk action must not dispatch;
- an explicit approval requirement must not be bypassed;
- a tracked SECRET/PII/CREDENTIAL flow must not reach a denied sink;
- a configured tool-call budget must not be exceeded;
- a known canary must not appear on an external sink when the source scenario provides that assertion.

Do not auto-author a new allow/deny rule as remediation.

### 3.9 Trace diff compares semantics, not volatile IDs

New replay run IDs, trace IDs, event IDs, timestamps, generated decision IDs, and generated approval IDs are expected to differ.

Semantic diff should compare stable projections such as:

- tool/capability/resource/destination/provenance context;
- policy outcome;
- reason codes;
- matched rule provenance;
- approval required/approved/denied;
- dispatched vs blocked;
- returned success and artifact metadata;
- exposed artifact labels/lineage;
- security signals;
- termination reason;
- assertion/finding outcomes.

No regression/improvement claim should be made solely from ID/timestamp changes.

### 3.10 Phase 5 does not change policy semantics by default

The compiled policy semantics are already `phase4-v1`.

Do **not** bump the compiler version merely because replay code is added.

A compiler-version change is warranted only if Phase 5 actually changes compiled policy meaning, identity, or executable behavior. If that becomes necessary, document it explicitly and test compatibility.

---

## 4. Scope

### 4.1 In scope

Phase 5 should implement:

- canonical `Incident` model;
- canonical replay bundle/manifest model;
- stable bundle/source-evidence digests;
- strict replay bundle validation;
- explicit replayability/fidelity assessment;
- bundle creation from validated evidence plus required security artifacts;
- deterministic replay engine with no live side effects;
- source-vs-replay semantic trace projection/diff;
- evidence-backed incident classification;
- incident-to-regression promotion;
- regression validation and execution CLI;
- local CI integration;
- current-plan/source-plan identity handling;
- compatibility behavior for legacy Phase 0–4 evidence;
- schema export for new public models;
- focused examples;
- focused docs;
- `AGENTS.md` phase-boundary update;
- Phase 5 implementation report.

### 4.2 Explicitly out of scope

Do not pull later phases into Phase 5:

- deterministic reproduction of model hidden state/token generation;
- live tool execution during replay;
- automatic retrieval of historical raw response contents from hashes;
- hosted incident storage/control plane;
- cryptographic signatures/attestations/transparency log;
- generalized tamper-proof evidence storage;
- OAuth/OIDC/workload identity/delegated credentials (Phase 6);
- generic protocol adapters beyond current local/eval/MCP boundaries (Phase 7);
- supply-chain signing/scanning platform expansion (Phase 8);
- multi-agent delegation graph semantics (Phase 9);
- semantic secret/PII classifiers;
- automatic declassification;
- a new policy language;
- Cedar/OPA migration;
- model-provider recording proxy;
- full debugger/UI.

---

## 5. Proposed package ownership

Exact filenames may adapt to the current tree, but preserve dependency direction.

```text
src/agentsec/
├── domain/
│   ├── incidents.py          # canonical incident model
│   └── replay.py             # bundle/result/diff/regression domain models
├── incident/
│   ├── classify.py           # deterministic evidence-backed classification
│   └── promote.py            # incident -> regression material
├── replay/
│   ├── bundle.py             # create/load/validate/digest bundle
│   ├── projection.py         # stable semantic trace projection
│   ├── engine.py             # deterministic side-effect-free replay
│   └── diff.py               # source vs replay semantic diff
├── regression/
│   ├── loader.py             # strict regression case loading
│   └── runner.py             # local/CI gate
├── cli/
│   ├── incident.py
│   ├── replay.py
│   └── regression.py
└── contracts/
    └── schema_export.py      # export new public schemas
```

Prefer these focused packages to a generic `utils.py`.

Core domain models must not import MCP, Typer, filesystem, or model-provider code.

---

## 6. Canonical models

### 6.1 `Incident`

Recommended minimum shape:

```text
Incident
- schema_version
- incident_id
- source_run_id
- source_trace_id
- categories[]
- severity
- evidence_event_ids[]
- finding_ids[]
- classification_basis[]
- created_at
- summary?              # content-minimized / trusted operator text only
```

Requirements:

- evidence refs must point into the source trace when the bundle contains it;
- duplicate refs/categories are rejected/canonicalized consistently;
- category identifiers reuse the existing taxonomy;
- severity reuse existing severity;
- no raw malicious content is required.

### 6.2 Replayability assessment

Recommended shape:

```text
ReplayabilityAssessment
- fidelity: POLICY | SECURITY_RUNTIME
- replayable: bool
- blockers[]
- limitations[]
- source_plan_binding: EXPLICIT | LEGACY_INFERRED | UNBOUND
```

Stable blockers should cover cases such as:

- mixed run/trace evidence;
- invalid trajectory;
- missing run start;
- contract hash mismatch;
- material redacted input;
- missing required tool metadata;
- missing source plan binding;
- unsupported event semantics.

A reduced fidelity can be valid; a false exactness claim is not.

### 6.3 `ReplayBundle`

Prefer one strict versioned JSON artifact initially instead of a custom binary/archive format.

Recommended contents:

```text
ReplayBundle
- schema_version
- bundle_id
- created_at

- source_run_id
- source_trace_id
- source_evidence_digest
- source_events[]

- contract
- contract_document_hash
- effective_policy_hash

- source_compiled_plan?
- source_compiler_version?
- source_compiled_plan_digest?

- tool_descriptors[]
- replay_steps[]

- incident?
- replayability

- bundle_digest
```

The exact field arrangement can change, but the semantics must remain explicit.

`bundle_digest` must be calculated over canonical bundle content excluding the digest field itself. Loading must recompute and reject tampering.

### 6.4 Replay steps

A replay step must contain only what the replay engine needs to reproduce security semantics.

For a tool request:

```text
ReplayActionStep
- source_request_event_id
- structured policy request fields
- source action digest
- expected source decision projection?
- approval outcome?
- deterministic substituted result?
```

A substituted result may contain:

```text
ReplayToolResult
- success
- response_hash?
- artifacts[]
- expose_artifacts[]
- effect_verification?   # factual recorded metadata only
```

Do not require raw response content.

### 6.5 Replay result / trace diff

Recommended result models:

```text
ReplayResult
- bundle_id
- source_run_id
- replay_run_id
- fidelity
- status
- projected_trace
- findings/assertion outcomes
- error_code?
```

```text
TraceSemanticDiff
- source_digest
- candidate_digest
- changes[]
- unchanged_count
- incomplete_reasons[]
```

Each change should include:

- stable semantic path;
- before;
- after;
- change kind.

Do not label a change "security improvement" unless an explicit regression assertion establishes that interpretation.

### 6.6 Regression case

A promoted regression should be a strict portable artifact/directory that can be checked into the repository.

Recommended manifest:

```text
RegressionCase
- schema_version
- regression_id
- source_incident_id
- status: ACTIVE | DRAFT
- contract
- scenario
- replay_script / replay inputs
- expected assertions
- provenance metadata
```

Reuse existing `Scenario`, assertion, fixture/evaluation types where doing so preserves one evaluation model. Do not fork a second incompatible assertion language.

---

## 7. Source evidence and identity hardening

### 7.1 Validate before packaging

Bundle creation must validate:

1. JSONL parsing;
2. event schema;
3. one source run/trace;
4. sequence uniqueness/order;
5. evaluation/runtime trajectory invariants applicable to the source;
6. event references;
7. source contract ID/effective-policy hash;
8. provenance/exposure causality;
9. any supplied tool/discovery metadata against source identities where possible.

Never package invalid evidence and call it replayable.

### 7.2 Bind future traces more strongly

Current `RUN_STARTED` binds contract ID and effective-policy hash but older Phase 4 traces do not necessarily prove the exact compiled-plan digest used by the original runtime.

Phase 5 should consider an additive evidence hardening:

```text
RunStartedPayload
- compiler_version?
- compiled_plan_digest?
- document_hash?
```

If added:

- runtime/eval producers should populate them when known;
- legacy events remain readable;
- replayability reports legacy binding as `LEGACY_INFERRED`/`UNBOUND`;
- do not pretend a plan compiled later is cryptographic proof of the exact historical runtime plan.

If an equally strong identity already exists by implementation time, reuse it instead of duplicating fields.

---

## 8. Replay engine

### 8.1 Deterministic inputs

Replay must inject:

- deterministic clock;
- deterministic ID generator;
- deterministic approval outcomes from the bundle/regression case;
- deterministic budget state progression;
- deterministic substituted tool results;
- deterministic provenance/exposure ordering.

No wall-clock/network dependency should affect a local replay result.

### 8.2 Reuse authoritative semantics

Where possible, call existing:

- compiled-plan/native policy evaluation;
- approval binding logic;
- budget ledger semantics;
- provenance engine;
- trajectory validator;
- evaluation assertions/findings.

Do not implement "replay policy" as a second interpretation of the contract.

### 8.3 Preserve event order and causal structure

For sequential traces, replay in canonical source order.

For overlapping requests:

- preserve request-time snapshots;
- allow multiple outstanding request lifecycles in replay state;
- do not retroactively add later exposure to an earlier request;
- ensure replayed lineage matches the same causal rules hardened in Phase 4.

If an event pattern cannot be represented by the initial replay engine, fail with a typed unsupported/replayability result; do not reorder it into a convenient story.

### 8.4 Side-effect substitution

A source dispatch should transition into a replay-only substitute result.

The replay engine must not instantiate the live MCP upstream adapter.

Tests should monkeypatch/socket-block or otherwise prove that replay does not perform network/tool side effects.

### 8.5 Historical and candidate modes

Support two clear operations:

1. **verify/source replay** — check the bundle's internal coherence against its captured/source semantics to the extent possible;
2. **candidate/current replay** — apply current code/current supplied contract and produce a semantic diff.

If exact historical plan binding is unavailable, source verification must report that limitation rather than imply exact reproducibility.

---

## 9. Incident classification

### 9.1 Inputs

Classification may use:

- canonical `Finding` objects;
- `SECURITY_SIGNAL` events;
- explicit reason codes;
- assertion failures;
- explicit operator category input.

### 9.2 Rules

Classification rules must be:

- deterministic;
- documented;
- independently testable;
- explainable through `classification_basis`.

Examples:

- canary/external-sink evidence -> `SECRET_EXFILTRATION` only when the scenario/evidence explicitly establishes that semantic;
- dispatch despite required-but-unapproved approval -> `APPROVAL_BYPASS`;
- out-of-authority dispatch -> `UNAUTHORIZED_TOOL_USE` / `POLICY_BYPASS` according to exact evidence;
- tracked untrusted data written to a denied memory sink -> `MEMORY_POISONING` when the evidence satisfies that definition.

Do not infer categories from arbitrary free-form tool text.

### 9.3 Ambiguity

If classification is ambiguous:

- preserve multiple supported categories, or
- require operator selection.

Do not silently collapse to a guessed category.

---

## 10. Promote-to-regression workflow

### 10.1 CLI shape

Exact names may adapt, but a coherent flow should exist, for example:

```bash
agentsec replay bundle create \
  --evidence run.jsonl \
  --contract contract.yaml \
  --out incident.replay.json

agentsec incident classify \
  --bundle incident.replay.json \
  --out incident.json

agentsec replay run \
  --bundle incident.replay.json \
  --format json

agentsec incident promote \
  --bundle incident.replay.json \
  --incident incident.json \
  --out regressions/<regression-id>/

agentsec regression validate --root regressions
agentsec regression run --root regressions
```

Avoid proliferating redundant commands if a simpler equivalent fits the existing Typer structure.

### 10.2 Promotion rules

Promotion must:

1. validate bundle/incident integrity;
2. preserve source provenance metadata;
3. map the incident to existing scenario/assertion semantics where possible;
4. create stable deterministic IDs;
5. emit ACTIVE only when expected behavior is unambiguous;
6. emit DRAFT/NEEDS_REVIEW otherwise;
7. never edit the source security contract automatically;
8. never copy unreviewed raw secrets into repository files.

### 10.3 Reproducibility

A checked-in regression case should run without:

- network;
- credentials;
- model API;
- original tool server.

---

## 11. CI integration

Add a deterministic regression gate to the existing CI only after the local runner is reliable.

Recommended behavior:

- validate regression corpus;
- run ACTIVE regressions;
- report DRAFT cases explicitly;
- fail on ACTIVE regression failure/error;
- do not silently skip malformed cases;
- preserve existing Ruff/format/mypy/examples/pytest/build gates.

A minimal command may be:

```bash
agentsec regression run --root regressions
```

or an equivalent examples-root command if the repository keeps public regressions under `examples/`.

Do not add hosted CI services or secrets.

---

## 12. Trace projection and diff

### 12.1 Stable projection

Create a stable projection independent of volatile IDs/timestamps.

Potential semantic paths:

```text
steps/0/request/tool_id
steps/0/request/capability
steps/0/request/data_destination
steps/0/request/data_labels
steps/0/decision/outcome
steps/0/decision/reason_codes
steps/0/decision/matched_rules
steps/0/approval/outcome
steps/0/dispatched
steps/0/return/success
steps/0/exposure/labels
signals/...
termination/reason
assertions/...
```

### 12.2 Missing/extra facts

Diff must detect:

- missing request/decision/dispatch/return/exposure;
- extra action;
- changed ordering with semantic impact;
- changed reason/rule provenance;
- changed incident/assertion result.

Do not compare raw `event_id`, `decision_id`, `approval_id`, `occurred_at` as security drift.

### 12.3 Incomplete comparisons

If either trace lacks required evidence, diff should be `INCOMPLETE`/contain explicit limitations rather than silently treating absent evidence as unchanged.

---

## 13. Error handling and trust boundaries

Add stable replay/incident error codes or typed application errors for:

- bundle digest mismatch;
- source evidence digest mismatch;
- mixed traces;
- invalid trajectory;
- contract mismatch;
- unsupported legacy semantics;
- incomplete replay inputs;
- material redaction;
- live-adapter attempt;
- promotion ambiguity;
- regression corpus invalidity;
- output-path collision/write failure.

Do not reuse policy `ReasonCode` for unrelated filesystem/package failures.

Avoid echoing raw untrusted content in CLI errors.

---

## 14. Schemas and compatibility

Export schemas for public Phase 5 artifacts, likely including:

- incident;
- replay bundle;
- replay result;
- trace semantic diff;
- regression case.

Do not manually edit generated schemas.

Pre-1.0 additive model changes may retain current schema-version conventions if that remains the repository policy, but document compatibility implications in the implementation report.

Legacy Phase 0–4 evidence should:

- remain parseable when structurally valid;
- receive honest replayability/source-binding limitations;
- never be upgraded silently into stronger guarantees.

---

## 15. Testing strategy

Testing should be security-focused but not gratuitously exhaustive.

### 15.1 Unit tests

Cover:

- strict model validation/unknown fields;
- canonical ordering;
- bundle self-digest exclusion and recomputation;
- tamper rejection;
- source evidence digest;
- mixed run/trace rejection;
- invalid event order/duplicate ID rejection;
- legacy source-plan binding status;
- material-redaction replay blockers;
- deterministic IDs/clocks;
- incident classification basis;
- ambiguous classification;
- semantic projection ignoring volatile IDs;
- semantic diff catching policy/dispatch/provenance changes;
- promotion ACTIVE vs DRAFT;
- stable regression IDs;
- output-path collision handling.

### 15.2 Replay/runtime-focused tests

Cover:

- allow -> allow stable replay;
- allow -> deny current-policy change;
- deny -> allow current-policy change;
- approval required / approve / deny;
- action-digest mismatch cannot reuse approval;
- budget exhaustion trajectory;
- substituted tool return without live upstream call;
- returned-but-not-exposed response;
- data-flow denial using inherited labels;
- concurrent sibling provenance ordering;
- transport/no-return lifecycle;
- effect-verification facts are not mistaken for live replay side effects.

### 15.3 End-to-end incident loop

At least one focused local integration should prove:

```text
source evidence
 -> bundle
 -> classify incident
 -> replay
 -> semantic diff
 -> promote
 -> regression validation
 -> regression run
```

Use a known unsafe local fixture and a corrected candidate case so the workflow demonstrates both a failing regression before the fix and a passing regression after expected semantics change, without network access.

### 15.4 Preserve existing gates

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
git diff --check
```

Also run focused Phase 5 CLI/replay/regression tests.

Test count is not a target.

---

## 16. Documentation requirements

Update or add focused documentation covering:

- replay fidelity and non-goals;
- replay bundle structure/integrity;
- incident classification;
- promote-to-regression workflow;
- trace diff semantics;
- CI usage;
- privacy/redaction limitations;
- legacy evidence limitations.

Update `AGENTS.md` so the current phase boundary no longer says Phase 4 is awaiting review if the repository baseline has already incorporated those review fixes.

Update architecture only for enduring design choices. Do not rewrite the PRD for implementation convenience.

---

## 17. Implementation report

Create:

```text
docs/reports/phase-5-implementation-report.md
```

Required sections:

1. baseline and final implementation commit;
2. scope implemented;
3. replay fidelity/security semantics;
4. source/current identity and integrity decisions;
5. privacy/redaction decisions;
6. incident classification and promotion semantics;
7. CI/regression integration;
8. deliberate deviations from this plan;
9. exact verification commands/results;
10. mandatory self-review;
11. known limitations;
12. readiness for Phase 6.

Do not call self-review independent approval.

---

## 18. Mandatory implementation self-review

Before declaring Phase 5 complete, explicitly check:

- Can any replay path call a live tool/upstream?
- Can a tampered bundle pass because the digest omits security-relevant content?
- Can events from two runs/traces be combined?
- Can redacted/missing data be silently reconstructed or defaulted?
- Can a current contract be mislabeled as the historical source contract?
- Can volatile IDs/timestamps create noisy/fake semantic diffs?
- Can a real semantic change be hidden by projection normalization?
- Can approval be replayed under a different action/provenance context?
- Can budget state be reset in the middle of a replay?
- Can provenance/exposure be reordered so an earlier request sees later data?
- Can a substituted tool return be misrepresented as a real external effect?
- Can raw secrets enter generated incident/regression files?
- Can classification overclaim based on free-form content?
- Can promotion auto-weaken/expand the contract?
- Can a DRAFT/invalid regression be silently counted as passing CI?
- Are Phase 0–4 enforcement/evidence invariants still intact?
- Are docs/schemas/examples consistent with actual code?

Any unresolved issue should be documented rather than hidden.

---

## 19. Exit criteria

Phase 5 is complete when all of the following are true:

1. a valid source evidence trace can be packaged into a strict integrity-checked replay bundle;
2. replayability/fidelity and legacy limitations are explicit;
3. replay runs perform no live side effects;
4. authoritative current security semantics are reused rather than reimplemented;
5. source and replay traces can be compared semantically without volatile-ID noise;
6. incidents can be classified from explicit evidence with reviewable basis;
7. safely expressible incidents can be promoted to deterministic regressions;
8. ambiguous promotion does not guess a fix;
9. ACTIVE regressions run locally and in CI without network/credentials/models;
10. tampering, mixed traces, missing material inputs, and malformed cases fail visibly;
11. public schemas/docs/examples are synchronized;
12. the full existing suite and quality gates pass;
13. the Phase 5 implementation report records exact behavior and limitations.

Phase 6 identity/delegation work should start only after Phase 5 receives independent review and any required fixes.
