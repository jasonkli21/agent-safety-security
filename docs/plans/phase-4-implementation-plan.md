# Agent Safety & Security Platform — Phase 4 Detailed Implementation Plan

**Phase:** 4 — Provenance and Data-Flow Security
**Status:** Implementation-ready plan
**Repository:** `jasonkli21/agent-safety-security`
**Repository baseline inspected:** `3b9bc15abfbe70403afc858ec6811c7ff78c6489` (`fix: address phase 3 independent review findings`)
**Depends on:** Phase 0 canonical schemas; Phase 1 deterministic evaluation/evidence; Phase 2 MCP runtime gateway; Phase 3 compiled contract/conformance/coverage/diff, including the independent-review corrections in `3b9bc15`
**Primary goal:** make explicit data labels and provenance part of the same compiled security contract used by runtime and evaluation, then enforce sound source→sink restrictions over tracked data without pretending that an MCP gateway can see or perfectly taint arbitrary model-internal text.

---

## 1. Current repository baseline

Phase 4 starts from a materially stronger baseline than the original PRD/architecture text anticipated. Current `main` already has:

1. **Canonical data/provenance vocabulary from Phase 0**
   - `DataLabel`, `TrustClass`, `DataOrigin`, and `DataArtifactRef`;
   - `PolicyRequest.data_artifact_refs` as a protocol-independent hook that is currently unused by runtime;
   - `DataRule` / `DataPolicy` in the contract, with exact label, capability, and opaque destination identifiers;
   - `ReasonCode.DATA_FLOW_DENIED` and security categories for secret exfiltration, PII exposure, and memory poisoning;
   - typed events whose `TOOL_RETURNED` payload can already reference data artifacts.

2. **Deterministic evaluation and evidence from Phase 1**
   - causal trajectory validation;
   - deterministic assertions and content-minimized evidence;
   - explicit completeness semantics rather than treating missing evidence as a pass.

3. **A real MCP enforcement boundary from Phase 2**
   - immutable discovery snapshots and explicit tool bindings;
   - exact resource extraction/coverage checks;
   - approval and budget state separated from policy;
   - response schema inspection;
   - truthful ENFORCE / SHADOW / DISABLED behavior;
   - privacy-minimized request evidence and fail-closed critical evidence handling.

4. **A unified executable contract path from Phase 3**
   - immutable `CompiledSecurityPlan` consumed by native policy/runtime;
   - exact plan identity (`contract_id`, compiler version, effective-policy hash, compiled-plan digest);
   - source-linked semantic atoms and dimensioned coverage;
   - non-circular generated conformance/eval cases;
   - adapter proof bound to the exact plan and discovery snapshot;
   - finite semantic diff including explanation changes;
   - current compiler identifier `phase3-v2`.

5. **Phase 3 independent-review corrections already applied**
   - executable identity excludes cosmetic agent/task prose;
   - conformance checks exact reason and matching-rule provenance;
   - stale compiled plans and stale discovery proof are rejected;
   - grouped identity/task atoms do not overclaim generated coverage;
   - semantic diff reports explanation-only changes.

The Phase 3 fix report records a clean verification baseline of **502 tests**, plus passing Ruff, formatting, mypy, examples, schema export, package build, and `git diff --check`. Phase 4 must preserve the behavior protected by those tests; test count itself is not a target.

### 1.1 Baseline reconciliation rule

Before implementation, inspect the then-current HEAD, `AGENTS.md`, PRD, architecture, focused docs, Phase 3 plan/report, `docs/contract-conformance.md`, `docs/runtime-mcp.md`, and the actual compiler/policy/runtime/adapter code. If the repository has advanced past `3b9bc15`, reconcile this plan with the newer implementation rather than forcing stale filenames or APIs.

Do not start Phase 4 from the original architecture alone: the Phase 3 review fixes are part of the security boundary now.

---

## 2. Phase 4 objective

The PRD names Phase 4 as:

> **Provenance and Data-Flow Security — data labels, source/sink modeling, provenance graph, taint propagation, flow policy, memory-write controls, and secret/PII flow restrictions.**

The concrete Phase 4 objective is:

> **For data that the security boundary can explicitly identify and track, preserve its provenance and labels across agent/tool trajectories, compile `data.rules` into executable restrictions, and prevent tracked sensitive or untrusted data from crossing disallowed capability/destination boundaries.**

The critical qualifier is **tracked**. The project must not equate “no tracked SECRET artifact” with “the model contains no secret text.” MCP exposes tool calls and tool responses, not the model’s complete hidden/context state. Phase 4 therefore establishes a sound conservative tracked-provenance subset and reports unobservable sources as limitations rather than inventing unsound value-level taint.

The target flow becomes:

```text
Agent Security Contract
        │
        ▼
Compiler
        │
        ├── tool/task authority
        └── data-flow rules
                │
                ▼
      Compiled Security Plan
                │
         ┌──────┴─────────┐
         ▼                ▼
  Provenance state    Native policy
  labels + lineage    authority + flow clamp
         │                │
         └──────┬─────────┘
                ▼
        Runtime / MCP PEP
                │
      source response observed
                ▼
      response guard / release
                ▼
    artifact exposed to agent
                │
       conservative taint
                ▼
       later sink request
                │
       allow / approval / deny
                ▼
       canonical evidence
```

---

## 3. Security thesis and resolved Phase 4 design

Several architectural questions are intentionally resolved here so implementation does not silently invent semantics.

### 3.1 Data policy is a restriction layer, never a grant

`data.rules` may only make an otherwise valid action **more restrictive**.

They must never:

- turn default deny into allow;
- bypass an explicit tool deny;
- expand task scope;
- bypass required approval;
- grant an unbound tool;
- widen identity/delegation authority.

Conceptually:

```text
base_authority = evaluate tool/task/identity policy

if base_authority is DENY or ERROR:
    preserve that result
else:
    data_result = evaluate tracked labels + capability + sink destination
    data_result may clamp ALLOW/REQUIRE_APPROVAL to DENY/ERROR
```

### 3.2 Labels are explicit security metadata, not content detectors

Phase 4 enforces labels supplied by trusted security/runtime code. It does **not** claim to discover every secret, credential, PII value, or prompt injection in arbitrary text.

No Phase 4 behavior may scan content and then silently promote an uncertain heuristic to authorization authority.

Secret/PII restrictions in this phase mean:

> if a tracked artifact is explicitly labeled `SECRET`, `PII`, or `CREDENTIAL`, its configured data-flow rules are enforced.

Automatic secret/PII classifiers may be added later as signals or trusted classifiers with explicit coverage semantics.

### 3.3 Propagation is monotonic and conservative

For a derived artifact:

```text
derived labels ⊇ union(parent labels)
```

Phase 4 has **no automatic declassification, sanitizer, label removal, or trust upgrade**. A transformation may add labels; it may not automatically remove inherited labels.

This avoids inventing a data-label lattice or claiming semantic sanitization that the runtime cannot prove.

### 3.4 MCP uses conservative ambient context taint, not value matching

The MCP gateway cannot know exactly which prior response bytes influenced a later model-generated tool argument. It can, however, know which tool responses were released into the agent’s context.

For one protected runtime session, Phase 4 therefore treats all currently exposed provenance-frontier artifacts as **possibly influential** on the next tool request. The request carries a snapshot of that frontier into policy evaluation.

This is intentionally conservative:

- it can over-taint and block a legitimate action;
- it must not under-taint by guessing that a prior secret “probably was not used”;
- it never searches arguments for matching plaintext/digests to reconstruct lineage;
- it does not claim token-level or model-internal provenance.

### 3.5 Propagation must be causally correct under concurrency

Ambient taint is snapshotted when a tool request begins authorization.

If request B begins before response A is released to the agent, B must not retroactively inherit A. If B begins after A is released, it must see A’s exposed artifact state.

Provenance state therefore needs explicit concurrency-safe snapshot/expose operations; a global mutable set with race-prone reads is not sufficient.

### 3.6 Returned data and exposed data are different facts

Phase 4 introduces an evidence distinction the current runtime needs for truthful taint:

```text
upstream returned data
    ≠
response passed the guard and was released to the protected agent
```

`TOOL_RETURNED` records the upstream return. Provenance/taint must enter agent context only after response inspection and an explicit **data exposed / response released** evidence step.

This prevents an ENFORCE-mode response rejected by the response guard from contaminating later context as if the agent saw it.

### 3.7 Source classification is explicit; MCP output is untrusted by default

Every MCP response that is actually released should produce a content-free artifact reference with at least:

- `TOOL_OUTPUT`;
- `UNTRUSTED_CONTENT`.

A binding may add explicit labels such as `SECRET`, `PII`, `CREDENTIAL`, `SENSITIVE`, etc.

Do not reinterpret the existing `data_access_labels` field as proof about response content. Add a distinct source/output-label declaration so old risk metadata does not silently acquire new authorization meaning.

Recommended additive binding field:

```text
output_data_labels: set[DataLabel] | null
```

Semantics:

- `null` = not reviewed/classified for Phase 4 source labeling;
- `[]` = explicitly reviewed; no extra labels beyond automatic MCP output/untrusted labels;
- non-empty = add these explicit labels to returned artifacts.

### 3.8 Sink destinations are trusted categories, not inferred URLs/recipients

Existing contract destinations are opaque identifiers. Phase 4 should preserve that design.

Recommended additive MCP binding field:

```text
data_sink_destination: Identifier | null
```

Examples: `external`, `memory`, `internal_service`, `local_workspace`.

The adapter does **not** infer internal/external from a URL, email address, path, Unicode form, or tool description in Phase 4. A dynamic argument-dependent destination classifier is future work.

If a contract activates destination-based data rules, missing destination classification is an adapter coverage gap; ENFORCE must not silently treat “unknown” as “not denied.”

### 3.9 The current label set is a tag set, not a confidentiality lattice

Do not infer hidden relationships such as:

```text
CREDENTIAL => SECRET
PII => SENSITIVE
PUBLIC < INTERNAL < SECRET
```

unless the contract explicitly contains rules for those labels. A future phase may formalize a lattice, but Phase 4 should keep wire semantics exact and explainable.

---

## 4. Scope boundaries

### 4.1 In scope

Phase 4 should implement:

- executable compilation of current `data.rules` instead of reporting them as unsupported;
- exact, documented `allowed_*` / `denied_*` semantics for capability and destination restrictions;
- protocol-independent flow evaluation over trusted `DataArtifactRef` inputs;
- a small provenance engine that stores immutable artifact nodes, parent relationships, labels, and source metadata;
- monotonic label propagation;
- concurrency-safe exposed-context/frontier tracking for runtime sessions;
- MCP tool-output artifact creation and conservative propagation after responses are actually released;
- explicit MCP source-label and sink-destination binding metadata;
- fail-closed MCP coverage rules for destination classification and source-label declarations where required;
- data-flow-aware `PolicyRequest` inputs;
- binding data-flow context into `NormalizedAction` / approval digests so approvals cannot be replayed under a materially different provenance context;
- data-flow denial as a deterministic policy clamp;
- memory-write protection using ordinary data rules plus a `memory` destination category in examples;
- secret/PII/credential flow restrictions over explicitly labeled artifacts;
- generated non-circular flow-policy conformance probes and Phase 1-derived cases;
- coverage that distinguishes compiled flow policy, runtime support, adapter/source/sink proof, generated cases, and execution;
- Phase 4 semantic diff for exact data-rule changes, rather than continuing to label all `data.rules` changes unsupported;
- evidence updates needed to distinguish returned from exposed data;
- focused MCP integration tests proving real cross-call tracked flow blocking;
- schema, docs, examples, `AGENTS.md`, and implementation report updates.

### 4.2 Explicitly out of scope

Do **not** pull future phases or unsound claims into Phase 4:

- token-level, byte-level, or model-internal taint tracking;
- automatic inference that a tool argument contains a prior secret by plaintext/hash matching;
- general semantic secret/PII detection;
- prompt-injection classifiers or LLM-based DLP as authorization authority;
- automatic declassification/sanitization;
- a formal data-label lattice;
- dynamic URL/email/path destination classification from arbitrary arguments;
- tracking initial user/model text that never crosses a supported provenance adapter;
- persistent cross-session memory provenance beyond explicit protected memory-tool flows;
- incident/replay bundles and “promote to regression” workflow (Phase 5);
- delegated identity/OAuth/OIDC/capability tokens (Phase 6);
- generic non-MCP adapters (Phase 7);
- supply-chain trust/signing work (Phase 8);
- multi-agent message provenance/delegation graphs (Phase 9);
- hosted storage/control plane;
- cryptographic attestations;
- a general graph database;
- a new policy language or Cedar/OPA migration;
- silent policy activation/hot reload.

Phase 4 should be useful and end-to-end for the tracked subset without pretending the subset is comprehensive DLP.

---

## 5. Normative `DataRule` semantics

The existing authored contract shape should remain valid; no new contract field is required for the Phase 4 core.

For an artifact label `L`, at most one `DataRule` already exists. Let a request have:

- effective tracked labels `labels` = union of labels on its trusted artifact refs;
- `capability`;
- optional `data_destination` from the trusted enforcement adapter.

A rule applies only when its `label` is present in `labels`.

### 5.1 Capability axis

For an applicable rule:

```text
if capability ∈ denied_capabilities:
    deny

if allowed_capabilities is non-empty and capability ∉ allowed_capabilities:
    deny
```

An empty `allowed_capabilities` means **no allowlist restriction on this axis**, not “deny all.”

### 5.2 Destination axis

If either destination set is non-empty, a trustworthy destination classification is required.

```text
if destination is unavailable:
    fail closed as missing flow context

if destination ∈ denied_destinations:
    deny

if allowed_destinations is non-empty and destination ∉ allowed_destinations:
    deny
```

An empty `allowed_destinations` means **no allowlist restriction on this axis**.

### 5.3 Multiple labels

Restrictions compose monotonically:

> **Any applicable label rule may block the flow. No label rule may override another rule’s denial.**

### 5.4 No matching data rule

A tracked label with no authored `DataRule` adds no data-flow restriction. Tool/task/identity policy still applies normally.

### 5.5 No tracked artifacts

If the request contains no tracked artifacts, no `DataRule` is activated solely from content guesses. This is a coverage limitation, not proof that the request is non-sensitive.

### 5.6 Decision composition

Preserve Phase 3 ordinary authority semantics first.

Recommended composition:

1. validate request/identity/task/tool inputs;
2. evaluate current exact tool/task policy;
3. if result is `DENY` or `ERROR`, return it unchanged;
4. if result is `ALLOW` or `REQUIRE_APPROVAL`, evaluate applicable data rules;
5. explicit flow restriction clamps result to `DENY` with `DATA_FLOW_DENIED`;
6. required but missing flow context fails closed with a new stable reason such as `DATA_FLOW_CONTEXT_MISSING`;
7. otherwise preserve the base `ALLOW` / `REQUIRE_APPROVAL` result.

For flow results, `matched_rule_ids` must retain exact relevant provenance. Do not discard the underlying matching tool rule IDs or the applicable data-rule IDs needed to explain the decision.

The exact reason-code set must be documented and tested; do not leave it dependent on incidental loop order.

---

## 6. Proposed package ownership

Exact filenames may adapt to the current tree, but preserve the dependency boundaries.

```text
src/agentsec/
├── domain/
│   ├── provenance.py            # content-free refs/origins; additive canonical types
│   ├── policy.py                # request gets destination/canonicalized artifact context
│   ├── approvals.py             # exact action binds data-flow context
│   ├── events.py                # returned vs exposed evidence distinction
│   └── taxonomy.py              # stable Phase 4 reason/event values
├── provenance/
│   ├── __init__.py
│   └── engine.py                # graph + monotonic propagation + exposure frontier
├── compiler/
│   ├── models.py                # compiled data rules / Phase 4 plan identity
│   ├── compile.py               # data rules become executable atoms
│   ├── probes.py                # flow obligations + finite flow partitions
│   ├── reporting.py             # coverage dimensions
│   └── diff.py                  # data-flow policy diff
├── policy/
│   └── native.py                # base authority + restrictive flow stage
├── runtime/
│   └── gateway.py               # snapshot context, bind action, create/expose artifacts
├── adapters/mcp/
│   ├── config.py                # output labels + sink category
│   ├── coverage.py              # source/sink proof
│   └── server.py                # passes trusted classifications only
└── eval/
    └── contract_cases.py        # source→sink generated conformance cases
```

Do not move MCP config types into the provenance/compiler core. Do not make the provenance engine depend on MCP.

---

## 7. Provenance engine

### 7.1 Keep the graph content-free

`DataArtifactRef` is already close to the right node representation:

```text
artifact_id
labels
data origin
parent artifact IDs
optional content hash
optional created_at
```

Raw response/request text is not required for provenance. Avoid adding raw content to graph nodes.

### 7.2 Required engine responsibilities

Implement a small in-memory application service that can:

- register an immutable root/source artifact;
- create a derived artifact from parent refs;
- union parent labels monotonically with explicitly added labels;
- reject conflicting duplicate artifact identities;
- preserve parent relationships without cycles created through its own API;
- answer artifact lookup and ancestry/lineage questions needed by tests/reporting;
- snapshot the currently exposed frontier;
- atomically expose a newly released artifact and update the frontier;
- support injected clock/ID generation for deterministic tests.

Do not add SQLite or a graph database solely for Phase 4.

### 7.3 Frontier semantics

The runtime frontier represents artifacts that may still influence future agent actions.

For each call:

```text
request_snapshot = current exposed frontier
```

For each returned/released tool response:

```text
new_artifact.parents = request_snapshot artifact IDs
new_artifact.labels  = union(request_snapshot labels)
                     ∪ {TOOL_OUTPUT, UNTRUSTED_CONTENT}
                     ∪ binding.output_data_labels
```

When the new artifact is exposed, update the frontier without destroying concurrent branches. An implementation may compact parents that the new artifact causally supersedes, but it must preserve artifacts from concurrent branches that were not parents of this response.

### 7.4 Concurrency invariant

There must be a focused test proving this ordering:

```text
A starts (frontier = F0)
B starts (frontier = F0)
A response exposes SECRET artifact A1
B request remains based on F0
B response later exposes B1 with parents F0, not A1
next request sees frontier representing both A1 and B1
```

No event-loop race may allow a post-exposure request to read a stale frontier.

---

## 8. Policy and action model changes

### 8.1 `PolicyRequest`

Add a protocol-independent optional field such as:

```text
data_destination: Identifier | None
```

Continue using the existing `data_artifact_refs` field for provenance inputs.

Normalize artifact refs deterministically (for example, sort by `artifact_id`) and reject duplicate artifact IDs in one request so semantically identical context does not produce unstable identity/digests.

### 8.2 `NormalizedAction`

Approval/exact-action binding must include the data-flow context that affected authorization.

At minimum bind:

- `data_destination`;
- the exact canonical tracked artifact refs or a canonical digest over them.

Prefer an explicit typed representation over a loose dictionary. A change in relevant provenance labels/artifact identity/destination must change the action digest.

This prevents an approval created under one flow context from authorizing a materially different data-bearing action.

### 8.3 Trusted ownership

Artifact refs and sink classification used for authorization must come from trusted runtime/adapter state, not from agent-authored tool arguments saying “this is safe.”

MCP request arguments must not contain a magic field that can clear or relabel provenance.

---

## 9. Compiler / compiled-plan extension

### 9.1 Compiler version

Advance the compiler identity from `phase3-v2` to a Phase 4 identifier such as:

```text
phase4-v1
```

This is required because data rules change from “unsupported inventory” to executable semantics. Phase 3 compiled manifests/reports are stale and must be regenerated.

Do not change `effective_policy_hash` semantics merely because data rules become executable: the current effective-policy projection already includes them.

### 9.2 Compiled data rules

Add a protocol-independent representation, or reuse the strict canonical `DataRule` if doing so preserves immutability and source identity.

The compiled plan must include:

- exact label selector;
- exact allowed/denied capabilities;
- exact allowed/denied destination category IDs;
- source rule ID/path;
- deterministic semantic atom identity.

### 9.3 Semantic atoms

Existing `data.rules/<rule_id>` atoms should become compiled/runtime-supported rather than unsupported.

They should remain `adapter_required` because a real adapter must supply trustworthy provenance and, when destination constraints are present, destination classification.

Do not mark a data atom adapter-covered merely because the policy engine can evaluate a synthetic `DataArtifactRef` offline.

### 9.4 Remaining unsupported semantics

Phase 4 should leave these as explicit gaps unless separately implemented by current code:

- prose invariants;
- `acts_on_behalf_of` semantics;
- unsupported budgets;
- delegation enforcement;
- general content classifiers;
- automatic declassification.

The plan digest must continue to bind unsupported inventory as Phase 3 review required.

---

## 10. Native policy engine

### 10.1 Preserve one executable policy path

Do not create a separate “DLP engine” with subtly different contract interpretation.

The native evaluator should consume the same compiled plan and apply:

```text
ordinary authorization
        then
restrictive data-flow stage
```

Generated conformance and runtime both exercise that same evaluator.

### 10.2 Data-flow input validation

The engine must reject or fail closed on malformed/incomplete flow context that is required to evaluate an active rule.

Examples:

- duplicate artifact identity;
- required destination missing;
- unsupported/malformed artifact reference;
- mismatched protected identity still remains an ordinary invalid request.

### 10.3 Explanation/provenance

Phase 3 review specifically hardened exact reason and matched-rule provenance. Phase 4 must preserve that bar.

A flow denial must make it possible to tell:

- which tool rules matched;
- which data rules applied;
- which stable reason caused the final restriction.

Do not regress to a generic “denied” without rule provenance.

---

## 11. MCP source/sink integration

### 11.1 Additive binding metadata

Recommended fields:

```text
output_data_labels: set[DataLabel] | null = null
data_sink_destination: Identifier | null = null
```

`data_access_labels` remains existing tool-risk/data-access metadata and does not become an implicit output-label declaration.

### 11.2 Default response labels

Any protocol-valid MCP response that is actually released to the client is conservatively treated as:

```text
TOOL_OUTPUT + UNTRUSTED_CONTENT + explicit output_data_labels
```

This makes memory-poisoning controls useful without a semantic prompt-injection classifier.

### 11.3 Source classification coverage

For labels other than automatically known MCP labels (`TOOL_OUTPUT`, `UNTRUSTED_CONTENT`), an active flow policy should not claim adapter/source coverage if relevant output classification is unreviewed.

Using nullable `output_data_labels` allows:

- `null`: unreviewed/unproven;
- empty: reviewed, no additional labels;
- non-empty: reviewed and classified.

Pre-discovery and discovery-time coverage should surface unreviewed classifications truthfully. ENFORCE should fail closed where the implementation claims the relevant data-rule atom is adapter-covered but cannot establish its source labeling assumptions.

The exact coverage gate should be conservative and documented; do not hide incompleteness behind “no labels observed yet.”

### 11.4 Destination coverage

If any active data rule constrains destinations, every discovered bound tool that may receive tracked context must have an explicit `data_sink_destination` category before ENFORCE claims destination coverage.

This is intentionally strict. “No destination configured” means **unknown**, not “internal/safe.”

SHADOW may forward with an explicit coverage/error signal; it must not fabricate a safe destination.

### 11.5 Static categories only in Phase 4

A tool whose destination changes per request may be conservatively classified to a broader static category such as `external`.

Do not parse recipient strings/URLs to invent a dynamic trusted category in this phase.

### 11.6 Discovery proof freshness

Extend the existing Phase 3 adapter proof; do not create an unbound side channel.

Data source/sink proof must remain bound to:

- exact `PlanIdentity` including compiled-plan digest;
- exact MCP discovery snapshot digest including bindings/metadata.

A changed source label or sink classification must invalidate old proof.

---

## 12. Runtime response and exposure flow

Recommended protected path:

```text
request arrives
    │
    ├─ snapshot exposed provenance frontier
    ├─ build PolicyRequest(data refs + sink destination)
    ├─ decide tool/task/data policy
    ├─ approval/budgets if applicable
    ├─ dispatch
    ▼
upstream response
    │
    ├─ TOOL_RETURNED factual evidence
    ├─ create response DataArtifactRef
    ├─ output schema / response guard
    │
    ├─ ENFORCE rejected response -> do not expose / do not taint context
    │
    └─ response will be released
          ├─ atomically update provenance frontier
          ├─ emit DATA_EXPOSED / RESPONSE_RELEASED evidence
          └─ return response to MCP client
```

### 12.1 Tool errors

If the upstream returns a protocol-level tool error body to the client, that content is still tool output and may contain untrusted text. If it is released, it should participate in provenance/taint even though `success=false`.

A dispatch exception with no returned content produces no exposed artifact.

### 12.2 SHADOW

SHADOW retains the real data-flow decision but forwards protocol-valid calls/responses as its mode requires.

If SHADOW forwards data that ENFORCE would block, evidence must remain truthful. Emit an appropriate stable security signal rather than presenting the flow as protected.

### 12.3 DISABLED

DISABLED may still collect provenance evidence if the implementation already records runtime evidence, but it must never claim policy enforcement. Any reports must preserve the distinction.

---

## 13. Evidence-model changes

### 13.1 Add a release/exposure event

Add one narrowly scoped typed event such as:

```text
DATA_EXPOSED
- dispatch_id
- request_id
- tool_id
- artifact_ids[]
```

Exact naming may adapt to current conventions, but the semantic distinction is mandatory:

> `TOOL_RETURNED` means upstream returned data; the new event means that data crossed the response guard into protected agent context.

The event must be schema-versioned and added to generated schemas through the Pydantic source of truth.

### 13.2 Artifact evidence

Use `TOOL_RETURNED.artifacts` to carry the content-free response artifact refs. Parent IDs and labels are enough to reconstruct the tracked graph from evidence.

Do not require raw response bodies in evidence.

### 13.3 Request evidence

`PolicyRequest.data_artifact_refs` and `data_destination` are security-relevant inputs and must be bound by the full `policy_input_digest`.

If persisted directly, keep refs content-free and avoid secret-bearing source IDs. If additional redaction is introduced, evidence must retain enough artifact identity to reconstruct the flow and must distinguish redaction from absence, following the Phase 2 pattern.

### 13.4 Evidence failure before exposure

In ENFORCE, if the system cannot record a critical exposure event before releasing a response, fail closed/poison consistently with the existing critical evidence policy. Do not release data and then claim no exposure occurred.

---

## 14. Memory-write and exfiltration journeys

Phase 4 should include at least two explicit end-to-end examples.

### 14.1 Secret/PII exfiltration restriction

Example contract:

```yaml
data:
  rules:
    - rule_id: secret-no-external
      label: SECRET
      denied_destinations: [external]

    - rule_id: pii-no-external
      label: PII
      denied_destinations: [external]
```

Example source binding explicitly labels output as `SECRET` or `PII`; later external-write binding is categorized `external`.

Expected flow:

```text
source response exposed
  -> tracked artifact carries SECRET
  -> later external sink request snapshots artifact
  -> base tool rule would allow
  -> data policy clamps to DENY / DATA_FLOW_DENIED
  -> no dispatch in ENFORCE
```

The test is strongest when the base tool policy is otherwise ALLOW, so it proves the data rule—not ordinary authorization—caused the block.

### 14.2 Memory poisoning restriction

Because released MCP output is automatically `UNTRUSTED_CONTENT`, a contract can express:

```yaml
- rule_id: untrusted-no-memory
  label: UNTRUSTED_CONTENT
  denied_destinations: [memory]
```

A memory-write tool binding is categorized `memory`.

Expected result: a later write is blocked if any current tracked provenance frontier can carry untrusted tool content.

Phase 4 does not implement a memory database; it protects configured memory-write tools at the action boundary.

---

## 15. Generated conformance and evaluation

### 15.1 Flow-policy obligations

Extend the Phase 3 obligation generator with non-circular data-flow cases. Expected results must come from declarative rule semantics and a small explicit oracle, never by calling `NativePolicyEngine` and copying its result.

High-value cases:

- exact denied capability for a tracked label;
- capability outside a non-empty allowed-capability set;
- exact denied destination;
- destination outside a non-empty allowed-destination set;
- explicitly allowed capability/destination does not itself grant authority;
- multiple labels where any one denial wins;
- missing destination for a destination-constrained rule fails closed;
- propagation from source artifact to derived artifact preserves the sensitive label;
- untrusted tool output to memory sink;
- SECRET/PII-labeled output to external sink.

### 15.2 Avoid vacuous flow tests

A generated flow-denial case does not prove anything if the same request would already be denied by base tool policy.

Prefer a request partition where base authority is `ALLOW` or `REQUIRE_APPROVAL`, then verify data policy changes the final result. If no such finite request can be derived from the contract, report the flow obligation as non-derivable/NOT_RUN rather than passing it vacuously.

### 15.3 Phase 1 bridge

Use existing trajectory/assertion machinery where possible. Add only the minimum artifact/exposure semantics needed so synthetic flow cases can prove:

- source artifact exists;
- it was actually exposed when the test needs taint;
- a later request carries tracked provenance;
- a denied sink did not dispatch;
- a deliberately broken propagation/evaluator path fails rather than self-validating.

Do not turn Phase 1 into a second provenance engine.

---

## 16. Coverage model

Extend rather than replace Phase 3’s truthful dimensioned coverage.

For each data-rule semantic atom, report distinctly:

- compiled intent;
- runtime evaluator support;
- provenance-input requirement;
- adapter/source classification proof;
- adapter/sink classification proof when applicable;
- generated policy obligation;
- generated evaluation case;
- executed result;
- known boundary/limitation.

Do not produce a generic “DLP coverage %” or “X% secure.”

### 16.1 Tracked-data claim boundary

Documentation/reports must explicitly state:

- MCP Phase 4 tracks data returned through the protected MCP gateway and subsequently exposed;
- it does not automatically label arbitrary user input or model-internal text;
- explicit label declarations are trusted security configuration;
- absence of a label is not a semantic content scan result.

### 16.2 Adapter proof identity

Coverage composition must reject stale proof exactly as Phase 3 does. Changing `output_data_labels`, `data_sink_destination`, discovered metadata, or compiled flow policy must invalidate the proof identity/snapshot digest.

---

## 17. Semantic diff extension

Phase 3 currently treats `data.rules` as unsupported-change inventory. After Phase 4, that would be misleading.

### 17.1 Finite exact flow partition

For each old/new data label rule, build a finite partition from:

- union of labels referenced by old/new rules;
- capabilities referenced by allowed/denied sets plus a collision-free OTHER capability sentinel where needed;
- destinations referenced by allowed/denied sets plus a collision-free OTHER destination sentinel;
- no-rule/unrestricted state.

Compare the pure flow restriction result under both compiled plans.

### 17.2 Required change visibility

Report at least:

- data-flow restriction added / tightened;
- data-flow restriction removed / relaxed;
- allowed-capability set changed;
- denied-capability set changed;
- allowed-destination set changed;
- denied-destination set changed;
- label rule added/removed;
- explanation/rule-ID changes even when effective flow result is unchanged.

Do not call this general formal equivalence. It is a bounded exact comparison for the current set-based data policy.

### 17.3 Ordinary authority remains separate

A data-flow relaxation is not the same as granting a tool permission. The diff should distinguish ordinary action authority changes from data-flow restriction changes.

---

## 18. Public artifacts and schema/versioning

### 18.1 Contract schema

The authored contract already contains `data.rules`; a contract-schema redesign should not be necessary.

### 18.2 Additive public model changes

Likely schema changes include:

- `PolicyRequest.data_destination`;
- `NormalizedAction` data-flow binding;
- MCP binding source/sink fields;
- new exposure evidence payload/event;
- `CompiledSecurityPlan` data rules + compiler version;
- coverage/conformance/diff additions.

Use Pydantic models as source of truth and regenerate schemas. Never hand-edit generated JSON Schema.

### 18.3 Version discipline

Document compatibility decisions explicitly. If existing project convention keeps additive pre-1.0 artifact changes under schema `0.1`, preserve that only with tests/docs; otherwise bump where the existing versioning rules require it.

The compiler version **must** change because executable meaning changes.

### 18.4 Hash/digest review

Review all identity projections touched by Phase 4:

- `effective_policy_hash` already includes `data.rules`; preserve unless a deliberate semantic gap is found;
- `compiled_plan_digest` must bind the new executable flow IR and coverage inventory;
- approval/action digest must bind data-flow context;
- discovery snapshot digest must bind new binding classifications;
- ordinary hashes remain content identities, not signatures/authentication.

---

## 19. CLI and developer workflow

Do not add a large new command surface unless implementation proves it necessary.

Prefer extending existing workflows:

```bash
agentsec contract compile contract.yaml
agentsec contract test contract.yaml
agentsec contract coverage contract.yaml
agentsec contract diff old.yaml new.yaml
agentsec protect mcp --contract ... --config ... --check
agentsec protect mcp --contract ... --config ...
```

Expected Phase 4 changes:

- `compile` shows data rules as executable, not unsupported;
- `test` includes generated flow conformance;
- `coverage` shows provenance/source/sink dimensions;
- `diff` behaviorally reports data-rule changes;
- MCP `--check` reports obvious source/sink configuration gaps without connecting;
- serving startup rechecks against actual discovery and exact proof identity.

A standalone provenance-inspection CLI is optional and should be omitted unless it materially improves the phase without duplicating future replay/incident tooling.

---

## 20. Focused testing strategy

Phase 4 touches a security-critical stateful boundary. Tests should be high-value and focused, not exhaustive permutation generation.

### 20.1 Provenance engine tests

Cover:

- root/source artifact creation;
- monotonic label union;
- parent/lineage preservation;
- duplicate/conflicting ID rejection;
- deterministic injected clock/IDs;
- frontier compaction/preservation;
- concurrent branch semantics and post-exposure snapshot freshness.

### 20.2 Data-policy unit tests

Cover:

- data policy never grants base-denied authority;
- denied capability clamps an otherwise allowed request;
- non-empty allowed-capability set acts as a ceiling;
- denied destination;
- allowed-destination ceiling;
- empty allow sets mean no restriction;
- multiple labels: any deny wins;
- no matching label leaves base authority unchanged;
- required destination missing fails closed;
- exact matched data rule provenance/reasons;
- approval requirement survives when flow permits, but data deny wins when flow forbids.

### 20.3 Compiler / coverage / diff tests

Cover:

- `data.rules` compile deterministically into the plan;
- compiler version/plan digest changes appropriately;
- source-linked data atoms are no longer unsupported;
- adapter-required status is truthful;
- stale Phase 3/old proof is rejected;
- source/sink binding changes invalidate discovery proof;
- generated flow obligations are non-circular;
- vacuous base-denied cases are not reported as exercised flow coverage;
- flow diff detects tightening/relaxation and explanation-only changes.

### 20.4 Evidence tests

Cover:

- upstream return can exist without exposure;
- ENFORCE schema-rejected response is not exposed or added to active taint;
- SHADOW-forwarded response is exposed and tracked;
- exposed artifact IDs reference previously recorded artifacts;
- ordering/causality checks reject impossible exposure where applicable;
- no raw response content is required.

### 20.5 MCP integration tests

A compact end-to-end matrix is more valuable than dozens of near-duplicates:

1. source returns `SECRET` → later external sink otherwise ALLOW → data-flow DENY, no dispatch;
2. ordinary MCP output (`UNTRUSTED_CONTENT`) → later memory sink → deny;
3. source response blocked by output schema guard → later sink does **not** inherit it;
4. SHADOW would-block flow forwards but records real deny/coverage signal and exposed state;
5. missing destination/source classification required for active policy refuses ENFORCE or remains explicitly uncovered;
6. one concurrency test proves pre/post exposure causality.

Preserve at least one current stdio two-process smoke path.

### 20.6 Regression checks

All Phase 0–3 tests must continue to pass. Do not repeatedly run the full suite during every small edit; use focused tests while developing and run full verification near completion.

Recommended final checks remain the current repository equivalents of:

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

Add focused Phase 4 test commands to the implementation report.

### 20.7 What not to test excessively

Avoid:

- brute-force all label×capability×destination permutations;
- property/fuzz tests only to inflate coverage;
- huge JSON snapshots when direct semantic assertions are clearer;
- re-testing Pydantic/jsonschema behavior already covered;
- network/model calls;
- tests whose expected data decision comes from the same evaluator under test.

---

## 21. Implementation sequence

### Step 0 — Reconcile the latest baseline

- inspect current HEAD and `AGENTS.md`;
- read PRD/architecture plus focused Phase 1–3 docs/reports;
- inspect current compiler, policy, runtime, evidence, MCP adapter, and tests;
- run a focused baseline and record current full-suite state if practical.

**Exit:** implementation assumptions match the real repository, especially the Phase 3 review fixes.

### Step 1 — Specify Phase 4 semantics in docs/tests first

- write/extend a focused `docs/provenance-data-flow.md` (name may vary);
- codify `DataRule` allow/deny semantics;
- codify tracked-data boundary, monotonic taint, returned-vs-exposed distinction, source/sink trust assumptions;
- add small oracle/table tests where useful before the runtime refactor.

**Exit:** ambiguous security semantics are resolved before wiring them into runtime.

### Step 2 — Build the provenance engine

- keep canonical refs content-free;
- implement immutable graph + frontier operations;
- inject ID/clock;
- add concurrency-safe snapshot/expose semantics.

**Exit:** deterministic tests prove lineage and conservative propagation independent of MCP.

### Step 3 — Extend canonical request/action/evidence types

- add trusted data destination to `PolicyRequest`;
- canonicalize/deduplicate data artifact refs;
- bind flow context into `NormalizedAction`/approval digest;
- add typed exposure/release event;
- regenerate schemas later after all public changes settle.

**Exit:** policy/evidence/action models can represent one exact flow decision without raw content.

### Step 4 — Compile `data.rules`

- advance compiler version;
- include data rules in executable plan;
- convert data atoms from unsupported to supported/adapter-required;
- preserve all Phase 3 plan identity and unsupported-inventory guarantees.

**Exit:** compiled intent contains exact data policy with stable identity.

### Step 5 — Add restrictive data-flow evaluation

- preserve ordinary authority behavior;
- evaluate applicable label rules only over tracked artifacts;
- clamp allow/approval to deny/error when required;
- preserve exact matched-rule/reason provenance;
- ensure no data rule can grant authority.

**Exit:** direct policy tests prove deterministic data-flow enforcement.

### Step 6 — Add MCP source/sink configuration and coverage

- introduce explicit output label declaration and static sink category;
- keep old data-access metadata semantically distinct;
- extend configured/discovered coverage;
- bind proof to plan + discovery snapshot;
- fail closed on missing required classification in ENFORCE.

**Exit:** adapter can prove the classifications needed for the tracked MCP subset.

### Step 7 — Integrate runtime provenance and response release

- snapshot frontier before request evaluation;
- pass refs/destination into policy and action digest;
- create response artifacts on return;
- run response guard;
- expose/update taint only for data actually released;
- emit exposure evidence before release under ENFORCE;
- preserve SHADOW/DISABLED truthfulness.

**Exit:** a real protected MCP session can enforce a cross-call tracked source→sink restriction.

### Step 8 — Extend conformance, coverage, and diff

- generate independent flow obligations;
- bridge focused cases into Phase 1 evaluation;
- extend coverage dimensions;
- implement finite exact data-rule diff partitions;
- preserve Phase 3 explanation/freshness semantics.

**Exit:** one contract feeds runtime flow enforcement, generated verification, coverage, and pre-activation diff.

### Step 9 — Examples and docs

- extend the synthetic MCP example or add a tightly scoped safe flow example;
- document secret/PII flow and untrusted→memory journeys;
- update `docs/security-contract.md`, `docs/evidence-model.md`, `docs/runtime-mcp.md`, `docs/contract-conformance.md`, architecture, README where useful, and `AGENTS.md`;
- update architecture’s phase guidance to reflect the concrete Phase 4 boundary;
- create `docs/reports/phase-4-implementation-report.md`.

**Exit:** users can understand exactly what is protected and what is not.

### Step 10 — Verification and self-review

- run focused Phase 4 tests during development;
- run full lint/type/test/schema/example/build checks once the feature stabilizes;
- inspect for raw-content leakage, stale proof acceptance, approval digest gaps, race conditions, and overclaimed coverage;
- ensure unrelated files are not included.

**Exit:** implementation is ready for an independent Phase 4 review, not self-declared as independently approved.

---

## 22. Acceptance criteria

Phase 4 is complete only if all of the following hold.

### 22.1 Executable data policy

- Existing `data.rules` compile into the active immutable plan.
- Data rules can only restrict ordinary authority.
- Exact capability/destination allowlist/denylist semantics are documented and deterministic.
- Multiple labels compose fail-closed.
- Missing required destination context cannot silently allow.

### 22.2 Provenance correctness

- Runtime can create content-free response artifacts with source/origin/parents/labels.
- Derived labels are monotonic.
- The exposed-context frontier is concurrency-safe and causally ordered.
- No agent/tool argument can directly clear or rewrite protected provenance state.
- No declassification is claimed.

### 22.3 MCP end-to-end protection

- Released MCP output is tracked as `TOOL_OUTPUT` + `UNTRUSTED_CONTENT` plus explicit labels.
- A later MCP action carries the current trusted provenance snapshot into policy.
- Static sink category is trusted adapter config, not inferred from untrusted text.
- Secret/PII-labeled tracked data can be blocked from an `external` sink.
- Untrusted tool output can be blocked from a `memory` sink.
- A response withheld by ENFORCE response validation is not treated as exposed/tainting.
- SHADOW forwards while retaining the real would-block decision and evidence.

### 22.4 Exact action/evidence binding

- Data destination/provenance that affects policy is bound into the full policy-input digest.
- Approval/action digest changes when relevant data-flow context changes.
- Evidence distinguishes returned from exposed data.
- Critical exposure evidence failure does not result in an unrecorded ENFORCE release.

### 22.5 Coverage and conformance truthfulness

- Data atoms no longer appear as generic unsupported Phase 3 gaps.
- Adapter coverage states source/sink assumptions explicitly.
- Generated flow cases are non-circular and non-vacuous.
- Coverage does not imply content detection or model-internal taint.
- Plan/proof freshness protections from Phase 3 remain intact.

### 22.6 Semantic diff

- Data-rule tightening/relaxation is behaviorally visible over the finite exact set-based policy space.
- Explanation/rule-ID-only changes remain visible.
- Data-flow restriction change is distinguished from ordinary tool authority change.

### 22.7 Quality and phase discipline

- all existing tests pass;
- focused new tests cover the security boundary without excessive duplication;
- lint/format/type/schema/examples/build checks pass in the available environment;
- no required network, model API, real credential, or cloud dependency is introduced;
- public schemas/docs reflect actual code;
- Phase 5 replay/incidents and later identity/adapters are not pulled in;
- implementation report records exact commands/results, deviations, known limitations, and Phase 5 readiness.

---

## 23. High-risk implementation mistakes to avoid

Treat these as explicit implementation and review targets.

1. **Unsound value taint:** searching arguments for a prior response string/hash and calling that complete provenance.
2. **Data policy grants authority:** an allowed destination/capability bypasses default/tool deny or task scope.
3. **Missing destination treated as safe:** destination-constrained rule sees `None` and silently permits the call.
4. **Returned equals exposed:** an ENFORCE-blocked response pollutes future taint even though the agent never received it.
5. **Exposure without evidence:** ENFORCE returns a response after the critical exposure record failed.
6. **Agent-controlled relabeling:** tool arguments can claim “PUBLIC” or clear `SECRET` without trusted security code.
7. **Silent source classification:** existing `data_access_labels` is reinterpreted as precise response labels without an explicit compatibility decision.
8. **Unreviewed output treated as clean:** missing source-label declaration becomes equivalent to an explicit empty declaration.
9. **Stale adapter proof:** changing output labels/sink categories does not invalidate Phase 3 discovery proof.
10. **Approval context gap:** approval digest omits provenance/destination even though policy depends on them.
11. **Concurrency under-taint:** a request that starts after a secret response was exposed sees an older frontier.
12. **Concurrency over-causality bug:** a request already authorized before exposure is retroactively changed by unrelated later data.
13. **Taint can decrease:** a transform silently removes SECRET/PII/UNTRUSTED labels.
14. **Vacuous flow conformance:** sink case passes because base tool policy denied it anyway.
15. **Data diff remains unsupported:** contract diff says a data-rule change is merely “unsupported” after runtime enforces it.
16. **Coverage overclaim:** report says “secret exfiltration protected” when it only tracks labeled MCP tool outputs and not arbitrary user/model text.
17. **Raw-content regression:** provenance/evidence starts persisting tool response bodies or full prompts by default.
18. **MCP leakage into core:** compiler/provenance/domain imports MCP SDK/config types.
19. **Phase 3 regression:** exact plan identity, reason/matched-rule conformance, or snapshot-bound adapter proof is weakened.
20. **Unbounded graph growth ignored:** runtime stores redundant full histories per request rather than a bounded/frontier representation where possible.

---

## 24. Documentation updates required during implementation

At minimum review/update:

- `docs/architecture.md` — concrete Phase 4 engine and returned-vs-exposed boundary;
- new focused `docs/provenance-data-flow.md` (or equivalent);
- `docs/security-contract.md` — executable `DataRule` semantics;
- `docs/evidence-model.md` — artifact/exposure evidence semantics;
- `docs/runtime-mcp.md` — ambient taint, binding fields, source/sink coverage, mode behavior;
- `docs/contract-conformance.md` — flow probes/coverage/diff;
- `AGENTS.md` — active phase boundary and protected Phase 4 invariants;
- README/examples only where they improve discoverability;
- `docs/reports/phase-4-implementation-report.md`.

Do not rewrite the PRD merely to rationalize implementation choices. Amend it only if a genuine product-level contradiction is discovered.

---

## 25. Independent review expectations

The independent Phase 4 review must use this plan as **one input, not the ceiling of the review**.

The reviewer should first derive intended Phase 4 behavior from:

1. PRD/product thesis;
2. architecture/trust boundaries;
3. focused current docs;
4. Phase 3 review fixes and actual current code;
5. the Phase 4 implementation itself.

Then review both implementation **and this plan’s assumptions**.

The reviewer must explicitly ask:

- Did the plan choose a sound tracked-provenance boundary, or did implementation reveal a missing class of bypass?
- Can any untrusted/agent-controlled input forge, erase, reorder, or relabel provenance?
- Are source/sink declarations actually sufficient to support the security claims?
- Is ambient MCP taint causally correct under async concurrency?
- Can a blocked response become taint, or an exposed response fail to become taint?
- Can data rules ever expand ordinary authority?
- Can a missing destination/source classification fail open?
- Does approval bind exactly the security context that was reviewed?
- Are flow conformance expectations independent and non-vacuous?
- Does coverage distinguish tracked data from semantic content detection?
- Did Phase 4 weaken any Phase 0–3 boundary, especially the Phase 3 plan/snapshot identity fixes?
- Are there security flaws or requirements the Phase 4 plan failed to anticipate?

A separate Sol High review prompt should instruct a fresh reviewer to search beyond the plan and produce a self-contained findings/fix handoff for a fresh Luna XHigh implementation session.

---

## 26. Phase 5 handoff boundary

Phase 4 should leave enough factual evidence for Phase 5 replay without implementing replay now.

After Phase 4, Phase 5 should be able to reconstruct a tracked sequence such as:

```text
MCP source returned artifact A
A passed response guard and was exposed
A (or a derived descendant) was active for later request R
flow policy denied/allowed R at sink S
R was or was not dispatched
```

Phase 5 can then package artifacts/events/config identities into replay bundles and regressions.

Phase 4 should **not** create incident objects, replay manifests, deterministic tool substitution, or “promote to regression” commands. Its job is to make the provenance/evidence trustworthy enough that those later workflows have a sound foundation.
