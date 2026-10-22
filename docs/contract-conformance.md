# Executable contract conformance (current compiler: phase6-v1)

One validated contract compiles into an immutable native exact-match plan. Compilation owns
normalization and the unsupported inventory. Native policy owns execution. The probe oracle
independently states obligations from compiled facts and the explicit DENY > REQUIRE_APPROVAL >
ALLOW > DEFAULT_DENY table. Task scope always limits authority.

```bash
agentsec contract compile examples/mcp/contract.yaml
agentsec contract test examples/mcp/contract.yaml --format json
agentsec contract coverage examples/mcp/contract.yaml
agentsec contract coverage examples/mcp/contract.yaml --run
agentsec contract diff examples/mcp/contract.yaml examples/mcp/contract.yaml
```

All four commands support `--format text|json`. JSON uses canonical ordering. Text uses stable
summaries. `test` exits 0 for passing generated cases, 1 for failed conformance, 4 for execution
errors (ERROR takes precedence). CLI usage errors use 2; existing input-validation errors use 1.
Inspection and diff exit 0 on a valid report, including a report containing gaps or expansions.
No command activates policy, calls a tool/model or uses credentials. An unsupported contract can
pass its generated supported obligations: inspect coverage before interpreting a PASS.

## Compiled meaning

The versioned plan contains contract/schema/compiler identity, effective policy hash, protected
principal/agent/environment, exact rules with original IDs, immutable task ceiling, supported
budget configuration and approval timeout. Source paths identify rules as `tools.rules/RULE_ID`.
Agent binding includes only ID, environment, owner and trust level. Agent name, framework,
provider/model metadata and task description are document context; they cannot change native
request validity or compiled meaning. Canonical request objects use fixed descriptive placeholders.
Runtime request/action protection comes from the plan, including principal, agent and task identity.
Configured unsupported semantics are individual atoms with intent digests; they are never
reported as compiled/enforced. Mutable budget/approval state is absent from this artifact.

`compile` exposes authored policy values, including exact resources; handle its output like the
source contract. The other reports contain IDs, semantic digests, outcomes and status, not runtime
argument/response content. The JSON schemas are exported from the public Pydantic definitions.
Compiled manifests are inspection artifacts, not a trusted activation format. Runtime checks any
supplied plan against its own compilation, including contract ID and effective policy identity.
Compiler `phase6-v1` is current and supersedes earlier Phase 3–5 manifests; regenerate earlier
manifests/reports. Historical replay keeps the exact recorded `phase4-v1` meaning.
Additive schema 0.1 extensions require updated strict consumers and action digests. Conformance and coverage reports
require `plan_identity`: contract ID, compiler version, effective policy hash and
`compiled_plan_digest`. The latter hashes canonical complete compiled content (including compiler
identity and unsupported inventory), without a self-referential digest field. It is freshness
identity, not signing or authenticity, and does not replace `effective_policy_hash`.
Coverage rejects results from another exact plan. The eval target requires the supplied plan to
equal a fresh compilation before invoking the evaluator.

## Generated obligations and coverage

The generator uses capabilities referenced by rules/scope, each capability's exact resources,
`None`, a collision-free other-resource sentinel, and a collision-free unknown capability.
This compact partition exercises exact rules, overlaps, default deny and task exclusions.
A protected task ceiling may make a rule or default-deny branch unreachable; coverage then
leaves that atom without generated tests. A shadowed rule may participate in an overlap probe;
coverage means represented in a checked obligation, not independently influential on its outcome.
Both direct and eval execution require the exact reason-code and matched-rule sets, including
shadowed rules; extra reasons and missing provenance fail. Scope-excluded/default-denied requests
have no matched rules.

Each coverage row separates compiled intent, runtime support, adapter requirement/proof,
source/sink classification completeness, source/sink runtime reachability, generated probe IDs,
generated evaluation IDs and execution status. Runtime reachability is a topology witness, not
evidence that the MCP path was executed. Without `--run`, execution is NOT_RUN. Budget/timeout atoms are runtime-supported but have no generated policy cases;
stateful behavior remains verified by the runtime tests. Grouped identity and task-scope atoms
also have no generated IDs and stay NOT_RUN: valid requests do not establish mismatch enforcement.
The finite partition still exercises task capability/resource exclusions, but does not claim full
scope consistency coverage. Dedicated manual runtime/policy tests remain separate evidence.
Unsupported atoms have no tests.
An offline command has no discovery proof: adapter requirements remain UNPROVEN. The MCP adapter
can supply COVERED/UNCOVERED proof from discovered bindings; no applicable tool leaves it unproven.
Adapter proof is a typed, versioned result bound to the exact plan and a digest of the discovery
snapshot (wire metadata, descriptors and bindings, sorted by tool name). To compose it, pass the
current registry's `discovery_snapshot_digest` to `coverage_report`; missing or mismatching snapshot
identity and stale plans raise `STALE_ADAPTER_PROOF`. Snapshot/plan digests identify content, not
trusted attestations. No applicable tool yields no atom proof. There is no generic security percentage.

The evaluation bridge uses the native evaluator's actual decision to emit canonical evidence;
Phase 1 causality/assertions check it. Approval cases contain a matching request and exact bound
approval before synthetic dispatch. Missing/contradictory evidence and wrong outcomes fail or
error. The synthetic approver is a deterministic local test actor, not approver authentication.
Generated conformance is not model robustness or a prompt-injection evaluation.

## Semantic diff boundary

Diff evaluates both compiled plans over the union of referenced capabilities/resources, scope
resources, `None`, one OTHER resource per capability and an unknown capability. It includes
resource exceptions beneath broad rules and the remaining default space. Request identity/scope
is adapted to each protected plan; identity/environment and scope configuration changes are
reported separately. Authority is ordered DENY < REQUIRE_APPROVAL < ALLOW, so approval-to-allow
is an expansion and allow-to-approval a reduction; both also flag approval-boundary changes.
Scope widening/narrowing is reported even when rules still deny the representative action.
`policy_explanation_change` records exact before/after reason-code and matched-rule sets, even
when outcomes stay equal. Rule renames and explicit-to-default deny transitions therefore remain
visible without being classified as authority expansion or reduction.

Supported budget changes treat an absent limit as unbounded. Approval timeout changes are
reported without asserting a universal safety ordering. Unsupported intent changes are detected
by atom digests and labeled unsupported; their behavior is not simulated. Representative resource
values are digested; capability names remain visible. This is finite comparison of the native
subset, not formal equivalence, arbitrary argument analysis, deployment or general data policy.
Full OAuth/OIDC lifecycle services remain out of scope. Phase 7 adapters reuse this compiler. Current
Phase 6 identity conformance uses trusted synthetic authority facts and is described below.


## Phase 4 flow obligations, proof and diff

Data atoms compile into runtime-supported adapter-required rules. Independent set-based flow
obligations use base ALLOW/REQUIRE_APPROVAL witnesses and verify exact reasons/matched IDs for
each configured capability/destination restriction, missing context, inherited source labels,
and multiple-label any-deny-wins. An unreachable axis becomes NOT_RUN with an explicit reason;
ordinary denial cannot pass it vacuously. Direct probes may use trusted synthetic refs. The Phase 1
bridge emits a labeled source return and DATA_EXPOSED event before the later sink request.
Trajectory validation reconstructs request-time frontiers and verifies returned lineage and label
inheritance; separate MCP/runtime tests verify actual guarded exposure and concurrent trajectories.
Generated checks make no model-robustness,
classifier or complete context-capture claim.

Coverage separates required provenance, source/sink classification requirements and proof
statuses, source/sink runtime reachability, generated obligation/eval IDs, execution status, and
the tracked-data adapter boundary. `adapter_status=COVERED` means classification and required
reachability are complete; it does not mean a real runtime flow was exercised.
Absent discovery remains UNPROVEN. Changed source/sink binding fields invalidate snapshot proof.
Pure data-policy diff invokes the native evaluator with an equal synthetic base grant across
finite exact labels/capabilities/destinations, missing destination and collision-free OTHERs.
It separates data tightening/relaxation, exact explanations and authored set changes from ordinary
authority changes. See [provenance/data flow](provenance-data-flow.md) for the full comparison and
trusted-input boundary. No generic security percentage or formal equivalence is claimed.

## Phase 5 offline lifecycle

See [replay and incidents](replay-incidents.md) for strict evidence bundles, exact versus legacy
source plan binding, offline substituted security replay, semantic trace diff, evidence-backed
classification, safe assertion promotion and the local/CI regression gate. Historical evidence
remains immutable; missing or redacted material is never reconstructed. This does not extend
model/context coverage or authorize any live execution.


## Phase 6 authority probes

Current compilation emits `phase6-v1`; historical replay retains `phase4-v1`. Trusted synthetic
authority fixtures exercise direct/OBO behavior, missing direct authority, missing or mismatched
delegation, expiry, credential capability ceilings and delegated capability/resource narrowing.
Existing rule, approval and data-flow obligations use valid synthetic authority, preserving deny
precedence.
The authority layer is shared with runtime/replay. These probes authenticate no external workload.
`identity.authority` is separately covered; grouped identity/task atoms remain unclaimed.
Authored OBO changes and compiler semantic changes appear explicitly in semantic diff.
See [identity and delegation](identity-delegation.md).

## Phase 7 adapter integration

See [adapters/isolation](adapters-isolation.md). New protected calls bind execution-route identity
to exact actions and record safe route facts on dispatch. Absent fields preserve old serialization;
offline replay substitutes these facts without live execution. Generic schema, argument and
resource/data coverage checks are shared with MCP. Compiler and authored hashes are unchanged.

## Phase 8 trust composition

The optional operator-owned supply-chain guard restricts protected implementations through
RuntimeGateway; it never grants contract or delegated authority. Metadata pins and Ed25519
signatures do not attest runtime code. Existing approval, evidence, provenance, TLS and isolation
boundaries remain active. See [supply-chain trust](supply-chain-trust.md) for exact mode behavior,
route identities, offline replay limits and commands. Independent Phase 7 acceptance is still
unconfirmed; Phase 8 implementation is awaiting independent review.


## Phase 9 local graph composition

Explicit `phase9-v1` operator-created ENFORCE sessions now add bounded single-parent graphs,
all-ancestor authority/approval/data ceilings, atomic recursive budgets and protected adjacent
messages. Standalone `phase6-v1` behavior and historical digests retain their existing meaning.
The gateway guard applies to direct calls and adapter rebinding. Phase 8 pins restrict tools;
they do not authenticate peers or approve delegation. See [local multi-agent security](multi-agent-security.md)
for ownership, evidence-before-import, finality, source replay blockers, DRAFT graph promotion,
unsupported modes and exact limitations. Earlier one-hop/future-graph statements describe their
original phase boundary. Independent Phase 7–8 acceptance remains unconfirmed.
