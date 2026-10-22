# Offline incident replay and regression (Phase 5)

Replay re-executes structured security transitions. It never reproduces model reasoning or
calls a tool, subprocess, provider, MCP server, or network adapter. `replay.engine` has no
execution port: its only tool results are typed metadata events from its input program.
A substituted dispatch means a simulated dispatch opportunity, never a verified external effect.

## Workflow

The public fixture deliberately permits a synthetic send while an explicit scenario assertion
requires that send to remain undispatched. A separately authored current contract denies it.
All files contain synthetic data. From the repository root:

```bash
agentsec replay bundle create \
  --evidence examples/replay/source.jsonl \
  --contract examples/replay/source-contract.json \
  --scenario examples/replay/scenario.json --out /tmp/demo-bundle.json
agentsec incident classify --bundle /tmp/demo-bundle.json --out /tmp/demo-incident.json
agentsec replay run --bundle /tmp/demo-bundle.json
agentsec replay run --bundle /tmp/demo-bundle.json \
  --contract examples/replay/current-contract.json
agentsec incident promote --bundle /tmp/demo-bundle.json \
  --incident /tmp/demo-incident.json \
  --contract examples/replay/current-contract.json --out /tmp/demo-regression.json
agentsec regression validate --root examples/regressions
agentsec regression run --root examples/regressions
```

Every Phase 5 command emits deterministic JSON. Output files must not exist; parent directories
must exist. This protects inputs and prior outputs, including symlink/hardlink collisions.
Use a new output name for repeated commands. Successful replay exits 0 even for semantic drift;
only explicit assertions establish expected direction. Incomplete replay exits 3. Validation,
integrity and path failures exit 4 without echoing untrusted payloads. Typer usage errors exit 2.
A failing/errored ACTIVE regression exits 1; an empty corpus is invalid (4). DRAFT cases are
reported individually. A corpus with only drafts exits 3; a corpus with passing ACTIVE cases
and explicitly reported drafts exits 0. CI runs this same regression command alongside all
previous quality gates. All JSON manifests under the selected root are parsed and validated;
malformed ACTIVE cases cannot be silently skipped.

`--scenario` supplies operator-reviewed tool classifications and explicit assertions, not task
text as authority. `--report` optionally supplies canonical findings from an evaluation report;
its run/trace/contract/policy identities and finding references must match the source. Findings'
free-form descriptions are minimized before packaging. The Python builder also accepts typed
findings and expectations. Resource/task/argument text and raw canary values are never fetched
to improve fidelity. Canary assertions lacking their original capture produce a typed blocker.

## Integrity and identity

A bundle is a strict, versioned JSON document containing source events, contract, freshly compiled
source plan, operator-supplied tool metadata, explicit expectations, findings, and assessment.
The evidence digest covers the entire ordered canonical event sequence. The bundle digest covers
all bundle fields except itself, including evidence, contract, plan, findings and assessment.
Creation and every execution revalidate sequence uniqueness, single run/trace, trajectory,
approval links/expiry/redemption, return/exposure causality, provenance frontiers, source contract
and policy hash, and any complete policy-input digest. Load/execution recomputes the assessment
and captured plan as well as the digests. Recomputed checksums cannot hide inconsistent identities.

Digests detect corruption relative to an expected digest; they are **not authentication**. An
attacker who can replace a whole bundle and its trusted digest can fabricate a new history.
Protect source storage and regression manifests outside ordinary agent write authority.

New native runtime RUN_STARTED events add optional `plan_identity` (contract ID, compiler
version, effective policy hash, compiled-plan digest). `EXACT` means the supplied source plan
matches that recorded identity, not a signature or attestation. Legacy events remain readable
and use `LEGACY_INFERRED`: a later compilation is not proof of historical runtime identity.
For those results, `source_identity` is null; the compiled bundle source plan is only an
interpretation of the supplied contract. Legacy non-approval policy replay remains available,
but approval-dependent replay is blocked with `APPROVAL_SOURCE_PLAN_UNBOUND` and is INCOMPLETE.
The scripted fixture producer stays legacy because it deliberately does not execute native
policy. For this historical Phase 5 fixture-producer path, compiler semantics/version remain
`phase4-v1`; current identity and delegation replay uses `phase6-v1`. Public artifact schema versions remain
`0.1` under the existing additive pre-1.0 convention; strict older readers need refreshed schemas.

A replay result records source bundle digest, the recorded source plan identity when known,
current plan identity, separate replay identity, deterministic events, substituted dispatch IDs,
findings, assertion outcomes and diff.
Source input is never changed. Derived replay envelope and decision IDs are deterministic and
separate from the source; source request/approval/dispatch/artifact IDs are retained as script
correlation references, scoped by the new run/trace. Full-action hashes remain historical action
commitments, not newly authenticated candidate actions or reusable live approval grants.

## Fidelity and causality

`POLICY` means structured authorization inputs are reconstructible but tool metadata for runtime
counters is missing. `SECURITY_RUNTIME` additionally evaluates count budgets, approval scripts and
tracked provenance against substituted return/exposure metadata. It does not validate raw response
schemas or rerun detectors. Tool classifications are operator assertions; exact historical tool
schema/description bytes cannot be recovered from action digests. `BLOCKED` carries stable blockers.

The replay clock follows source timestamps and is injected into the native policy/approval
components. Counter IDs and budget reservation IDs use deterministic factories. One BudgetLedger
covers the entire program; reservations cover outstanding approvals, and each retry dispatch is
charged. ApprovalLedger preserves exact action commitment, expiry, denial and one-shot redemption.
A historical approval is usable only under the identical compiled plan and identical request
context, and only when source binding is `EXACT`; changed policy or provenance yields
`APPROVAL_BINDING_UNAVAILABLE`. Missing approval scripts/pending approvals remain explicit.
Native policy is the only authority interpretation.

Replay currently does not execute SHADOW or DISABLED source dispatches. Truthful source events in
those modes are checked for lifecycle causality and produce the `UNSUPPORTED_SOURCE_ENFORCEMENT_MODE`
blocker, making the comparison INCOMPLETE. Malformed dispatch/return/exposure links still fail as
`INVALID_TRAJECTORY`; source mode is never rewritten to ENFORCE.

Requests snapshot the replay frontier when requested, independently of when their decisions or
responses arrive. ProvenanceEngine registers monotonic returned refs and commits only scripted
DATA_EXPOSED events. Returned but withheld data never enters the frontier. Transport/no-return
paths create no response. Concurrent siblings preserve the source order and independent snapshots.
Changed request context cannot reuse the historical action commitment
(`ACTION_CONTEXT_BINDING_UNAVAILABLE`). If a substitute response has different parents, source
metadata cannot separate inherited
from explicitly configured labels; replay reports `CHANGED_PROVENANCE_SUBSTITUTE` rather than
inventing a new label set. Newly permitted dispatches without a source result are visibly
`MISSING_SUBSTITUTE_RESULT`. Neither missing results nor hash-only bodies are guessed.

Material redaction blocks execution. Unsupported compiled intent and missing monotonic duration
for runtime-second budgets also block execution. Wall timestamps cannot prove a runtime monotonic
clock. Source signals and terminations are explicitly substituted source observations, not
recomputed detector/termination results. Source EFFECT_VERIFIED facts are never emitted as replay
external effects. These cases make the full comparison INCOMPLETE while retaining observed
changes. Complete scripted dispatch evidence can still decisively score supported dispatch/count
assertions even when unrelated detector/content comparison is incomplete. No whole-model branching,
initial-user context tracking, semantic content detection, live side effects or model robustness
claim is made.

## Semantic diff and classification

Projection preserves event ordering and normalized causal links, request identity/authority,
resource/destination/provenance, outcomes/reasons/matched rules, approvals, dispatch/return/exposure,
labels/lineage, security signals, terminal reason, and assertion/finding outcomes. It excludes
envelope IDs/timestamps and normalizes request/decision/approval/dispatch/artifact reference IDs
by namespace. Absolute approval timestamps are excluded while the approval timeout duration
remains semantic. Policy identities, response and full-action commitments remain significant.
Opaque hashes cannot explain whether changed underlying content was purely cosmetic. Projection
never interprets free-form descriptions as policy. Missing/extra facts and order changes produce
indexed differences; INCOMPLETE is distinct from UNCHANGED. A change alone has no good/bad rank.

Classification uses canonical signal categories and their exact severities, canonical finding
categories/references and their exact severities,
explicit DATA_FLOW_DENIED/OUTSIDE_TASK_SCOPE/BUDGET_EXCEEDED indicators, and deterministic failures
of TOOL_NOT_CALLED/MAX_TOOL_CALLS/APPROVAL_REQUIRED assertions. Each basis records a stable rule
and source event/finding/assertion references. Operator category selection is recorded separately
as OPERATOR_SUPPLIED. Multiple supported categories remain present. A blocked flow indicator is
classified as POLICY_BYPASS investigation evidence, not proof of successful exfiltration.
Reason-code, assertion and operator bases have unknown severity (`null`); incident severity is not
aggregated and no missing severity is inferred.
No free-form tool/model text, finding description or signal summary selects a category.

## Promotion and privacy

Promotion validates the incident against deterministic classification, preserving source incident,
bundle and evidence identities. It reuses existing assertion semantics. ACTIVE requires explicit
TOOL_NOT_CALLED, MAX_TOOL_CALLS or APPROVAL_REQUIRED expectations and sufficient replay inputs.
An optional candidate contract is compiled and captured separately from the source plan. Without
it, a case tests the source plan and may intentionally fail. No contract is edited or generated
as remediation. Stable IDs derive from source incident and explicit expectations.

An ACTIVE manifest contains a **derived, minimized replay program**, not a byte-for-byte copy of
the source bundle. It strips arguments summaries, agent prose, approval/signal/decision prose,
findings' raw content, and tool descriptions/schemas. Schemas are unnecessary for budget metadata
substitution; response validation is not claimed. Source commitments remain as provenance links,
not assertions that sanitized bytes equal the source evidence. Meaningful resource/task values
cannot safely be removed or replaced, so such cases produce DRAFT without an embedded program
or plan. Unknown/unsupported expectations also produce DRAFT with a stable reason. These conservative
rules avoid exporting source canaries or guessing a remediation. Structured IDs, configured labels,
static destinations, principals and rule metadata are trusted configuration; never put secrets
in those identity fields. Hashes reveal equality and do not encrypt data.

This section records the historical Phase 5 readiness state. Phase 6 identity/delegation is now
implemented; its current semantics and review-fix status are recorded in the focused identity
documentation and implementation reports.


## Phase 6 verified authority facts

Bundles retain historical `phase4-v1` source identities and meanings while candidate compilation
uses `phase6-v1`. Historical-to-current replay without recorded verified authority is explicitly
INCOMPLETE / MISSING_AUTHORITY_CONTEXT; promotion with such a candidate remains DRAFT.
Replay never obtains a bearer token or calls an identity verifier. It uses canonical authority
facts at recorded timestamps and rechecks freshness at dispatch, including approval waits.
Resource-bearing grant evidence is redacted with an authority digest. An explicitly supplied
`replay bundle create --authority PATH` artifact must match that digest; remaining resource/task
redactions stay material blockers. Session authority commitments and unchanged request/authority
bindings protect historical approval replay. See [identity and delegation](identity-delegation.md).

## Phase 7 adapter integration

See [adapters/isolation](adapters-isolation.md). `diff.status` reports policy/evidence trace
substitution only. Candidate route fidelity is separate in `ReplayResult.route_comparison`: it is
`UNKNOWN` if no candidate route manifest is supplied, `UNCHANGED` only when all recorded route
identities are present, `CHANGED` when an observed source route is absent from the candidate, and
`INCOMPLETE` when source or candidate route facts are missing. Historical Phase 5/6 dispatches
without route facts remain readable and cannot establish route equivalence.

See [adapters/isolation](adapters-isolation.md). New protected calls bind execution-route identity
to exact actions and record safe route facts on dispatch. Absent fields preserve old serialization;
offline replay substitutes these facts without live execution. Generic schema, argument and
resource/data coverage checks are shared with MCP. Compiler and authored hashes are unchanged.

## Phase 8 trust composition

The optional operator-owned supply-chain guard restricts protected implementations through
RuntimeGateway; it never grants contract or delegated authority. Metadata pins and Ed25519
signatures do not attest runtime code. Captured inventory equality does not prove that the observed
set contains every deployment-required candidate; locks express that separately through optional
required-presence IDs. Replay remains offline and does not attest process startup or endpoint
contact. See [supply-chain trust](supply-chain-trust.md) for exact mode behavior and proof limits.
Independent Phase 7 acceptance is still unconfirmed.


## Phase 9 local graph composition

Explicit `phase9-v1` operator-created ENFORCE sessions now add bounded single-parent graphs,
all-ancestor authority/approval/data ceilings, atomic recursive budgets and protected adjacent
messages. Standalone `phase6-v1` behavior and historical digests retain their existing meaning.
The gateway guard applies to direct calls and adapter rebinding. Phase 8 pins restrict tools;
they do not authenticate peers or approve delegation. See [local multi-agent security](multi-agent-security.md)
for ownership, evidence-before-import, finality, source replay blockers, DRAFT graph promotion,
unsupported modes and exact limitations. Earlier one-hop/future-graph statements describe their
original phase boundary. Independent Phase 7–8 acceptance remains unconfirmed.
