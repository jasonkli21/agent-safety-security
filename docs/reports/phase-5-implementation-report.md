# Phase 5 implementation report

## Baseline and final implementation commit

Baseline: `be727ecf6aacc144a96cb6ceb2c9db7eaf1d918c` (`fix: address phase 4 review findings`).
HEAD matched the plan's inspected baseline. No tracked user changes existed. The supplied
Phase 5 implementation plan and unrelated `PHASE-0-SOL-MEDIUM-PROMPT.md` were untracked.
The implementation includes the Phase 5 plan, with trailing Markdown whitespace normalized;
the unrelated prompt remains untouched and excluded from the commit.

The user explicitly requested Phase 5 implementation according to the attached prompt and one
commit. The attachment was treated as the requested task specification, not independent authority
to override higher-priority instructions. Phase 4 review fixes already exist in the baseline;
the supplied implementation-ready Phase 5 plan and explicit request resolve the stale Phase 4
boundary text. No independent approval of Phase 5 is inferred. The final implementation revision
is the single feature commit containing this report; its own SHA cannot be embedded in this
file without changing that SHA. Resolve it with
`git log -1 --format=%H -- docs/reports/phase-5-implementation-report.md`.

## Scope implemented

Strict versioned incident, classification basis, replay assessment/program/bundle/result,
semantic trace fact/diff and regression manifest models; five generated public artifact schemas;
JSONL-to-bundle integrity and trajectory validation; offline native policy/approval/count-budget/
provenance replay; semantic diff of events and assertion/finding outcomes; evidence-backed
classification; conservative promotion; Typer commands; public source/candidate/fixture/corpus;
CI regression gate; focused docs and repository phase-state update. No dependency was added.
The source-evidence reader gains an optional aggregate byte limit, retaining existing callers'
behavior. Source JSONL and bundle sizes are bounded to the existing 1 MiB artifact limit for
replay workflows. Source JSONL is included in source distributions.

## Replay fidelity: guarantees and non-guarantees

The engine has no live execution port and imports no MCP/upstream adapter. NativePolicyEngine
is the only policy interpretation. ApprovalLedger, BudgetLedger and ProvenanceEngine are reused.
Native decision and budget reservation IDs now accept injected factories; runtime defaults are
unchanged. Source event timestamps drive an injected deterministic clock. One ledger spans the
whole script, reservations account for outstanding approvals, and retries charge separately.
Request snapshots remain request-time facts even with concurrent decisions/returns. Returned
but withheld data is never exposed, and transport failure never manufactures a response.

POLICY fidelity lacks runtime tool metadata; SECURITY_RUNTIME adds operator-classified tool
metadata for counters plus scripted approval/provenance/return transitions. Every result also
reports limitations and blockers. These levels do not claim raw-response schema revalidation,
model/token reproduction, detector execution, complete model-internal taint or external effects.
Source EFFECT_VERIFIED events are omitted from replay output with explicit comparison limits;
`external_effects_performed` is constrained to false. Source signals/termination are explicitly
substituted and make their full comparison incomplete. Complete structured dispatch trajectories
can still score relevant count/dispatch assertions without claiming detector/content completeness.

Changed authority can be evaluated, including ALLOW→DENY and DENY→ALLOW. A newly permitted path
without a return substitute remains incomplete. Historical approval commitment reuse requires
identical compiled policy and request context. Changed causal request context cannot reuse a
historical action commitment. A response with changed parents cannot be relabeled by guessing
which source labels were inherited. Missing/redacted policy inputs, missing/pending approval
scripts, unsupported compiled intent, and absent monotonic runtime duration produce stable
blockers. Wall timestamps are not substituted for the runtime monotonic clock.

## Source/current identity and integrity

The source event digest covers the complete ordered canonical event sequence. The bundle digest
excludes only itself and includes source identity, contract, compiled plan, events, tool metadata,
expectations, canonical findings and assessment. Execution reparses input, checks both digests,
recompiles the source contract, recomputes the assessment and checks all bindings. Mixed run/trace
streams, invalid trajectories and policy-input digests fail visibly. Source and candidate plans
remain separate in replay results and promoted manifests. Derived replay envelope/decision IDs
are deterministic and separate; source lifecycle IDs remain script correlation references within
a distinct replay run/trace. Digests establish content identity, never authenticity or signatures.

Native runtime RUN_STARTED additively records `plan_identity`: contract, compiler, policy hash
and compiled-plan digest. EXACT means agreement with that recorded identity, not an attestation.
Legacy traces, including the scripted public fixture producer, remain LEGACY_INFERRED. A later
compilation is never historical proof. Compiler semantics/version stay `phase4-v1`; public schemas
retain additive pre-1.0 `0.1`. Existing strict consumers need regenerated event schemas.

## Privacy and redaction

No raw tool response is stored or reconstructed. Material resource/task redaction blocks replay.
The bundle preserves structured source evidence and protected contract inputs; it is sensitive
storage, not automatically scrubbed arbitrary data. Optional canonical findings lose free-form
text before packaging. CLI validation errors print stable codes without untrusted values.
Outputs use exclusive creation, protecting source/output paths and existing symlinks/hardlinks.

Promotion creates minimized derived material: no source contract prose, argument summaries,
agent display/model prose, signal/decision/approval prose, finding descriptions or tool schema/
description text. Meaningful resource/task values require review and yield DRAFT without embedded
plan/program. Trusted IDs, principals, configured labels/static destinations and rule metadata
must not contain secrets. Hashes expose equality. Canary tests prove source argument/finding
text is absent from generated material; no general semantic secret detector is claimed.

## Incident classification

Canonical signals, canonical findings, explicit control reason codes and deterministic assertion
failures produce inspectable classification bases with event/finding/assertion references.
Operator selection is separately OPERATOR_SUPPLIED. Multiple supported categories are preserved.
Blocked-flow evidence is an investigation indicator, not proof of successful exfiltration.
No arbitrary tool/model/summary/description text selects a category. Promotion recomputes and
validates classification rather than trusting an edited incident's category list.

## Promotion semantics

Existing TOOL_NOT_CALLED, MAX_TOOL_CALLS and APPROVAL_REQUIRED assertions can become ACTIVE
expectations when their inputs are sufficient. Missing or unsupported expectations, material
resources/scopes, redaction and other replay blockers yield DRAFT with a stable reason. IDs
are stable for the source incident/expectations. An optional explicitly supplied candidate
contract is compiled separately; no source contract is changed and no remediation rule is authored.
Without a candidate, a manifest tests the source plan and can intentionally fail. Promoted event
programs are derived/minimized material with original evidence/bundle commitments retained as
provenance, not claims that sanitized bytes are identical to source evidence.

## CI integration and public corpus

CI preserves every previous gate and adds
`agentsec regression run --root examples/regressions`. Every JSON manifest under the root is
parsed/validated; malformed ACTIVE cases cannot silently skip. ACTIVE failure/error exits 1,
validation errors exit 4, and DRAFT-only corpora exit 3. DRAFT entries are reported individually.
The public corpus has one passing ACTIVE blocked-send case and one DRAFT requiring expectations.
The public example includes immutable source JSONL, source/candidate contracts, scenario, fixture,
bundle and incident. A focused integration proves the full evidence→bundle→classification→replay→
diff→promotion→regression chain fails before a separately supplied deny policy and passes after it.

## Deliberate deviations and rationale

- Use existing typed canonical event payloads as the ordered replay action/approval/result script,
  avoiding a duplicate lifecycle grammar and preserving overlapping source ordering.
- Use one `plan_identity` object on start events instead of three parallel optional scalar fields.
  Scripted evaluation does not receive an exact native execution binding it cannot prove.
- Require explicit existing safe assertions for automatic ACTIVE promotion. Classifications alone
  do not establish a unique remediation. Unsupported/unsafe exports become DRAFT.
- Export a strict self-contained regression manifest with a minimized program and separate
  source/candidate compiled plans rather than a generated Scenario/fixture pair containing raw
  source material. Assertion semantics still call the existing evaluation implementation.
- Monotonic-duration budgets, new paths with no results, changed action/provenance commitments,
  detector signals and external verifier effects degrade explicitly instead of fabricated fidelity.
- Commands emit deterministic JSON by default; a separate `--format json` option is unnecessary.
  Replay semantic drift alone does not exit as regression failure; explicit assertions govern gates.

These are conservative representations of insufficient evidence, not future-phase scaffolding.
No PRD change, hosted service, identity/delegation framework, policy language or live replay was added.

## Verification

All commands used the repository `.venv`, without network/model credentials. The default pytest
fixture forbids network connections. Development failures were corrected before the final runs;
the following table records final results, not intermediate failing iterations.

| Exact command | Result |
| --- | --- |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 130 files formatted |
| `.venv/bin/mypy src` | PASS, 80 source files |
| `.venv/bin/pytest -q tests/unit/test_replay.py` | PASS, 38 tests |
| `.venv/bin/pytest -q` | PASS, 591 tests |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts and 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS, all 6 expected outcomes |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS, generated schemas refreshed; freshness tests pass |
| `.venv/bin/agentsec regression validate --root examples/regressions` | PASS, 2 validated manifests |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS, one ACTIVE PASS and one reported DRAFT |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel |
| `git diff --check` | PASS |

The public bundle/create, classify, source replay, candidate replay and candidate promotion commands
from `docs/replay-incidents.md` were also executed with fresh temporary output paths. Source replay
is UNCHANGED with an explicit failed safe assertion; candidate replay is CHANGED with that assertion
PASS. Both report no external effects. Full CLI chain, collision/error privacy and failing/passing
regression behavior are also tested in the focused suite.

## Mandatory self-review

Actively checked the prompt's failure modes and added targeted negative cases:

- Live dispatch: no adapter import/execution callback exists; source evidence is generated at the
  real local runtime boundary, then gateway construction is replaced with a failure during replay.
  The whole default test suite additionally blocks sockets.
- Tampering: mutated events, digests, source identity, captured plan and assessment are rejected;
  recomputing only the outer digest cannot hide cross-field inconsistency. Full adversarial artifact
  replacement remains outside unsigned-integrity guarantees.
- Mixed sources/order: mixed runs, duplicate IDs, swapped lifecycle ordering, foreign findings,
  mismatched contract/plan/input hashes and malformed public versions/unknown fields fail visibly.
- Redaction: both bundle execution and the lower program execution entry reject material redaction;
  unavailable canary surfaces never default to empty plaintext. Aggregate source/bundle sizes are bounded.
- Approval: changed action hashes fail trajectory validation; changed policy and causal context cannot
  redeem source grants; approve/deny/expiry/one-shot semantics reuse ApprovalLedger.
- Budget: one ledger persists across actions, outstanding reservations and retry attempts; source
  monotonic durations are not inferred from wall clocks. Tests verify fewer candidate dispatches.
- Provenance: sibling concurrency preserves earlier snapshots; withheld outputs and transport failures
  never expose artifacts. Changed causal action commitments now block dispatch rather than reusing
  their old digest. This was found and fixed during self-review.
- Effects: substituted returns never become verified external effects. Output schema bytes/detector
  behavior are not falsely reconstructed from hashes; incomplete comparisons remain explicit.
- Diff: volatile envelope/lifecycle IDs and absolute timestamps are normalized; approval timeout,
  outcomes, reason/rule provenance, dispatch/return/exposure and assertion/finding drift remain visible.
  Missing/extra facts and meaningful ordering are retained; opaque action/content hashes are preserved.
- Classification/promotion: only structured categories/reasons/assertions select bases. Multiple
  categories survive. Tampered incident classification is rejected. No contract writer exists.
  Generated manifests omit targeted source argument/finding canaries and produce stable IDs.
- Gate: malformed ACTIVE artifacts fail; DRAFT-only runs are non-success and mixed corpora enumerate
  drafts. Existing Phase 0–4 tests remain passing; generated schemas and example manifests match code.

This is self-review, not independent approval.

## Known limitations and Phase 6 readiness

Unsigned evidence requires trusted source storage and operator metadata. The 1 MiB bundle limit
favors small incident windows; larger trace packaging would need a separately reviewed storage
format/limit design. Source control events without complete policy inputs cannot be repaired by
replay. SHADOW/DISABLED source dispatches fail the existing enforcing trajectory validator rather
than being relabeled protected. Whole-model branching, raw response validation, detector reruns,
monotonic duration capture, exact historical tool metadata proof and verifier reexecution are not
claimed. Promotion intentionally leaves resource/task/content-sensitive cases DRAFT. Source signals
and termination can make full semantic comparison incomplete even where dispatch assertions are
conclusive. Opaque commitment changes remain meaningful but cannot explain their underlying cause.

Phase 5 is implemented and ready for independent review. Phase 6 must await that review/fixes and
a reviewed Phase 6 plan; identity/delegation work is not authorized by this implementation.
