# Phase 5 independent review fixes report

## Baseline and status

Baseline: `3298fcabb31dff99980e639181e03b2b964945f5` (`feat: implement phase 5 incident replay and security regression`).
This report records the corrective pass for the four findings in the Sol High review handoff.
The corrections and this report are intended to land together in one commit. The unrelated
untracked `PHASE-0-SOL-MEDIUM-PROMPT.md` was left untouched and excluded.
The fix commit is the commit containing this report; resolve its exact SHA with
`git log -1 --format=%H -- docs/reports/phase-5-review-fixes-report.md`.

## Findings addressed

### P1-01 — legacy approval binding

Historical approval scripts now require `SourceBinding.EXACT` before replay can create or redeem
them. A legacy source with an approval request receives `APPROVAL_SOURCE_PLAN_UNBOUND`; it emits
no substituted dispatch and its diff is `INCOMPLETE`. Legacy non-approval replay remains available.
`ReplayResult.source_identity` is nullable and is `null` for legacy traces, so a fresh compilation
is not presented as recorded historical identity. Exact-bound approval replay and changed-plan
rejection remain covered.

### P2-02 — ordinary approval denial

`ApprovalLedger` now distinguishes `APPROVAL_DENIED`, `APPROVAL_EXPIRED`, and `INVALID_APPROVAL`.
The gateway emits `APPROVAL_BYPASS` only for invalid, reused, or mismatched approval state. A
valid human denial or timeout remains an operational outcome; successful exact one-shot redemption
is unchanged.

### P2-03 — severity preservation

`ClassificationBasis.severity` preserves the exact severity from canonical signals and findings.
Reason-code, assertion, and operator bases use `null`; no incident-wide aggregate is invented.
Generated incident and replay-result schemas were refreshed.

### P2-04 — truthful non-enforcing modes

The replay source validator now recognizes SHADOW and DISABLED dispatches without applying the
ENFORCE-only evaluation validator. It checks event sequence, unique request/decision/dispatch
identity, source decision bindings, dispatch request/action links, and return/exposure causality.
Valid non-enforcing streams receive `UNSUPPORTED_SOURCE_ENFORCEMENT_MODE` and an INCOMPLETE
comparison; replay does not relabel or execute them. Malformed causality remains
`INVALID_TRAJECTORY`.

## Documentation and generated artifacts

Updated the public replay guide with legacy identity/approval semantics, unsupported source modes,
and severity behavior. Clarified the JSONL storage boundary in the evaluation guide, the historical
identity invariant in architecture, and denial/expiry taxonomy in the runtime guide. Updated the
report index and regenerated `incident.schema.json` and `replay-result.schema.json`.

## Verification

All commands ran in the repository `.venv`, without network/model credentials. The complete test
suite ran after the schema refresh and reported 595 passing tests. The focused replay/runtime set
reported 63 passing tests. Final static checks and build passed after correcting one import-order
finding from the first Ruff run.

| Exact command | Result |
| --- | --- |
| `.venv/bin/pytest -q tests/unit/test_replay.py tests/unit/test_runtime_state.py` | PASS, 63 tests |
| `.venv/bin/pytest -q` | PASS, 595 tests |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 131 files |
| `.venv/bin/mypy src` | PASS, 80 source files |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts and 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS, all 6 expected outcomes |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS |
| `.venv/bin/agentsec regression validate --root examples/regressions` | PASS, 2 manifests |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS, one ACTIVE PASS and one DRAFT |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel |
| `git diff --check` | PASS |

The public workflow also passed end-to-end with fresh temporary output paths: `agentsec replay
bundle create`, `agentsec incident classify`, source `agentsec replay run`, candidate `agentsec
replay run --contract`, and `agentsec incident promote`. The legacy CLI result exposed a null
`source_identity`, and candidate replay satisfied the explicit blocked-send assertion.

## Limitations and readiness

SHADOW and DISABLED are recognized as truthful evidence but remain unsupported for semantic replay;
the typed blocker is the deliberate contained fix. Legacy approval-dependent traces remain
INCOMPLETE because their historical compiled plan cannot be proven. Severity remains per-basis;
there is no aggregate severity rule. This correction pass does not authorize Phase 6. Phase 5
should receive independent re-verification against the handoff findings before Phase 6 work begins.
