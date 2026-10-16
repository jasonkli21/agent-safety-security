# Phase 6 independent review fixes

## Baseline and scope

Fixes address the confirmed findings in the independent review of Phase 6 commit
`6c8c0580056dc0c383c4ba06233e21b4e095447f`, based on Phase 5 review-fix commit
`c84b03ff4e221d998f20e18589c85dd594a6a5a5`. Scope is limited to P1-01, P2-02, P2-03 and
P3-01 from the supplied handoff. No Phase 7 behavior or unrelated refactor is included.

## Findings and disposition

### P1-01 — Missing trusted authority on direct Phase 6 policy requests

`authority_failure()` now requires `AuthorityContext` for every `phase6-v1` decision. Missing
authority on direct-principal contracts returns `AUTHORITY_REQUIRED`; OBO requests retain
`DELEGATION_REQUIRED`. Valid static and signed-JWT authority contexts continue through the same
principal, freshness and scope checks. Historical `phase4-v1` behavior remains outside this
Phase 6 check.

Regression coverage now checks a direct explicit ALLOW with no authority is denied, a valid
static direct authority preserves ALLOW, the existing signed-JWT direct flow remains exercised,
and generated authority conformance includes a missing-direct-authority negative probe.

### P2-02 — Promotion dropping recovered protected authority

When a replay bundle recovers resource-bearing authority that was redacted from source events,
promotion now creates a `DRAFT` with reason `PROMOTION_PROTECTED_AUTHORITY_REVIEW`. It does not
copy protected authority or resource values into public regression material. A focused lifecycle
case covers runtime evidence, protected authority recovery, delegation incident classification,
promotion, and draft handling by the regression runner.

### P2-03 — Policy-time authority denials absent from incident classification

Deterministic classification now maps `IDENTITY_MISMATCH`, `INVALID_DELEGATION`, and
`OUTSIDE_AUTHORITY_SCOPE` policy evidence to `DELEGATION_ESCALATION`. `AUTHORITY_EXPIRED` and
`DELEGATION_REQUIRED` are not automatically categorized as attacks. Existing final pre-dispatch
freshness signals are unchanged. Regression coverage checks authority-scope classification and
that expiry alone does not produce a delegation incident.

### P3-01 — Stale current-state documentation

Updated architecture scope, conformance title and current compiler language, MCP identity install
and trust-boundary wording, Phase 4 data-flow context, Phase 5/6 replay status, and the focused
identity/security-contract descriptions. Generated schemas were refreshed for the new reason
code.

## Verification

| Command | Result |
| --- | --- |
| `agentsec schema export --out schemas/generated` | PASS — exported generated schemas |
| `pytest -q tests/unit/test_identity_authority.py tests/unit/test_replay.py` | NOT RUN — tests were added but execution was not requested |
| `pytest -q` | NOT RUN — execution was not requested |
| `ruff check .` | NOT RUN — lint execution was not requested |
| `ruff format --check .` | NOT RUN — format check was not requested |
| `mypy src` | NOT RUN — type-check execution was not requested |
| `git diff --check` | PASS |

## Deviations and limitations

- No finding required an architecture expansion or change to Phase 0–5 semantics.
- Protected authority remains available only as a protected replay input; promotion conservatively
  requires operator review instead of embedding that authority in an ACTIVE case.
- The new focused tests and other repository gates remain unexecuted in this fix session.

## Readiness

The confirmed findings have code, regression coverage, documentation and schema changes prepared
for independent review. Phase 7 remains out of scope and is not declared ready by this report.
