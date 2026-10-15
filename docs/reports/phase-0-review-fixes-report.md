# Phase 0 Review Fixes Report

## Baseline

- Reviewed commit: `eab7a44962ffabec9eb50e276146a2f00a61d788` (`scaffolding + phase 0`).
- HEAD matched the reviewed commit before changes.
- Final state: all review-fix changes are included in one commit atop the baseline. The exact
  commit SHA is included in the completion response. The pre-existing untracked
  `PHASE-0-SOL-MEDIUM-PROMPT.md` was preserved and excluded from the commit.

## Findings addressed

1. **Policy request environment consistency.** `PolicyRequest.environment` must equal
   `agent.environment`. Field validation rejects a mismatch with `INVALID_SCHEMA` at
   `environment`. Added matching, mismatch, error-path, and canonical round-trip coverage.
   Files: `src/agentsec/domain/policy.py`, `tests/unit/test_domain.py`,
   `docs/security-contract.md`.
2. **Scenario task-scope consistency.** A present `task_scope.task_id` must equal `task_id`.
   Added a mismatching invalid scenario fixture, stable error-path coverage, and canonical
   round-trip coverage. Files: `src/agentsec/domain/scenarios.py`,
   `tests/fixtures/scenarios/task-scope-task-id-mismatch.yaml`,
   `tests/unit/test_events_scenarios.py`, `docs/scenario-format.md`.
3. **Destructive tool metadata consistency.** `DESTRUCTIVE` requires `destructive=true`; the
   prior rule rejecting `destructive=true` on low-risk classes remains. `CODE_EXECUTION` and
   `INFRASTRUCTURE` may use either boolean value. The same `DESTRUCTIVE` implication is encoded
   in the exported JSON Schema. Files: `src/agentsec/domain/tools.py`,
   `schemas/generated/tool-descriptor.schema.json`, `schemas/generated/scenario.schema.json`,
   `tests/unit/test_domain.py`, `tests/unit/test_schemas_cli.py`, `docs/taxonomy.md`.
4. **Dispatch attempt correlation.** Added required `dispatch_id` fields to dispatched, returned,
   and effect-verified payloads. Regression coverage shows two attempts can share a request ID
   while using distinct dispatch IDs; missing IDs are rejected. Updated event fixtures and the
   evidence guide. Files: `src/agentsec/domain/events.py`,
   `schemas/generated/security-event.schema.json`, `tests/fixtures/events/approval-run.json`,
   `tests/fixtures/events/invalid-order.json`, `tests/unit/test_events_scenarios.py`,
   `docs/evidence-model.md`.
5. **Agent trust typing.** Changed `AgentIdentity.trust_level` to an opaque optional `Identifier`;
   provenance `TrustClass` remains used for data origins and scenario injections. The effective
   policy projection continues to include the field, with a regression test for hash changes.
   Files: `src/agentsec/domain/identity.py`,
   `schemas/generated/agent-security-contract.schema.json`,
   `schemas/generated/policy-request.schema.json`,
   `schemas/generated/security-event.schema.json`, `tests/unit/test_domain.py`,
   `tests/unit/test_contracts.py`, `docs/security-contract.md`, `docs/taxonomy.md`.
6. **Literal YAML `<<` keys.** Removed rejection based only on the key spelling. Merge resolution
   remains disabled, while anchors, aliases, explicit tags, duplicates, and other parser limits
   remain enforced. Added YAML/JSON parity and no-merge-operation tests. Files:
   `src/agentsec/contracts/loader.py`, `tests/unit/test_loading.py`,
   `docs/security-contract.md`.
7. **Stale post-bootstrap context.** Marked Phase 0 complete and blocked Phase 1 implementation
   until an active plan exists; updated the README read path and historical prompt notice; removed
   the obsolete `SCAFFOLD-MANIFEST.json`; corrected Incident, ReplayBundle, and ContractCompiler
   timing in the architecture; generalized report guidance; and added a pointer from the original
   implementation report. Files: `AGENTS.md`, `README.md`, `SCAFFOLD-MANIFEST.json` (deleted),
   `docs/architecture.md`, `docs/prompts/phase-0-sol-medium-implementation-prompt.md`,
   `docs/reports/README.md`, `docs/reports/phase-0-implementation-report.md`.

## Schema/model changes

- `PolicyRequest` and `ScenarioTask` now reject inconsistent duplicate context fields.
- Agent trust context is now a bounded identifier rather than a provenance enum.
- Three evidence payloads require an attempt identifier. Existing event producers must provide it;
  no migration framework was added.
- Tool metadata validation and exported schemas now reject `DESTRUCTIVE` with a false or omitted
  destructive flag.
- Schema version remains `0.1` as this is corrective work before a compatibility promise; no
  migration framework was introduced.
- Generated schemas were regenerated using `agentsec schema export --out schemas/generated` and
  the byte-for-byte freshness test passes.

## Tests added

- Finding 1: matching environments, mismatch rejection with stable code/path, and round-trip.
- Finding 2: matching task IDs, mismatch rejection with stable code/path, round-trip, and invalid
  fixture.
- Finding 3: destructive-class true/false/default behavior, preserved code-execution and
  infrastructure behavior, and independent JSON Schema enforcement.
- Finding 4: required IDs on all three payloads and two distinct attempts for one request.
- Finding 5: opaque agent trust identifier typing and `effective_policy_hash` sensitivity.
- Finding 6: literal `<<` YAML/JSON equivalence, no merge behavior, and continued anchor/alias/tag
  rejection.
- Finding 7: reviewed active-context files and removed the stale manifest; the existing schema,
  CLI, and example tests remain in the full suite.

## Verification

Commands were run from the repository root with the checked-in `.venv`:

| Exact command | Result |
| --- | --- |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 53 files formatted |
| `.venv/bin/mypy src` | PASS, 27 source files |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS; schema freshness test passes byte-for-byte |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts and 3 scenarios |
| `.venv/bin/agentsec contract validate examples/contracts/research.yaml` | PASS |
| `.venv/bin/agentsec scenario validate examples/scenarios/indirect-injection.yaml` | PASS |
| `.venv/bin/pytest -q` | PASS, 263 tests |
| `.venv/bin/pytest --cov=agentsec --cov-report=term-missing -q` | PASS, 263 tests, 99% line coverage |
| `.venv/bin/python -m build` | BLOCKED in isolated build setup: network access to PyPI was unavailable for `setuptools>=77` |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel built |

The test suite remains local and credential-free.

## Deviations from handoff

- No schema version bump was made, as requested for this pre-compatibility corrective change.
- The isolated build command could not install its build dependency without network access; the
  no-isolation build using the installed backend completed successfully.
- The suggested GitHub Actions SHA pinning was not changed because no upstream release SHAs were
  verified in this pass; mutable action tags remain a hardening follow-up.
- The pre-existing untracked top-level prompt was left untouched and is not part of the commit.

## Remaining known limitations

- Full lifecycle causal validation remains deferred; Phase 0 only represents dispatch-attempt
  identity and retains the documented sequence/trace checks.
- Arbitrary nested JSON remains mutable within frozen Pydantic models, as documented in the
  original report.
- No production policy engine, runtime gateway, evaluation runner, provider integration,
  provenance propagation, or hosted service is implemented.
- GitHub Actions still use mutable major-version action tags.

## Phase 1 readiness

The canonical domain and evidence representations are ready for Phase 1 planning: policy requests
and scenario tasks reject contradictory duplicated context, trust/provenance concepts are
separate, and each dispatch attempt can be correlated. This is readiness to design Phase 1, not
authorization to implement it. The repository has no active Phase 1 plan; creating and reviewing
that plan is the remaining prerequisite, not a blocker in the Phase 0 model.
