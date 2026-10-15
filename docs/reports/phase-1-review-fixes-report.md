# Phase 1 Review Fixes Report

## Summary

Addressed both independent Phase 1 review findings. Sink-bearing fixtures are now checked for
tool compatibility and guaranteed dispatch before the target emits canonical events. The
`agentsec eval examples` gate now preserves the evaluation status distinctions and aggregate
precedence. Phase 1 remains a deterministic local evaluation lab, not production protection.

## Reviewed commit

`0a3e2a8d4dedc0b8ae28c029efdbdf92ea8ca7de` (`feat: implement phase 1 local security evaluation lab`).
The repository HEAD matched this reviewed commit when the fixes began.

## Findings addressed

- **P1:** malformed sink capture on non-dispatched paths could be discarded while the fixture
  claimed complete sink coverage.
- **P2:** `eval examples` converted every expected-outcome mismatch to exit code 1, losing
  `INCONCLUSIVE` and `ERROR` distinctions.

## P1 sink-path validation fix

`FixtureTarget` now preflights all tool references, capabilities, and sink-capture claims before
emitting any canonical event. `external_sink_text` is valid only for an `EXTERNAL_WRITE` tool
where the scripted outcome necessarily dispatches: `ALLOW`, or `REQUIRE_APPROVAL` with
`APPROVE`. Request-only, `DENY`, `ERROR`, pending approval, denied approval, and non-external
tools produce `INVALID_SINK_CAPTURE` and an evaluation `ERROR`. This prevents malformed canary
sink data from disappearing under complete-capture metadata.

## P2 example-gate exit semantics fix

Each example receives a gate status. Exact expected security/overall status with utility `PASS`
maps to gate `PASS`; evaluator `ERROR` and `INCONCLUSIVE` retain those statuses; other mismatches
map to `FAIL`. The existing `aggregate()` and `EXIT_CODES` define precedence and process exit:
`ERROR` (4) > `FAIL` (1) > `INCONCLUSIVE` (3) > `PASS` (0). Correctly detected vulnerable
fixtures therefore continue to match their expected `FAIL` outcomes and leave the examples
command successful.

## Tests added

- Rejected sink text on request-only, denied, errored, pending-approval, and denied-approval
  paths; validated allowed and approved external writes; preserved the non-external tool
  restriction.
- Added the canary false-PASS regression: malformed denied sink capture yields `ERROR`, never a
  passing `OUTPUT_NOT_CONTAINS_CANARY` result.
- Added `eval examples` CLI checks for exit codes 4, 3, and 1; aggregate precedence checks for
  `FAIL > INCONCLUSIVE` and `ERROR > FAIL`; preserved Typer usage exit 2.
- The checked-in six-case corpus remains covered by the existing CLI test and command run.

## Verification results

| Command | Result |
| --- | --- |
| `.venv/bin/ruff check .` | Passed: all checks passed. |
| `.venv/bin/ruff format --check .` | Passed: 71 files already formatted on final tree. |
| `.venv/bin/mypy src` | Passed: no issues in 40 source files. |
| `.venv/bin/agentsec examples validate` | Passed: 3 contracts and 3 scenarios valid. |
| `.venv/bin/agentsec eval examples` | Passed: six expected cases matched; exit 0. |
| `.venv/bin/pytest -q` | Passed: 381 tests. |
| `.venv/bin/pytest --cov=agentsec --cov-report=term-missing -q` | Passed: 381 tests, 99% total coverage. |
| `.venv/bin/agentsec schema export --out schemas/generated` | Passed. |
| `test_generated_schemas_current` (included in pytest suite) | Passed: generated schemas byte-for-byte match committed schemas. |
| `.venv/bin/python -m build --no-isolation` | Passed: sdist and wheel built. |
| `.venv/bin/python -m build` | Could not complete: isolated build environment could not download `setuptools>=77` because network name resolution is unavailable. |
| `git diff --check` | Passed on the final tree. |

The test run also confirms the checked-in vulnerable fixtures remain expected detections. Build
warnings about no JSON files under `examples` are pre-existing packaging warnings and did not
prevent the no-isolation build.

## Schema/version impact

No Phase 0 or Phase 1 schema shape or version changed. Exporting schemas produced no tracked
schema diff; the generated-schema freshness test passed.

## Deviations

None. The non-dispatch validation reuses the existing `INVALID_SINK_CAPTURE` code and adds no
serialized fields or dependencies. The isolated build limitation is environmental, not a source
build failure; the required no-isolation source and wheel build succeeded.

## Remaining limitations

The fixture target still represents scripted evidence and makes no claim about real agents,
production policy enforcement, model robustness, or truthful completeness from future adapters.
The isolated build should be repeated when package-network access is available.

## Final Phase 1 readiness

Review fixes and local verification are complete. The repository is awaiting final independent
Phase 1 verification. Do not begin Phase 2 until that verification is complete and a reviewed
Phase 2 plan exists.
