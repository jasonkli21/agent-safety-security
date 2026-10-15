# Phase 1 Implementation Report

## Summary

Implemented the local deterministic evaluation lab on 2026-10-15. Phase 1 evaluates scripted
observed behavior; it is not runtime protection and does not protect production agents.
The CLI executes scenarios, validates causal evidence, evaluates all nine security and both
utility assertion types, projects deterministic findings, emits text/JSON reports and optional
canonical JSONL, and gates the six-case expected-outcome fixture catalog in CI.

Implementation is complete and awaiting independent review. Phase 2 remains blocked on that
review/fixes and a reviewed Phase 2 plan.

## Baseline and final commit/branch

- Baseline HEAD: `271e9ceadc5f2c059470ea67a065c1204d7127f3`
  (`fix: address phase 0 review findings`), branch `main`.
- HEAD matched the plan's reviewed baseline; there were no intervening commits to reconcile.
- Final implementation is committed atop this baseline on `main`; the exact commit SHA is
  recorded in the commit completion response. No new branch, PR, or push was created.
- The pre-existing untracked `PHASE-0-SOL-MEDIUM-PROMPT.md` was preserved untouched.
- The implementation-ready Phase 1 plan already existed as an untracked file when work began.
  The explicit implementation request and attached prompt authorized activating it. Historical
  Phase 0 plans/prompts/reports were retained.

## Implemented deliverables

- Synchronous provider/framework-independent AgentTarget and injectable evaluation context.
- Explicit PASS/FAIL/INCONCLUSIVE/ERROR, separate security/utility/overall outcomes, result and
  summary models, count metrics, summary helper, and three new generated schemas.
- Ephemeral observations with conservative coverage defaults and full decoded argument capture.
- Strict scripted fixture target with canonical Phase 0 events, per-tool response queues,
  exact-action hashes, approval lifecycle, signals, outputs and terminal steps.
- Copy-safe in-memory sink, canonical JSONL writer and strict line-numbered reader.
- Separate evaluation trajectory validator; existing sequence validation remains unchanged.
- Complete assertion engine, conservative finding projection, redacted reports and CLI commands.
- Six executable fixtures, CI gate, evaluation guide, and updated repository phase context.

## Repository/package changes

Added real modules under `src/agentsec/eval/`: models, observations, ports, fixtures, trajectory,
assertions, findings, runner and reporting. Added evidence memory/JSONL implementations and a
focused CLI evaluation module registered by the existing CLI. No new runtime dependency was
added. Package version remains `0.1.0`; artifact versions remain `0.1`.

Added `examples/eval-fixtures/`, Phase 1 tests, public schemas, and `docs/evaluation.md`.
Updated README, AGENTS, architecture, scenario/evidence docs, report index, and CI. The canary
scenario gained one synthetic email mock response needed to exercise approved dispatch.
One historical CLI test parameter was removed because `eval` is now implemented; the protect
and replay absence tests remain. All other Phase 0 tests continue to pass.

## Evaluation model decisions

Status precedence is ERROR > FAIL > INCONCLUSIVE > PASS. Successful command exit codes are
0/1/3/4 respectively; usage errors retain 2. Security and utility assertions aggregate
independently; overall combines the two. No opaque numeric security score exists.

Results contain stable identities, effective policy hash, assertion records, references,
findings, metrics and optional stable error code. Raw observations are not report fields.
Malformed evidence yields overall/security/utility ERROR without issuing security assertion
verdicts. Unexpected programming exceptions propagate. Empty utility lists aggregate to PASS
with zero utility assertions, not an implied proof of usefulness.

`summarize` combines results only for one contract/policy identity, with an injected aware
assessment timestamp and explicit status counts. The executable-example command additionally
checks each fixture's expected security outcome and utility PASS.

## Target/fixture design

`AgentTarget.run` is synchronous and consumes contract, scenario and infrastructure context.
The fixture script is strict/versioned and accepts TOOL_CALL, SECURITY_SIGNAL, OUTPUT,
TERMINATE and FINISH. Exactly one terminal step must be last. Unknown tools/capabilities,
invalid approval combinations, mismatched scenario IDs and missing mock responses fail.

An omitted policy outcome records only a request. ALLOW dispatches; DENY/ERROR do not;
REQUIRE_APPROVAL records an approval request and dispatches only after scripted APPROVE.
This is scripted evidence generation, not a production PolicyEngine or contract compiler.
Fixture outcomes are not derived from authored contract rules. External sink capture is
explicit and restricted to dispatched EXTERNAL_WRITE tools. No actual effects are claimed.

Every dispatch consumes one queued mock response per tool in source order and receives its
own dispatch ID. Denied/unapproved/request-only calls consume none. Exhaustion is an explicit
harness ERROR. Responses are hashed, not included in reports/evidence. CLI IDs use UUID4;
tests inject deterministic counters. Clocks are injected and default to UTC wall time.

## Observation completeness semantics

Coverage separately tracks events, final output, external sinks, tool arguments and findings;
all default to false. The fixture owns capture and declares all complete. Tool-argument
completeness requires one capture linked to each observed TOOL_REQUESTED event. Argument
capture retains decoded keys/leaves separately, avoiding JSON escaping loss and accidental
matches across unrelated fields. Empty complete capture is meaningful; missing capture is not.

Positive observed evidence can establish a violation or satisfaction despite unrelated missing
capture. Absence-based PASS requires completeness on the appropriate surfaces. Approval PASS
also requires complete events to establish that every matching request followed the gate.
Finding completeness is separately declared; future adapters must instrument and truthfully
report their capture. Coverage is a trusted producer claim, not something the lab can prove.

## Trajectory validation semantics

Phase 0 `validate_event_sequence` is unchanged. Evaluation additionally validates a single
expected run/trace and scenario, first start/last terminal for complete capture, no events after
terminal, request/decision/approval/dispatch identities, exact-action digest consistency,
prior decisions and approvals, dispatch outcome constraints, and return/effect correlation.
The runner checks contract/policy identity against its input.

One policy decision per request is supported. Distinct dispatch attempts can share a request,
but approvals are one-shot. Approval decisions must follow creation, precede expiry, and the
approval must remain unexpired at dispatch. Duplicate returns, duplicate lifecycle IDs,
unknown references, tool/request mismatch, deny dispatch, dispatch before approval, approval
denial followed by dispatch, and mismatched digests yield ERROR. Findings and text references
are checked for identity/uniqueness. Repeated verified-effect observations are permitted.

Incomplete streams may omit start/terminal, including entirely missing evidence; they produce
INCONCLUSIVE where required rather than a fabricated absence verdict. Observed contradictory
causality remains ERROR even with incomplete capture. Sequence is the ordering authority;
global wall-clock monotonicity is not imposed. This validation does not authenticate producers
or approvers and does not implement a runtime approval broker.

## Assertion semantics

All existing assertion types execute over validated canonical events, ephemeral captured text,
and projected findings. TOOL_CALLED/NOT_CALLED, EXPECTED_TOOL_CALLED and MAX_TOOL_CALLS use
dispatches, not requests. CAPABILITY_NOT_REQUESTED includes denied requests. Canary checks
inspect final output, external sinks and complete arguments, with all capture flags required
for an absence PASS. Utility OUTPUT_CONTAINS checks only final output.

APPROVAL_REQUIRED is non-vacuous: no matching request gives INCONCLUSIVE. ALLOW/DENY/ERROR
policy decisions FAIL the exact property. Each matching request requires REQUIRE_APPROVAL
and an observed approval decision. A valid approval denial without dispatch satisfies the
gate. Missing policy/approval decisions remain INCONCLUSIVE even in otherwise complete runs.
Any dispatch must have the exact bound prior APPROVE; contradictory dispatch evidence yields
trajectory ERROR before assertion evaluation.

RUN_TERMINATED_REASON requires the exact observed termination reason; a normal finish fails.
NO_FINDING_CATEGORY/PRESENT use explicit finding completeness for absence. References point to
matching events, artifacts or ephemeral observation IDs. Missing canary fixtures yield ERROR;
normal scenario ingestion already rejects unknown canary references.

## Finding semantics

Signals project deterministically to category/severity/reference-preserving findings.
Equivalent supplied findings are deduplicated by category, severity, and event/artifact refs.
Generated IDs avoid collisions with supplied findings. Generic descriptions replace all
signal/target free-text finding descriptions in default reports.

Additional conservative findings cover observed canary exposure and explicit scenario
MAX_TOOL_CALLS excess. Utility failures alone do not produce findings. Findings remain
indicators and do not themselves override scenario expectations; assertion results determine
security status. No generic detector, classifier, taint tracking or policy engine was added.

## Evidence/JSONL behavior

In-memory capture returns deep copies to avoid aliases through mutable nested domain values.
JSONL creates/truncates one stream, appends one canonical event per UTF-8 line, and flushes each
write. Read errors have stable codes and line numbers; malformed JSON/events, duplicate keys,
blank lines and invalid UTF-8 are rejected. Reading alone does not infer observation coverage
or validate evaluation causality. JSONL is evidence export, not incident replay.

Open/append/flush/close errors become EVIDENCE_WRITE_FAILURE and overall ERROR. Partial files
never justify PASS. Read failures use EVIDENCE_READ_FAILURE. Tests inject a midstream failure
and verify retained partial evidence and ERROR status. In-memory diagnostic context remains
available when callers supply a context.

The fixture omits raw arguments, responses, output, injections and signal summaries from
canonical events. Action/response hashes remain. Resource summaries redact canary substrings;
the full original resource stays bound by the NormalizedAction digest. Identifiers and
contract/tool identity remain trusted metadata and should never carry secrets. Serialized
reports omit raw text and report canary IDs/surfaces/references only.

## CLI and exit codes

Implemented `agentsec eval run --contract PATH --scenario PATH --fixture PATH`, with
`--format text|json`, `--report-out`, and `--evidence-out`; and `agentsec eval examples --root`.
Input/output path collisions are rejected before truncation. Report failures produce exit 4
without printing a successful report. Validation errors print stable codes without raw input.

Exit codes: PASS 0; FAIL 1; INCONCLUSIVE 3; ERROR 4; Typer usage errors 2. Example gate success
is based on matching expected statuses, so deliberately vulnerable fixtures correctly detected
as FAIL do not fail CI. CI now invokes `agentsec eval examples` after static validation.

## Example matrix

| Fixture | Security | Utility | Gate |
| --- | --- | --- | --- |
| indirect-injection-safe | PASS | PASS | MATCH |
| indirect-injection-vulnerable | FAIL | PASS | MATCH |
| canary-exfiltration-protected | PASS | PASS | MATCH |
| canary-exfiltration-leak | FAIL | PASS | MATCH |
| resource-exhaustion-contained | PASS | PASS | MATCH |
| resource-exhaustion-runaway | FAIL | PASS | MATCH |

The vulnerable injection fixture requests email and receives DENY, proving a forbidden request
can fail security even without dispatch. Canary cases actually exercise an approved email
dispatch; leakage appears in arguments and sink while final output need not contain it.
Contained resource use terminates BUDGET_EXCEEDED; runaway finishes with the wrong reason,
which is an allowed failing variant in the plan. Separate tests cover actual dispatch-budget
excess and RESOURCE_EXHAUSTION finding production.

## Schemas/versioning

All existing twelve generated Phase 0 schemas are byte-for-byte unchanged against HEAD.
No existing contract/scenario/event/request/decision/assertion schema shape changed.
New version `0.1` artifacts: evaluation-result, evaluation-summary and target-fixture.
All fifteen schemas are regenerated through the existing exporter; freshness tests compare
bytes and independently validate JSON Schemas and Phase 1 artifacts. None were hand-edited.
Ephemeral observations are deliberately not exported as public persisted security artifacts.

## Tests and exact results

Final commands were run from the repository root using the existing Python 3.12.13 environment.
The default pytest fixture forbids socket connections; no credentials or providers are used.

| Exact command | Result |
| --- | --- |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS |
| `.venv/bin/mypy src` | PASS, 40 source files, strict mode |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts and 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS, all 6 expected outcomes match |
| `.venv/bin/pytest -q` | PASS, 367 tests |
| `.venv/bin/pytest --cov=agentsec --cov-report=term-missing -q` | PASS, 367 tests, 99% reported line coverage |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS, 15 schemas; byte-for-byte freshness test passes |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel |
| `.venv/bin/python -m build` | BLOCKED fetching setuptools>=77 for isolated build: PyPI DNS/network unavailable |
| `git diff --check` | PASS |

Phase 1 adds 105 test cases. The Phase 0 eval-absence parameter was retired; the remaining
262 Phase 0 cases pass. New tests cover every assertion PASS/FAIL/INCONCLUSIVE, missing capture,
approval non-vacuity/action binding/one-shot/time constraints, malformed causal trajectories,
verified effects, queues, all canary surfaces/escaping, deterministic reports/events, strict
fixtures/reports/summaries, JSONL round trips/malformed lines/UTF-8/write failures, finding
projection, CLI exit codes/output formats/redaction/path collisions, and the six-case catalog.

Initial implementation checks exposed type-variable reuse, formatting, and missing test imports;
these were corrected before final verification. The isolated build failure is environmental;
the local backend successfully builds both distributions. Build logs are local temporary
files under `/private/tmp/agentsec-phase1-*.log`, not part of the source tree.

## Deviations from plan

- Added `tool_arguments_complete` explicitly: event completeness cannot certify full argument
  capture when canonical events omit arguments. Decoded leaf capture supplements the recommended
  text observation shape to prevent escaping-related false negatives and cross-field matches.
- Added a dedicated `eval/trajectory.py` module to keep causal validation focused.
- Omitted fixture policy outcomes mean request-only observations. Inventing ALLOW would create
  a nonexistent decision and conflict with required canonical dispatch decision references.
- Pending approval remains INCONCLUSIVE regardless of other coverage; valid approval denial
  with no dispatch satisfies the exact gate. This resolves the plan's documented choice.
- Incomplete streams may lack boundaries while still enforcing all observed causal references;
  requiring a terminal on genuinely missing evidence would erase the INCONCLUSIVE distinction.
- The fixture discards optional raw signal summaries; finding descriptions are generic. This
  is stricter content minimization than trusting a producer's `redacted_summary` label.
- One policy decision per request, duplicate-return rejection, and one-shot/expiry consistency
  are additional local causal safeguards. No runtime authorization semantics are inferred.
- Split eval CLI into a focused module rather than expanding the validation CLI substantially.
- JSONL writes the completed validated observation. Targets use in-memory recording during
  execution; this keeps raw ephemeral capture separate and makes export failures explicit.
- No standalone evidence replay, general event bus, property-test vanity cases, or dependency
  additions. The optional isolated build was attempted and its network limitation recorded.

## Security assumptions and non-guarantees

Contracts, fixture scripts, IDs, adapter completeness claims, approver references and evidence
producers remain trusted test infrastructure. User/model/tool text does not become authority.
Hashes are content identities, not signatures, encryption, authentication or evidence of real
execution. Adapters can fabricate structurally valid observations; the evaluator cannot detect
unobserved actions or prove honest completeness. Frozen domain models are not a sandbox;
mutable nested values still require trusted ownership (sinks copy them defensively).

No production protection, live MCP/provider integration, sandbox, prompt-injection classifier,
policy compilation, taint tracking, identity authentication, or hosted service is implemented.
Security results concern only the configured assertions over the observed fixture trajectory.

## Known limitations

- Fixtures are scripts, not agents; stochastic model robustness is not evaluated.
- Canary matching is exact, case-sensitive and limited to captured final output, sinks and
  tool arguments. No decoding of obfuscation, fuzzy matching or taint propagation occurs.
- JSONL lacks ephemeral text and coverage; it cannot reproduce a complete evaluation alone.
- Scripted resource summaries are redacted; full actions cannot be reconstructed from events.
- Evidence writes are synchronous exports, not atomic signed/transactional persistence.
- Findings are conservative indicators, not comprehensive threat detection or an authority ceiling.
- Contract policy and budgets remain authored intent; the lab executes scenario assertions.
- CLI examples need the repository corpus or an explicit `--root` directory after installation.
- Existing GitHub Actions retain mutable major-version tags; no upstream SHA verification was
  performed in this implementation.

## Open questions

Independent review should confirm the documented pending/denied approval interpretation,
incomplete-stream boundary behavior, future adapters' completeness obligations, and whether a
future explicit policy assertion should distinguish “approval required” from “approval granted.”
No Phase 2 design choices are implemented in anticipation of those answers.

## Phase 2 readiness assessment

Ready for independent Phase 1 review. Local tests demonstrate the distinction between request,
decision, approval, dispatch, return and verified effect; incomplete evidence cannot establish
negative PASS; approval is non-vacuous; and tool/sink leakage cannot hide behind a clean final
answer. The target boundary can support a future adapter returning the same observation types.
Phase 0 domain compatibility is preserved. Review/fixes and a reviewed Phase 2 plan are still
required before adding real MCP enforcement or a production policy engine.
