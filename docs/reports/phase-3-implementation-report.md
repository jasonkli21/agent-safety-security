# Phase 3 implementation report

## Baseline and status

Baseline and HEAD at implementation/verification start:
`eb29db96b8c1f0204ed0b31d7a04daec280a40f4` (`fix: address phase 2 independent review findings`).
There were no newer commits or tracked modifications. The supplied Phase 3 plan and an unrelated
`PHASE-0-SOL-MEDIUM-PROMPT.md` were untracked. The plan is included with this implementation (Markdown hard breaks were normalized to avoid
trailing whitespace);
the unrelated prompt remains untouched and excluded. The implementation revision is the single
`feat: implement phase 3 unified contract compilation` commit containing this report (a commit
cannot embed its own final SHA). No independent Phase 3 review is claimed.

The repository's previous phase-boundary text required Phase 2 fixes and a Phase 3 plan. The
baseline contains the Phase 2 review corrections, the supplied plan declares implementation
readiness, and the user explicitly authorized Phase 3 implementation. No review attestation
beyond the repository's Phase 2 history is inferred.

## Scope implemented

- Immutable versioned compiled plan for protected identity, exact rules, task ceiling, supported
  runtime budgets, approval timeout, source-linked semantic atoms and explicit unsupported gaps.
- Native evaluator over compiled intent with a raw-contract compatibility entry point. Gateway
  startup compiles its defensive snapshot once and rejects a different supplied plan before
  emitting a run or dispatching. Budget/approval configuration and evidence identity use the plan.
- MCP binding/resource coverage composed with compiled requirements; discovery proof can be
  projected to semantic atoms. Extraction and `opaque_exact` requirements remain adapter-owned.
- Deterministic independent policy obligations, local PASS/FAIL/ERROR conformance runner,
  synthetic contract-derived Phase 1 cases and dimensioned semantic coverage.
- Finite exact-match old/new semantic diff: authority and approval boundaries, resource
  exceptions, task ceilings, supported budgets, timeout, identity/environment and unsupported
  intent changes. No policy activation.
- `contract compile`, `test`, `coverage [--run]`, and `diff`, all with deterministic text and
  canonical JSON. Four generated public artifact schemas and existing schema freshness coverage.
- Focused compiler, oracle, broken-policy/evidence, diff, CLI, adapter and cross-path tests;
  focused documentation and updated phase guidance.

## Architecture choices and deviations

The compiler reuses frozen canonical `ToolRule`, `AgentIdentity`, `PrincipalRef` and
`ApprovalSettings` rather than defining duplicate versions of those fields. Resource ceilings
use tuples/frozen sets because the canonical TaskScope contains a mutable dict. Its compatibility
projection returns a new TaskScope each time. No mutable runtime ledger or MCP type enters the IR.
Semantic atoms use deterministic field/rule source paths as IDs and digest configured intent.
Identity and task scope are grouped atoms rather than a class per field; unsupported data rules
and invariants remain individually visible.

The supplied plan's suggested filenames were adapted: report projection lives in
`compiler/reporting.py`; the conformance generator and finite partition share `compiler/probes.py`.
Four public versioned Pydantic artifacts have inspection/interchange value, so generated schemas
were added; internal probes remain frozen dataclasses rather than a new persisted scenario DSL.
No dependency was added. The existing synthetic MCP example demonstrates the new commands;
no separate duplicate server or attack corpus was created.

The evaluation bridge adds two narrow hooks to existing fixture evidence emission. The base
scripted fixture semantics remain unchanged; ContractTarget overrides decision production and
uses a deterministic synthetic approving actor. Dispatch/approval evidence follows the actual
native result. This avoids a second canonical event producer while keeping scripted attack
fixtures distinct from contract-derived conformance. Existing trajectory/assertion semantics
remain authoritative and unchanged.

Compilation at gateway startup is tested to happen once across multiple MCP calls. Supplied
plans are compared in full with the startup compilation, catching mismatched contract IDs,
policy hashes or altered compiled contents. The legacy raw-contract policy API compiles first;
it does not maintain a second interpreter. Preflight CLI validation may compile independently;
this does not affect the gateway's reused active plan.

## Compiler and coverage semantics

Compiled/runtime-supported flags identify executable intent; adapter proof is a separate
NOT_REQUIRED/UNPROVEN/COVERED/UNCOVERED dimension. Probe/evaluation IDs and PASS/FAIL/ERROR/NOT_RUN
are separate. Offline coverage cannot manufacture discovery proof. An applicable discovered tool
without adequate extraction/opaque semantics produces uncovered proof; no applicable tool remains
unproven. Unsupported data/invariant/on-behalf-of/budget atoms never acquire generated tests.

The compact exact-match partition includes rule and scope capabilities/resources, None, a
collision-free OTHER resource per capability and an unknown capability. Task scope can make an
otherwise configured rule or default-deny branch unreachable. Such atoms have no generated IDs;
they are not reported as covered. Overlap participation does not mean a shadowed rule is
independently outcome-influential. Supported stateful budget/timeout atoms have no generated
policy probes/cases and stay NOT_RUN; existing runtime tests verify their stateful behavior.
There is no generic security percentage.

## Avoiding circular conformance

Expected outcomes/reasons come from declarative compiled facts and a small explicit precedence
oracle. Generation does not call NativePolicyEngine, directly or indirectly; a monkeypatched
engine that raises cannot affect obligation generation. Execution calls the shared compiled
native evaluator. Fixed expected matrix values additionally protect precedence and ceiling
behavior across direct policy, generated eval and MCP runtime.

Synthetic fixture steps contain no expected observed outcome. Native decisions govern observed
approval/dispatch. Existing APPROVAL_REQUIRED assertions demand an exercised matching request,
a REQUIRE_APPROVAL decision and decided exact approval before dispatch. The bridge also requires
one observed decision with the independently expected outcome/reason, so a missing request or
ERROR cannot pass a deny case through absence alone. Deliberately broken allow/approval decisions,
engine exceptions and empty complete evidence fail/error in focused tests.

## Semantic diff limitations

Comparison is finite for the current exact-match subset. It uses the union of both plans'
capability/resource partitions, including unknown/default space and exceptions beneath broad
rules. Request identity/task scope is normalized to each protected plan; identity/environment
and task configuration changes are reported separately. DENY < REQUIRE_APPROVAL < ALLOW defines
authority ordering. Approval transitions also receive approval-boundary records. Task scope
widening/narrowing is visible even if tool rules still deny. An absent supported budget is
unbounded; timeout changes are reported without a universal safety ordering.

Unsupported intent changes are digest comparisons labeled unsupported, not behavioral
simulation. No formal equivalence, argument-content analysis, data-flow enforcement, arbitrary
resource canonicalization or automatic activation is claimed. Representative resources are
reported by digest; capability names and before/after outcomes remain developer-readable.

## Privacy and security assumptions

The compiler and supplied runtime dependencies are trusted code. Compiled manifests intentionally
contain authored policy values, including exact resources, and must be handled like their source
contracts. Conformance/coverage/diff reports omit raw runtime arguments/responses and use IDs and
digests. Digests are identifiers, not encryption or protection for guessable values. Generated
cases keep canonical observations in memory and do not export raw evidence by default.
Runtime redaction, action/input digests, exact approvals, one-shot redemption, budget counting,
cancellation/unknown-effect handling, poisoned-sink behavior, request-ID guards, response checks
and shadow evidence semantics remain protected by the existing suite. Synthetic approvals are
not approver authentication. Synthetic PASS is not model/prompt-injection robustness or proof
that an upstream server is honest.

## Verification

All commands ran locally using the existing `.venv`; no model APIs, credentials or arbitrary
network access were used. Baseline `.venv/bin/pytest -q`: **451 passed**;
`.venv/bin/ruff check .` and `.venv/bin/mypy src`: passed (58 source files).

Final implementation verification:

| Exact command | Result |
| --- | --- |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 107 files formatted |
| `.venv/bin/mypy src` | PASS, 66 source files |
| `.venv/bin/pytest -q` | PASS, 477 tests |
| `.venv/bin/pytest -q tests/unit/test_compiler.py tests/integration/test_mcp_gateway.py -k 'compiler or phase3 or stdio'` | PASS, 27 tests, 30 deselected; includes existing two-process stdio smoke |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts and 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS, all 6 expected outcomes matched |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS; full-suite freshness/schema validation passed |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel; existing optional examples JSON glob emitted a no-files warning |
| `git diff --check` | PASS |

CLI text/JSON workflows are covered by focused tests and manual local example invocations.
Self-review checked raw-rule interpretation removal, startup stale-plan rejection, task ceilings,
independent expectation generation, non-vacuous approvals, unsupported coverage, finite resource
exception/default partitions and Phase 2 safety regressions. No unresolved correctness failure
was left from the implementation checks.

## Known limitations and readiness

Phase 3 is ready for a fresh independent Sol High review, not independently reviewed here.
Phase 4 work remains gated on that review/fixes and a reviewed next-phase plan. General DataRule,
provenance/taint, model attacks/judges, delegated identity, other adapters, hosted services and
hot policy deployment remain out of scope. The grouped atoms and finite native subset are
intentional current boundaries; future data semantics must enter compiler/runtime/test coverage
explicitly rather than inheriting a conformance claim from these synthetic cases.

## Independent review corrections (2026-10-15)

Fix baseline: `83cb9a08ae2a2c538a842237703b562fa6f251d2`. The supplied
`phase-3-sol-high-review-luna-xhigh-handoff.md` identified five correctness findings.
The following corrections supersede the initial representation/coverage choices above.
All fixes are delivered together; no Phase 4 implementation or dependency was added.

- **P3-R01:** Compiled `AgentBinding` includes agent ID, environment, owner and trust level;
  task scope excludes description. Agent name/framework/provider/model and task prose remain
  document context, outside native request validity, atom identity and semantic diff. Native
  comparisons project canonical domain requests onto these security fields. Gateway protected
  request/action inputs and contract identity now come from its startup plan. Regression tests
  cover cosmetic equality, protected binding/scope changes and poisoning the retained authored
  snapshot without changing the active plan.
- **P3-R02:** `PlanIdentity` binds contract ID, compiler version, effective policy hash and
  canonical complete compiled-content digest. The digest is computed from the plan without a
  self-referential stored field; it also binds unsupported inventory. Conformance/coverage
  require exact identity, and the eval target requires equality with a fresh compilation.
  MCP returns typed versioned adapter proof with plan identity and a deterministic digest of
  wire metadata, descriptors and bindings. Composition requires the current discovery snapshot
  digest and rejects missing/mismatching snapshots. Tests cover another contract with the same
  policy hash, changed compiler/content, stale eval plans and changed discovery bindings;
  valid same-plan proof remains deterministic and supports COVERED/UNCOVERED/UNPROVEN.
- **P3-R03:** Independent probes now derive the exact matching rule set as well as the expected
  reason. Both direct and Phase 1 execution require exact reason-code and matched-rule equality.
  Dropping shadowed provenance, substituting rule IDs or adding a reason fails both paths.
  Scope/default-deny branches expect no matching rules. Generation still never invokes the
  evaluator under test.
- **P3-R04:** Adopted the review's conservative alternative. Grouped identity/task-scope atoms
  have no generated IDs and remain NOT_RUN even after successful execution. Ordinary valid
  inputs cannot establish negative consistency enforcement. Finite probes still test task
  ceilings, but the grouped atom does not claim complete generated coverage. Existing manual
  policy/runtime tests remain separate evidence; no new negative identity probe family is claimed.
- **P3-R05:** Diff compares exact reasons and matched-rule IDs alongside outcomes. The new
  `policy_explanation_change` includes both explanation sets, with representative resources
  digested. Explicit-to-default deny, rule renames and changed shadowed matching sets are visible
  without authority expansion/reduction. CLI regression verifies these changes cannot render
  the empty-diff message.

### Compatibility and deviations

The compiler identifier advances from `phase3-v1` to `phase3-v2`; initial Phase 3 manifests and
reports must be regenerated. The four Phase 3 schemas were regenerated from Python models;
Phase 0–2 schemas/types and authored contract effective-policy projection are unchanged.
`plan_identity.compiled_plan_digest` identifies a compiled artifact, not policy authenticity,
a signature or a replacement for `effective_policy_hash`. Discovery proof is content-bound
freshness evidence supplied by trusted adapter code, not a cryptographic attestation.

Architecture and the focused conformance doc record these clarified boundaries. The PRD and
phase scope are unchanged. Grouped identity/scope NOT_RUN coverage is a deliberate documented
limitation rather than implementing the preferred finer-grained negative generator in this fix.

### Fix verification

All checks used the existing local `.venv`, without external services or credentials.
The final commands/results are recorded below. Earlier development runs caught and corrected a
runtime initialization reference and invalid new test fixtures; those intermediate failures are
not counted as passing verification. No independent reviewer approval is asserted by these checks.

| Exact command | Result |
| --- | --- |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 108 files formatted |
| `.venv/bin/mypy src` | PASS, 66 source files |
| `.venv/bin/pytest -q` | PASS, 502 tests |
| `.venv/bin/pytest -q tests/unit/test_compiler.py tests/integration/test_mcp_gateway.py` | PASS, 82 tests |
| `.venv/bin/pytest -q tests/unit/test_compiler.py tests/integration/test_mcp_gateway.py -k 'compiler or phase3 or stdio'` | PASS, 52 tests, 30 deselected; includes stdio smoke |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts and 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS, all 6 expected outcomes matched |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS; full-suite schema freshness checks passed |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel; existing optional examples JSON glob warning |
| `git diff --check` | PASS |

### Remaining limitations and readiness

All five supplied findings are addressed, with R04 using the explicit conservative alternative.
No unresolved fix failure remains. Exact identity/digests provide freshness, not authenticity;
callers supplying adapter proof must obtain the comparison snapshot digest from their current
registry. Identity/scope negative generated coverage remains unimplemented and visibly NOT_RUN.
The fixed Phase 3 is ready for independent follow-up review. Phase 4 remains gated on review/fix
acceptance and a reviewed Phase 4 plan. The unrelated untracked prompt remains excluded.
