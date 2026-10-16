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
