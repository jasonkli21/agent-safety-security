# Phase 4 implementation report

## Baseline and status

Implementation baseline/HEAD: `3b9bc15abfbe70403afc858ec6811c7ff78c6489`
(`fix: address phase 3 independent review findings`). No newer commits or tracked modifications
were present. The supplied Phase 4 plan and unrelated `PHASE-0-SOL-MEDIUM-PROMPT.md` were untracked.
The implementation includes the Phase 4 plan, normalizing Markdown trailing hard breaks only;
the unrelated prompt remains untouched and excluded. The user explicitly authorized scheduled
Phase 4 implementation in this chat at October 16, 2026, 02:00 PDT / 09:00 UTC and one commit.
Work began on that scheduled invocation. The attached implementation prompt is the task
specification, not independent authority to override higher-priority instructions.

The repository's old phase-boundary text gated Phase 4 on Phase 3 review/fixes and a next-phase
plan. The baseline contains the Phase 3 independent-review corrections, the supplied Phase 4
plan declares implementation readiness, and the user explicitly requested implementation.
No further independent acceptance/approval is inferred. Phase 4 is ready for a fresh independent
review, not independently approved. Phase 5 remains gated on review/fixes and its reviewed plan.
The implementation revision is the single feature commit containing this report; its own final
SHA cannot be embedded in this file without changing it.

## Scope implemented

- Content-free, protocol-independent provenance graph with immutable registration, exact parent
  lookup/lineage, monotonic derived label union, duplicate/conflicting ID and unknown-parent
  rejection, injected clock/IDs, and locked exposed-frontier snapshot/commit operations.
- Executable immutable compiled data rules under compiler `phase4-v1`; restrictive native
  capability/destination set semantics, any-label denial, explicit missing-context error,
  preservation of base denies/errors/approval requirements and exact rule provenance.
- Canonical unique artifact refs and destination on policy/action inputs. Exact action approval
  binding and complete policy-input digests include data context.
- Distinct factual returned and guarded-exposure evidence. TOOL_RETURNED carries artifact refs;
  typed DATA_EXPOSED precedes frontier commitment/release. ENFORCE critical-write failures
  withhold release and poison subsequent calls. Rejected output does not taint later calls.
- Additive MCP reviewed source-label/static sink-category configuration, conservative
  preflight/discovery classification gates, source/sink proof dimensions and snapshot freshness.
  Existing data_access_labels retains its prior meaning. Tool errors that are returned remain
  untrusted output; transport exceptions produce no artifact. SHADOW retains true decisions,
  signals and exposed output; DISABLED has no enforcement decision.
- Independent, non-vacuous generated flow obligations, source-return/exposure Phase 1 cases, explicit
  non-derivable NOT_RUN, dimensioned coverage and finite exact data-policy diff independent of
  ordinary tool-authority changes. Data changes no longer appear as unsupported intent.
- Synthetic source→external and untrusted→memory example pair, updated focused docs, repository
  guidance, public generated schemas and canonical event golden form. No dependency was added.

## Security semantics and trust assumptions

Ordinary identity/task/tool authorization remains first. Only ALLOW/REQUIRE_APPROVAL reaches
the data clamp. Applicable rules match exact labels in the trusted artifact union. Membership
in a denied capability set, exclusion from a nonempty allowed capability set, denied destination
membership or exclusion from a nonempty destination allowlist yields DENY / DATA_FLOW_DENIED.
An empty allowed set is unrestricted on that axis. If applicable destination sets are nonempty
and destination is missing, ERROR / DATA_FLOW_CONTEXT_MISSING results unless an explicit flow
denial already applies. Matching provenance retains matching tool IDs plus all applicable data
rule IDs; base-denied decisions retain their original explanation. Multiple-label denial and
explicit-denial-over-missing-context precedence are independent of authored order.

Every released MCP output gets TOOL_OUTPUT/UNTRUSTED_CONTENT, explicit configured labels and
its request snapshot's labels. These are exact tags, without implied label lattice or automatic
declassification. Every request snapshots the frontier before authorization. Response parents
stay bound to that snapshot even if concurrent responses expose later. Exposure replaces only
those parents in the frontier, retaining unrelated concurrent branches. The graph uses locked
synchronous operations, and no lock spans network/human I/O. There is no await between critical
exposure recording, frontier commitment and return. Post-exposure requests see the committed
frontier. Context is protected runtime state; tool arguments cannot forge or clear it.

For nonautomatic-label data rules, all configured/discovered bound tools require explicit
reviewed output labels: null means unreviewed, [] means reviewed without extra labels. For any
destination-constrained policy, all such tools require trusted sink categories, including read
tools that receive ambient context. ENFORCE refuses missing classification before serving;
SHADOW reports gaps and gives affected calls explicit context ERROR while forwarding. Static
categories are operator assertions. The gateway does not infer destinations from arbitrary URLs,
paths or recipients. Adapter proof remains bound to exact plan and serialized discovery/bindings;
source/sink proof statuses are reported separately. These are freshness identities, not attestations.

Refs/events contain IDs, labels, origin, parents, timestamps and response hashes, never raw
response bytes. Source IDs are trusted tool identities, and configured IDs/categories must not
contain secrets. Policy-input/action digests cover exact context independently of redacted
resource/task evidence. Hashes disclose equality and are not encryption. Native policy assumes
trusted request producers, as it already assumes trusted principal/capability metadata.

## Architecture decisions and deviations

- Reuse the frozen canonical DataRule in the compiled plan rather than duplicating a flow IR.
  Effective-policy hashing already includes data rules; its projection is unchanged. Compiler
  version changes because those rules now execute. Plan digest still binds the entire inventory.
- Use a small synchronous RLock service for graph/frontier atomicity rather than an async graph
  subsystem. Normal sequential context carries one frontier node; graph nodes store parent IDs,
  preserving O(number of artifacts) session lineage without copying full ancestry per request.
- Create/register the returned artifact immediately before TOOL_RETURNED emission so that the
  factual return event can contain its reference. This resolves the plan's schematic ordering
  that listed recording return before artifact creation. Creation does not expose anything.
- DATA_EXPOSED carries the complete content-free ref rather than only IDs, making exact prior
  return comparison unambiguous. The exposure callback writes evidence under the frontier lock
  before state commit. In-process commit-to-release is atomic with respect to requests, but
  neither exposure nor MCP transport proves eventual model ingestion.
- Extend existing resource/binding coverage functions and preserve the startup code
  UNSUPPORTED_RESOURCE_COVERAGE for all binding-input gaps. Exact gap names distinguish
  data_source_classification and data_sink_destination; affected SHADOW calls use
  DATA_FLOW_CONTEXT_MISSING / UNSUPPORTED_DATA_COVERAGE. No divergent coverage subsystem exists.
- Direct policy probes inject trusted synthetic derived refs to verify the policy clamp and exact
  explanation. Generated Phase 1 flow cases instead emit a labeled source return and exposure
  before making the sink request. The trajectory validator reconstructs the exposed frontier and
  verifies request snapshots, returned parents, inherited labels and sibling-branch compaction.
  Expected decisions remain independent declarative label/set obligations. Missing base-permitted
  axis witnesses are explicitly NOT_RUN, never vacuous PASS.
- Data diff gives both compiled plans an identical synthetic base grant and removes task scope
  only for the pure clamp comparison; real authority/scope differences still use the original
  native partition. Synthetic grant ID and OTHER values avoid collisions with either plan.
  Single-label partitions are sufficient for these independent exact rules composed by any-deny;
  no inter-label predicates exist. Set edits and rule additions/removals remain separately visible.
- Additive pre-1.0 public changes retain schema 0.1, following the existing repository convention.
  Strict old readers need regenerated schemas. New default action fields change digests even
  without configured data rules; regenerate approvals/manifests/reports rather than reusing
  old identities. Session approvals were already nonpersistent. The authored contract shape and
  hash projection are unchanged. No PRD rewrite or later-phase framework was introduced.

## Verification

All commands used the existing local `.venv`. The default suite forbids network connections;
no credential, model, hosted service or network test was added. The Phase 3 report records a
502-test baseline; the first development subset exposed the three old assertions that expected
data rules to remain unsupported. Those assertions were updated for the intended new semantics.
Intermediate failures from new fixtures/SDK host validation/type inference were corrected;
they are not represented as successful verification below.

| Exact command | Final result |
| --- | --- |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 113 files already formatted |
| `.venv/bin/mypy src` | PASS, 68 source files |
| `.venv/bin/pytest -q` | PASS, 548 tests |
| `.venv/bin/pytest -q tests/unit/test_provenance_flow.py tests/integration/test_mcp_gateway.py -k 'phase4 or provenance or flow or exposure or stdio'` | PASS, 51 tests, 32 deselected; includes existing two-process MCP stdio smoke |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts and 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS, all 6 expected outcomes matched |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS; full-suite freshness/JSON Schema tests passed |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel; pre-existing optional examples JSON glob warning |
| `git diff --check` | PASS |
| `.venv/bin/agentsec protect mcp --contract examples/mcp/flow-contract.yaml --config examples/mcp/flow-gateway.yaml --check` | PASS, ENFORCE |
| `.venv/bin/agentsec contract test examples/mcp/flow-contract.yaml --format json` | PASS, 26 direct probes and 26 Phase 1 cases |

Focused tests cover SECRET/PII/CREDENTIAL→external, automatic untrusted→memory, otherwise
permitted sink authority, missing classification refusal, source/sink proof freshness, tool-error
exposure, blocked/SHADOW-invalid response behavior, same-argument approval context changes,
concurrent branches/causality, failed critical exposure record/poison, transport exceptions,
canonical duplicate rejection, malformed binding classification and exact exposure causality.
Mutant engines that omit flow context fail both direct and Phase 1 conformance. Negative graph
registration tests reject relabeling and forged parents. A diff regression ensures a real data
rule named diff-base cannot collide with the synthetic comparison grant and hide explanation.

## Mandatory self-review

Reviewed the prompt's failure-mode list against the implementation and focused tests:

- Data policy cannot grant authority; base deny/default/task checks precede the clamp, and
  approval survives a nonblocked flow. Applicable explicit denial overrides missing context.
- Missing source/sink configuration refuses ENFORCE; nullable source classification stays
  distinct from reviewed empty labels. Agent arguments cannot supply flow metadata.
- NormalizedAction and full policy-input digest include provenance and destination. Approval
  digests change for identical arguments after exposure. data_access_labels was not reinterpreted.
- Withheld responses have returned artifacts but no exposure; critical recording failure yields
  no release/frontier commit. SHADOW-forwarded/error output is tracked. Transport exceptions do
  not manufacture artifacts. Concurrent earlier snapshots remain unchanged, later snapshots
  see all exposed branches, and only actual parents are compacted.
- Changed source/sink config changes discovery digest; changed data rules/compiler change exact
  plan identity. Existing stale-plan/proof, request-ID, cancellation, budget and evidence tests pass.
- Generated expectations never call the native evaluator. Flow cases require ordinary permitted
  witnesses; unreachable cases are NOT_RUN. Coverage explicitly states unobserved user/model
  text and content detection remain outside the boundary. Data diff is executable and separate
  from ordinary authority, with explanation/set changes and collision-free representatives.
- Raw responses remain ephemeral and only their digests enter persistent evidence. Core
  compiler/provenance modules import no MCP SDK/config types. No replay, incident, identity,
  hosted service, sandbox, classifier or declassification scope was added.

No substantive self-review issue remains unresolved in this implementation. These checks are
self-review, not independent approval.

## Independent review fixes

The follow-up review identified four issues and this report records their fixes:

- Adapter proof now separates reviewed source/sink classification from per-rule source/sink
  runtime reachability. `adapter_status=COVERED` requires both classification completeness and
  any required exact topology witnesses; it does not claim that the runtime flow was exercised.
- Evaluation trajectory validation reconstructs the exposed artifact frontier, checks every
  request snapshot, validates returned artifact parents and inherited labels, and preserves
  concurrent sibling branches. Generated Phase 1 flow cases now include source return/exposure
  before the sink request.
- Dispatcher exceptions no longer emit `TOOL_RETURNED`; dispatch is the last factual lifecycle
  event when the upstream returns no response.
- Authored data-rule diff paths use `data.rules/{rule_id}`.

### Review-fix verification

| Exact command | Result |
| --- | --- |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 114 files formatted |
| `.venv/bin/mypy src` | PASS, 68 source files |
| `.venv/bin/pytest -q tests/unit/test_provenance_flow.py tests/unit/test_runtime_state.py tests/integration/test_mcp_gateway.py` | PASS, 109 tests |
| `.venv/bin/pytest -q` | PASS, 553 tests |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS; generated schemas refreshed from source models |
| `.venv/bin/agentsec examples validate && .venv/bin/agentsec eval examples` | PASS; 3 contracts, 3 scenarios, all expected outcomes matched |
| `.venv/bin/agentsec protect mcp --contract examples/mcp/flow-contract.yaml --config examples/mcp/flow-gateway.yaml --check` | PASS, ENFORCE |
| `.venv/bin/agentsec contract test examples/mcp/flow-contract.yaml --format json` | PASS; direct probes and Phase 1 cases matched |
| `.venv/bin/python -m build --no-isolation` | PASS; sdist and wheel (existing optional examples JSON glob warning) |
| `git diff --check` | PASS |

The full suite includes regressions for classification versus source/sink reachability, generated
source-return/exposure causality, forged/omitted request provenance, returned parent mismatch,
inherited-label loss, no-return transport failures and rule-ID diff paths. No Phase 5 scope was added.

## Known limitations and readiness

The conservative frontier can over-taint legitimate calls. It covers only observed/released
tracked tool data, not initial user text, hidden model context, side channels, bypassing clients
or tools outside the protected gateway. A direct sink call before tracked sources can carry
unknown sensitive text; absence of tracked labels is not a content-security guarantee. Reviewed
source labels/static sink categories and upstream execution honesty remain operator assumptions.
There is no token/value matching, semantic secret/PII detector, label lattice or declassification.

Lineage/frontier is session-local, without eviction or persistence; long unbounded sessions and
wide concurrency can grow memory use. Supported tool-call budgets can bound dispatched artifacts.
Exposure proves a committed gateway release, not transport receipt/model use; crashes can leave
incomplete evidence/transport. Evidence is not tamper-resistant and cannot undo external effects.
Proof/digests establish content freshness, not authenticity. Generated cases cover synthetic
policy/evidence and do not measure model robustness or real content classification. Some flow
axes may be non-derivable under authored base authority and stay visibly NOT_RUN.

Phase 4 is ready for fresh independent review. Phase 5 replay/incident packaging is not implemented
and must await review/fix acceptance and a reviewed plan. This phase supplies factual returned/
exposed/request context linkage for that later work without claiming independent approval.
