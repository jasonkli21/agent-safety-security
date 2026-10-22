# Phase 9 local multi-agent implementation report

## 1. Baseline, authorization and inherited gates

Starting HEAD: `1619ac45da9edd54425f116f70acc5d3e72825e8`, branch `main`.
This matched the supplied handoff's planning baseline; no newer local commits were present.
Initial dirty state contained only untracked `PHASE-0-SOL-MEDIUM-PROMPT.md` and
`docs/plans/phase-9-implementation-plan.md`. The Phase 9 plan is included in this commit;
the unrelated Phase 0 prompt is untouched and excluded. Final HEAD is the single implementation
commit containing this report; its resulting SHA is given in the session handoff because a commit
cannot embed its own resulting SHA. No push, PR, deployment or publication was requested/performed.

The user's explicit request authorized Phase 9 implementation despite the older AGENTS phase
boundary. It did not accept Phase 7 or 8. Fresh independent Phase 8 review and combined Phase 7–8
release acceptance remain **unconfirmed**. This implementation and self-review do not close them.
No subagents, delegated chats or independent reviewers were used.

Read sources: attached implementation handoff, AGENTS, PRD (including Phase 9 and §§11.6–11.9),
architecture and appended Phase 3–8 decisions, Phase 9 plan, relevant Phase 6/8 integration plans,
identity/delegation, provenance, evidence, replay, conformance, adapters/isolation, runtime MCP,
supply-chain and threat docs, Phase 7/8 implementation and review-fix reports, and actual runtime,
compiler, policy, identity, adapter, replay, evidence and test seams. Readiness is taken from the
review-fix reports, not inferred from the README. No PRD rewrite or historical-report rewrite
was used to justify changed implementation scope.

Environment: existing repository `.venv`, Python 3.12 on macOS. No dependency changes,
installation, paid/model API, remote identity service or Docker daemon was needed.

## 2. Module/API and call-chain map

| Surface | Implemented path |
| --- | --- |
| Canonical graph | `domain/graph.py`: AgentNode, DelegationEdge, GraphSnapshot, GraphBinding, AncestorDecision |
| Compiler | `compile_contract(..., multi_agent=True)` → `phase9-v1`; default Phase 6 and historical Phase 4 retain their wire shape |
| Shared ceiling | `policy.native.compiled_ceiling`: extracted existing task/tool/data semantics, reused by standalone and ancestor policy |
| Path proof | `multi_agent/authority.py`: GraphMaterial, ParticipantFacts, check_path, decide_path |
| Protected owner | `multi_agent/session.py`: MultiAgentSession activation, retirement, replacement, exact providers/plans and per-node SessionGuard |
| Recursive accounting | `multi_agent/budgets.py`: one HierarchicalBudgets coordinator and gateway-compatible node views |
| Common enforcement | `RuntimeGateway.call`: graph commitment, combined policy/broker, ancestry reservation, trust/freshness and final pre-entry checks |
| Messaging | `multi_agent/messaging.py`: fixed MessageRoute, protected sender action, receiver import/evidence before body release |
| Evidence | typed versioned GRAPH_EVENT lifecycle/message payloads and optional omitted graph/ancestor fields |
| Assurance | `multi_agent/conformance.py`, `multi_agent/replay.py`, `multi_agent/regression.py`; Phase 1 trajectory/assertion reuse |
| Operator CLI | `graph validate`, `graph replay`, `graph regression` |
| Public demonstration | `examples/multi_agent/local_session.py`, contract template, graph snapshot, separate synthetic replay source and minimal incident manifest |

The concrete change map is compiler → protected graph/provider/plan admission → common pure
policy ceilings → gateway action/approval identity → atomic recursive budgets and final trust/
expiry gates → fixed message dispatcher → receiver evidence/provenance → offline replay and
minimal explicit incident regression. Adapter/framework inputs never supply graph authority.

## 3. Graph, identity, immutable state and mode behavior

The local topology is a bounded rooted single-parent tree, not a general graph scheduler.
Graph caps are 32 nodes/edges, depth/fanout 8, 8 KiB canonical grant per edge and 128 KiB graph.
Each node/principal/grant ID is unique; every node has one exact finite grant. Validation rejects
cycles/orphans, unknown parents, duplicate/multiple-parent edges, self links, incorrect parent
IDs/principals, cross-task chains, invalid validity windows, child validity outside parent validity,
unknown fields/versions and coercion. Canonical ordering makes insertion permutation irrelevant.
Canonical grant strings prevent nested resource-map aliasing.

GraphMaterial binds independently compiled participant plans, exact principals, direct OBO parent,
task identity, verified credential summaries and complete ancestor commitments. Session admission
calls each configured Phase 6 provider; raw credentials are not saved. Static configuration is
local trust, not remote authentication. Tests exercise a real locally signed pinned JWT provider,
missing proof, unsigned proof and mismatched providers. The root USER/SERVICE and finite root grant
are explicit protected local assertions; no user token is fabricated.

Protected inputs: graph/topology, contracts/plans, root/edge grants, provider/key/mapping config,
clock, broker, evidence sinks, source/sink classifications, tool routes, trust pins and isolation.
Untrusted inputs: model/provider arguments, messages, claimed sender IDs, descriptions/discovery,
caller labels/foreign refs and purported receipts. Agents receive their own tool/route handles;
operator session mutation/receive APIs must not be exposed as tools accepting model-selected IDs.
Python privacy is an application convention, not hostile-code isolation inside the interpreter.

Session state belongs to its constructing thread and first running event loop. Replacement accepts
validated snapshots with a strictly greater generation, even for A→B→A content restoration. Node,
principal, plan and root replacement require a new session. Revocation/finish retires membership
permanently; a closed ancestor invalidates new descendant actions. Replacement records lifecycle
commitments; evidence failure retires all active nodes. Already-entered effects are not undone.

Only ENFORCE graph sessions are supported. SHADOW/DISABLED graph guards and noncritical evidence
refuse setup with GRAPH_MODE_UNSUPPORTED. Standalone legacy modes retain their prior behavior;
no forged peer is forwarded as authenticated graph enforcement.

## 4. Restrictive authority, approvals and dispatch finality

For each descendant action, check every path grant's capability/task/resource scope, every
participant credential ceiling and validity, and every ancestor's compiled task/tool/data policy.
Null restrictions remain different from explicit empty sets; matching stays exact. Data rules
restrict ordinary authority. DENY/ERROR wins over REQUIRE_APPROVAL, which wins over ALLOW.
Decisions record per-ancestor plan IDs, outcomes, reasons and matched rule IDs.

Graph digest/generation/node/path and complete path-authority digest bind PolicyRequest and
NormalizedAction, alongside existing provenance, route and trust commitments. A graph string in
a standalone request is rejected rather than treated as proof. Ancestor approval is one actual
combined exact-action session-broker step, with the strictest path timeout. No child-only approval
can discard the requiring ancestor, and no denial invokes the broker.

The gateway checks the live path before authorization, after awaited approval and again after
critical dispatch evidence. A synchronous evidence callback can change graph/trust state or
consume runtime: final trust and committed-budget validation now run after that write, followed
by the graph check and dispatcher entry with no intervening await. Receipt compensation handles
pre-entry failure exactly once. Tests prove no dispatcher effect on ABA replacement, root expiry,
reentrant revocation, trust drift or exhausted runtime after a slow evidence callback.

TOOL_DISPATCHED is an entry-intent fact, not effect verification: a synchronous final rejection
can follow its successful write. Post-entry failure/cancellation retains accounting and explicit
unknown-effect signals. Arbitrary trusted dispatchers can await internally or have partial effects;
revocation cannot promise rollback or zero effects after entry.

## 5. Atomic recursive budgets and agent caps

One coordinator and one critical section reserve the complete ancestry. Pending approvals count
against shared parent capacity, so concurrent siblings cannot both consume the last slot. Direct
parent and descendant calls use the same counters. Supported counters are calls, external writes,
destructive actions and monotonic runtime. Reservations bind node/path, graph generation and action
digest; final checks revalidate the same receipt. Node views contain no independent quota state.

Unique tokens transition pending → committed → nonrefundable entry. Denial, approval timeout,
cancellation, stale graph/trust and pre-entry evidence errors release or compensate the exact
token. Repeated compensation cannot refund another call. The old decrement-by-tool refund was
removed from the shared ledger as well. Dispatch errors after possible effects stay charged.

Delegated-agent caps count distinct descendant principals ever admitted under every ancestor
in the session. Startup failure does not erase history. Retirement forbids reactivation, and
replacement cannot rename a principal to evade a cap. Counters survive replacement. There is
no cross-host/global quota, model-call, token or dollar accounting; unsupported contract intent
still blocks coverage, including zero values.

## 6. Messaging, provenance, privacy and uncertainty

MessageRoute fixes an explicitly configured adjacent sender/recipient, with separately configured
reverse direction if wanted. Nonadjacent/sibling routes reject before content. The only action is
agent.message.send, through the sender gateway and reviewed `agent:RECIPIENT` destination.
Arguments cannot choose sender, peer, labels, graph or source refs. Ancestor policy/approval/data,
budget, route/trust and ordinary gateway restrictions remain active.

Before dispatcher entry, the sender snapshots its real frontier. Receiver admission checks both
live paths/epoch, adjacency, unique bounded message identity, source dispatch/run/trace/request,
actual source refs and bounds. Sender labels union with USER_PROVIDED/UNTRUSTED_CONTENT; recipient
local frontier labels also survive. Foreign ancestry is referenced by commitment, not registered
as locally verified data. Critical recipient evidence precedes frontier commit and content release,
without an await. Receiver failure does not expose content or alter its frontier.

Limits are 64 KiB per body, 64 source/receiver frontier refs and 1024 successful messages per
session. Evidence stores safe source/recipient causal IDs, hash, size and artifact labels, never
body/JWT/resource values/arbitrary claims. Existing protected IDs/categories must themselves be
nonsecret. Text does not authenticate or mutate delegation, and arbitrary message text is not
semantically classified for secrets. RELEASE_COMMITTED is not model consumption. Sender entry
followed by receiver/return failure remains potentially effectful and is charged accordingly.

## 7. Evaluation, replay, incidents and compatibility

Graph conformance uses existing independent finite policy partition/oracle logic and the same
pure path evaluator. It generates missing graph/identity, wrong epoch, unknown capability,
expired-ancestor and bounded-budget probes. The checked-in source produces 45 PASS, 0 FAIL and
12 NOT_RUN obligations. Broker/agent-cap/label lifecycle coverage stays explicitly NOT_RUN in
this pure report; real session tests exercise those properties. A single Phase 9 plan's generic
conformance report says graph-session-required, not a synthetic Phase 6 pass.

GraphReplayInput binds complete ordered source evidence separately from optional protected graph/
participant/request/action material and reviewed tool metadata. Local Phase 1 trajectory checks
validate each run; shared policy, ancestry budgets, approval ledger and provenance reconstruct
recorded-time structured semantics. Delivery checks validate source dispatch causality, adjacent
route, source frontier commitment, labels and matching receiver import. Replay has no provider or
live dispatch port and never verifies a JWT afresh, delivers a message, starts a model/tool/network
or launches isolation. Source integrity hashes are not authentication of source storage.

Source fidelity and candidate graph equality are separate. Missing ancestors/material, modified
binding/path/digest, forged delivery/labels, resource redaction, missing exact approval actions,
unresolved reservation lifecycle, unknown monotonic duration, source uncertainty or epoch changes
produce INCOMPLETE with blockers. Only a matching supplied compiled task scope can recover task
redaction, and the complete request digest must still match. Single-epoch replay is intentional;
arbitrary operator epoch-history reconstruction and changed-candidate policy execution are not
claimed. Candidate equality alone never proves remediation or trust attestation.

Historical bundle creation recognizes phase9-v1 but single-agent substitution blocks with
GRAPH_SESSION_REPLAY_REQUIRED. Generic promotion remains DRAFT. `promote_graph` instead checks
the existing classified incident and exact selected run against a separately supplied complete
session source, then exports only a minimal assertion/commitment manifest. ACTIVE requires explicit
safe TOOL_NOT_CALLED/MAX_TOOL_CALLS/APPROVAL_REQUIRED expectations and unblocked source replay.
`run_graph_case` requires the exact protected source again and reuses Phase 1 assertions. Tests
show both a passing no-write assertion and failure of an assertion contradicted by a real read;
missing source blocks. No policy, trust lock, graph grant or credential is auto-exported/edited.

Legacy default compilation was compared with an isolated archive of 1619ac4. For
examples/mcp/contract.yaml both compiled-plan digests are exactly:
`sha256:8ef6116d19696ab59940bed483a985ef53c05e292620067a2aa170a395a29619`.
No historical tests/fixtures or examples/regressions files changed. Absent graph fields and empty
ancestor details are omitted, preserving old action/event/bundle shape. Existing golden, replay,
MCP and regression suites pass. New schemas were exported from typed models, never hand edited.

## 8. Adversarial verification matrix

| Threat/property | Precise observed assertion |
| --- | --- |
| Two-hop distinct authority | C read dispatches once; C write has zero dispatches despite own allow and ancestor deny |
| Parent approval/ABA | No effect before real awaited broker; generations 1→2→3 invalidate approval and leave no reserved/used quota |
| Expiring ancestor | Root credential expires during approval; child dispatch absent; pending quota released |
| Topology/schema | Duplicate nodes/edges, bad parent IDs/tasks, self links, root type, expiry overflow, coercion, unknown fields/version, grant bytes, depth/fanout fail validation |
| Empty/narrow authority | Empty credential/grant/resource sets deny; exact permitted resource succeeds and other resource cannot dispatch |
| Identity | Independently pinned local JWT fact accepted; missing/unsigned proof and wrong provider principal reject before activation; no token serialized |
| Shared last slot | One sibling's pending approval reserves the parent slot; second sibling raises BUDGET_EXCEEDED; cancellation frees the slot |
| Critical evidence | Dispatch-write failure refunds exact receipt; second sibling can use capacity; double refund leaves counters zero |
| Final synchronous race | Evidence callback revokes root or advances runtime deadline; dispatcher effect list remains empty and quota compensates |
| Possibly effectful failure | Dispatcher appends an effect then fails; ancestor quota remains used and subsequent call is over budget |
| Cap churn | Descendants b/c count under a permanently; retired c cannot reactivate and history remains b/c |
| Message success | Actual A→B→C body relay succeeds; SECRET/PII survive; content is absent from all canonical evidence |
| Flow/route failures | Sensitive forbidden-destination message has no dispatch/body; sibling/nonadjacent route rejects; receiver evidence failure withholds body/frontier update |
| Adapter/trust composition | Real MCP Client/Server call succeeds once; revoked root prevents second upstream call; provider rebind cannot erase ancestor deny or evade trust pin |
| Replay/incident | Valid recorded read/deny/message reconstruct; missing material blocks, forged receiver labels block; minimal incident manifest passes explicit no-write assertion and contradictory no-read assertion fails |
| Historical behavior | Old compiler digest exactly equal, all preexisting fixtures unchanged, full local suite/regressions pass |

Key tests: tests/unit/test_multi_agent.py (44 cases) and
tests/integration/test_multi_agent_integration.py (4 cases). The latter includes a real in-memory
MCP SDK ingress. Shared Phase 7/8 tests retain HTTP/process/isolation/trust coverage; no live
Docker/gVisor smoke or remote authentication claim is made.

## 9. Exact commands and results

All commands ran in this session from the repository root. Initial sandboxed full suite:
`.venv/bin/pytest -q` → 813 passed, 9 existing HTTP/HTTPS fixture setup errors because loopback
socket bind was denied. No tests were weakened. A subsequent intermediate full run found two
implementation compatibility issues (legacy compile monkeypatch call shape and exhaustive event
fixture); both were fixed. An early example waited indefinitely because a fixture changed a sorted
rule by position; it was interrupted and corrected to select explicit rule IDs. Transient focused
fixture mistakes (wrong denied-tool metadata) and formatting/import errors were fixed and rerun.

| Final command | Result |
| --- | --- |
| `.venv/bin/pytest -q tests/unit/test_multi_agent.py tests/integration/test_multi_agent_integration.py` | PASS — 48 tests |
| `.venv/bin/pytest -q` | PASS — 871 tests in 21.60s, with approved loopback test-server access |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS — 197 Python files |
| `.venv/bin/mypy src` | PASS — 121 source files |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS — generated from typed source; full-suite freshness checks pass |
| `.venv/bin/agentsec examples validate` | PASS — indexed corpus 3 contracts, 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS — all 6 expected outcomes matched |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS — 2 ACTIVE passes, 1 DRAFT |
| `.venv/bin/python examples/multi_agent/local_session.py` | PASS — actual gateway read/deny/relay/budget/sibling/approval-epoch assertions |
| `.venv/bin/agentsec graph validate --config examples/multi_agent/graph.json` | PASS — structural validity, explicitly not authentication |
| `.venv/bin/agentsec graph replay --config examples/multi_agent/replay.json` | PASS — SECURITY_SEMANTIC, 2 checked requests, no live effects |
| `.venv/bin/agentsec graph regression --case examples/multi_agent/regression.json --source examples/multi_agent/replay.json` | PASS — explicit incident no-write assertion |
| `.venv/bin/python -m build --no-isolation` | PASS — wheel and sdist |
| `git diff --check` | PASS |

No required verification command was intentionally omitted; interpreter paths were adapted to
.venv. The suggested integration filename was changed to avoid pytest basename collisions.
Loopback permission was used only for existing local fixture servers. No external endpoint,
real credential, model, remote registry or Docker daemon participated.

## 10. Scope decisions, residual risks and self-review

Deliberate secure restrictions relative to broad plan suggestions:

- ENFORCE-only graph sessions; unsupported mode composition refuses setup.
- All participants are verified from an operator-declared snapshot at session creation; new
  principals/plans or reauthentication require a new session. Permanent retirement prevents churn.
- One recorded graph epoch per replay. Epoch history, runtime duration without monotonic facts,
  exact approval material and material redactions remain explicit blockers rather than guesses.
- Stateful broker/label/cap proofs are real focused session tests, not credited as pure generated
  conformance. Finite synthetic policy/ledger coverage is reported separately.
- Graph incident export is a minimal manifest with a required separately protected source. The
  historical self-contained promotion path stays DRAFT rather than exporting authority/resources.
- Candidate graph comparison is commitment equality, not changed-candidate execution or full
  graph remediation simulation. Remote peer transport and distributed atomicity are unsupported.

Self-review inspected child→ancestor denial/approval paths, graph authenticity versus commitments,
provider binding, aliasing, resource/null/empty semantics, sibling contention, pending cancellation,
compensation, actor/peer roles, label laundering, receiver evidence-before-release, replay source
links, and historical omissions. Reproducible issues fixed during that review included ancestor
source-classification coverage, minimum approval timeout, admission evidence failure cleanup,
reentrant pre-entry revocation, and budget/trust expiry during synchronous evidence recording.
This is implementation self-review, not independent acceptance.

Residual TCB risks: operator application code can expose raw dispatchers or wrong node handles;
in-process Python privacy cannot contain malicious host code. Trusted tool classifications and
fixed resource mappings are assertions, not semantic attestation. Message contents may contain
unclassified secrets; no complete initial/model-internal taint or semantic DLP is claimed. Hashes
reveal equality and do not authenticate evidence. Effects after dispatcher entry may be partial or
unknown. Running code, remote implementations, Docker/gVisor behavior and cross-process quotas
remain unproven. Independent reviewers should prioritize those boundaries, final no-await ordering,
receipt state transitions, combined approval action binding and causal replay admission.

## 11. Documentation and readiness

Added focused multi-agent documentation, example README and report; updated AGENTS, current README,
docs/report indexes, architecture appendix, identity, provenance, evidence, replay, conformance,
adapters, MCP, trust and threat notes. PRD and historical reports are unchanged. The supplied Phase 9
plan is preserved as planning provenance, with status pointing to actual implementation limits.

The bounded local slice is implemented and ready for independent review. Passing tests do not
establish independent Phase 9 acceptance, close Phase 7–8 release gates, authorize hosted Phase 10
work or prove unsupported remote/distributed/model-content claims.
