# Agent Safety & Security — Phase 9 Detailed Implementation Plan

**Phase:** 9 — Multi-Agent Security
**Status:** Local implementation complete; independent review pending. Actual scope/deviations: `docs/reports/phase-9-implementation-report.md`.
**Repository:** https://github.com/jasonkli21/agent-safety-security
**Planning baseline:** `main` at `1619ac45da9edd54425f116f70acc5d3e72825e8` (`fix: address phase 8 trust review findings`, 2026-10-22 UTC)
**Primary roadmap source:** `docs/prd.md` §16, Phase 9; also §§11.6–11.9, 12–13, 17–19
**Architecture sources:** `docs/architecture.md` §§3, 5–6, 9–14, 17–18, 22–26 and appended Phase 3–8 notes
**Current source-of-truth companions:** `AGENTS.md`, `docs/identity-delegation.md`, `docs/provenance-data-flow.md`, `docs/evidence-model.md`, `docs/replay-incidents.md`, `docs/runtime-mcp.md`, `docs/adapters-isolation.md`, `docs/supply-chain-trust.md`, `docs/contract-conformance.md`, `docs/reports/phase-7-review-fixes-report.md`, `docs/reports/phase-8-implementation-report.md`, `docs/reports/phase-8-review-fixes-report.md`.

> **Review gates are not silently closed.** The repository contains Phase 7 and 8 implementation/review-fix reports, but the Phase 8 fix report explicitly calls for fresh independent review and says combined Phase 7–8 release acceptance is unconfirmed. Phase 9 planning is authorized here, but implementation/release must record the actual preflight state and must not relabel earlier phases as accepted. Reconcile `main`, working tree, new docs and reports before writing code.

## 1. Product outcome and boundary

Deliver one **credible local-first, in-process multi-agent security vertical slice**: an operator-controlled session of multiple distinct agent principals can pass messages and delegate restricted tasks through a bounded graph; each child action is checked against its own contract **and every applicable ancestor ceiling**, with provenance and recursive resource budgets preserved. Security evidence supports offline reconstruction and negative evaluation. The model/agent never chooses its own verified identity, parent, grants, budget, provenance labels, trust roots or operator configuration.

The PRD names six Phase 9 capabilities. Their concrete minimum in this phase is:

| PRD outcome | Phase 9 deliverable | Honest limitation |
| --- | --- | --- |
| Delegation graph | Immutable, bounded, protected single-parent DAG/tree snapshot, generation/digest, revocation | Not a generic agent orchestrator or graph database |
| Agent-to-agent identity | Protected per-agent principal binding using Phase 6 trusted static or pinned signed-JWT verification; explicit peer/session binding | No remote mutual authentication, federation or production identity issuance |
| Transitive authority | Full ancestor chain plus direct-grant links; action-time intersection of scopes, credential ceilings, contracts and policy/data restrictions | No free-form policy language or semantic resource equivalence |
| Message provenance | Protected parent/child message ingress/egress, content-free lineage and monotonic labels | Not model-internal taint or cryptographic proof of arbitrary external messages |
| Recursive budgets | Atomic ancestor/subtree counters, reservation/finalization and delegated-agent cap | No globally consistent cross-process quota or model-token/cost accounting |
| Laundering/scenarios | Deterministic graph attack fixtures, evaluation, replay and incident/regression cases | No claim to detect every linguistic/social multi-agent attack |

### 1.1 Actual implementation boundary at planning HEAD

- Phase 6: `Delegation` already has `parent_delegation_id`, but `identity.authority_failure` **rejects any parent chain**; `AuthorityContext` freezes **one** `delegation_json`. `identity.acts_on_behalf_of` is an exact **direct** parent, and `VerifiedCredential` contains only safe facts. `phase6-v1` is current; `phase4-v1` remains historical.
- `Budgets.max_delegated_agents` exists in the authored contract but is explicitly **unsupported** by the compiler; `BudgetLedger` is **one session's** pending/used counters for calls/writes/destructive actions/time. `max_model_calls` and `max_cost_usd` are also unsupported.
- `RuntimeGateway` is the common enforcement point. It snapshots authoritative identity, emits action-bound evidence, reserves budgets, redeems a one-shot approval, rechecks authority/trust and then commits dispatch synchronously without an intervening await. This ordering is security-critical.
- Phase 4 provenance is a per-gateway exposure frontier with monotonic labels; it does not know cross-agent delivery. Phase 5 replay is **offline semantic substitution**, not execution. Phase 7 protected routes/isolation and Phase 8 restrictive trust admission already compose with the gateway.
- Existing source paths include `src/agentsec/{domain/identity.py,domain/authority.py,identity/authority.py,identity/setup.py,policy/native.py,compiler/{compile.py,models.py},runtime/{gateway.py,budgets.py,approvals.py,events.py},provenance/engine.py,replay/{bundle.py,engine.py},eval/*}`. Inspect these and current tests rather than assuming proposed filenames below are already present.

### 1.2 Release prerequisites and compatibility

1. Establish a clean/readable baseline: HEAD/branch/status, pending reviews and changes, Python/env, full and focused tests, schema generation, lint/type status. Do not overwrite unrelated work.
2. Implement on a bounded phase-specific feature path, not by changing legacy one-hop interpretation in place. Old contracts, compiler plans, digests, event JSON, approved actions, replay bundles and fixtures must round-trip unchanged if Phase 9 fields are absent.
3. Existing standalone MCP/native/HTTP/process/LangChain/provider integrations keep Phase 6 behavior unless explicitly enrolled in a protected multi-agent session. Phase 8 trust pins and Phase 7 isolation remain operational restrictions, never authority grants.
4. The output must include an executable **three-principal/two-hop** scenario and meaningful negative/security tests, not only a schema, CLI inspector or diagram.

## 2. Threat model and trust ownership

Adversaries include compromised child/parent agent, prompt-injected message, fake parent identity, forged or replayed delegation/message, sibling collusion, cycle, stale parent authority after approval, diluted data labels, shared budget overspend, malicious tool metadata, tampered evidence/replay bundle, and agent-initiated attempt to register a new peer or replace protected graph state. Also test benign bugs: mismatched task IDs, duplicate IDs, partial failures, concurrent reservations and expiry.

**Protected operator/session owner controls:** graph topology; node-to-principal and node-to-compiled-plan bindings; verified credential/provider configuration; exact parent→child delegation grants; root grant; maximum depth/nodes/edges; permitted direct-peer routes; optional graph generation changes/revocations; message-route implementation; trusted clocks, evidence sink, brokers, budget coordinator, runtime/adapters and Phase 8 trust inputs. These facts must not come from model text, forwarded messages, MCP discovery, tool arguments, mutable public env vars or unsigned metadata.

**Untrusted:** prompts, model decisions, tool descriptions/results, message content, participant-supplied identity/delegation IDs, requested destinations and claimed labels, caller-provided budget receipts. A JWT authenticates mapped principal facts only; it does **not** make all message content or delegated capabilities trusted. Static identity is a trusted local configuration assertion, not remote identity proof.

**Formal ceiling:** for any action `a` by descendant `v`,

```text
ALLOW(v, a) only if
    own_contract(v, a) permits
    AND all ancestor contract/delegable ceilings permit
    AND all edge grants on root→v contain a
    AND all relevant verified credential ceilings contain a
    AND task/resource/expiry/revocation/graph restrictions contain a
    AND data-flow, approval, budget, trust and isolation restrictions pass.
```

If any ancestor requires approval and none denies/errors, the **single authorized protected broker** for this session must receive a combined exact-action approval including all requiring ancestors; an approval is not itself a policy grant. Alternative separate multi-party approvers are deferred. No implicit inheritance from an agent's owner, a model-visible message or a parent contract name.

## 3. Explicit non-goals

- No hosted team control plane, organization/RBAC/SSO, central registry, UI/dashboard, telemetry backend or billed cloud service (Phase 10+).
- No cross-process distributed transaction, multi-host coordination, remote A2A identity handshake, agent discovery, key distribution, signed message transport, OAuth/OIDC issuer, token minting, introspection or live revocation service. Remote identities require a future independently reviewed boundary.
- No arbitrary graph scheduler, workflow executor, swarm framework or model-driven agent spawning. Local, operator-configured parent/child sessions only.
- No general policy language, semantic classification, declassification, model-internal provenance, content inspection by an LLM, new sandbox implementation, code attestation or bypass of Phase 8 restrictions.
- Do not declare all possible topology forms supported. Start with a **rooted, single-parent, acyclic bounded tree** (a strict subset of a DAG); reject multi-parent merge, ambiguous path and disconnected graphs.
- Do not implement `max_model_calls` or `max_cost_usd` without actual model/cost instrumentation and a separate reviewed design. Keep them unsupported.

## 4. Normative topology and delegation semantics

### 4.1 Versioned graph/session objects

Introduce minimal typed, strict, versioned objects, potentially `src/agentsec/domain/graph.py` and `src/agentsec/multi_agent/{graph.py,authority.py,budgets.py,messaging.py,session.py}`:

- `AgentNode`: unique node/session ID, `PrincipalRef` (AGENT), agent binding, exact `PlanIdentity`, credential reference/summary (not token), optional readable label; no mutable policy copy.
- `DelegationEdge`: child node, parent principal/node (root USER/SERVICE may be an external anchor), a canonical `Delegation` with unique ID, finite expiry and `parent_delegation_id` equal to the preceding edge's ID when path length >1; exact parent/child principals and task ID.
- `GraphSnapshot`: explicit trusted root principal, sorted nodes/edges, schema/domain version, immutable content digest, monotonically increasing generation/epoch, bounded path depth and cardinality; frozen scalar/tuple/canonical JSON values, never aliased mutable resource maps.
- `GraphAuthorityContext`: safe per-child binding of all path grants and credential ceilings, authenticated node/plan identity, graph digest/epoch and earliest expiry. Distinguish the **node's direct grant** from the **complete chain**. Wire it as additive optional data; historical `AuthorityContext.delegation_json` still means one direct Phase 6 grant.
- `GraphMessageEnvelope`: protected sender/recipient session IDs, message ID, causality/parent ID, graph/authority generation commitment, content digest and bounded size, source references/labels, delivery state and timestamps. Its content is passed only on the in-memory delivery path, never copied into evidence/schema dumps.

Fix exact caps at implementation time and test upper bounds; recommended defaults: at most 32 agent nodes, 31 edges, depth 8, 8 KiB canonical grant per hop, 128 KiB protected graph artifact, 64 KiB message content, and bounded artifact-reference fanout. Hard rejects, not truncation or best-effort. These are proposed engineering guardrails, not claims about existing config support.

### 4.2 Graph validation must fail closed

Reject duplicate node/principal/delegation IDs, ambiguous aliases, missing/incorrect parent IDs, cycles, self delegation, disconnected/orphaned nodes, >1 parent, unsupported principal types at intermediate nodes, unknown schema fields/versions, malformed/overlong payloads, missing/invalid timestamps, non-finite expiry, grant issued before its own parent is valid, child beyond parent's grant validity, unrelated task IDs and unbounded fanout/depth. Ensure identifiers and serialized objects are deterministic under insertion permutations. A parent node's exact identity and plan digest must be independently registered and verified: a named parent does not prove that parent's authority exists.

Graph admission is **operator-owned**. Never accept graph/policy changes as data in `agent.message.send`, `tool.arguments`, scenario target output or an MCP listing. Reconfiguration/revocation replaces a validated complete protected snapshot and increments generation; even A→B→A replacements invalidate outstanding approvals. Reject cross-thread mutation if relying on same-event-loop ownership, otherwise prove atomic lock behavior. If graph proof is unavailable, ENFORCE refuses to start or dispatch; SHADOW reports but makes no protection claim; DISABLED is explicitly unprotected and must not be mislabeled.

### 4.3 Transitive authority computation

For path `root → A → B → C`, `C`'s effective authority is the intersection of:

1. C's own validated contract, task/resource policy and current authenticated credential ceiling;
2. all edge grant `capability_scope`, `task_scope.requested_capabilities` and exact per-capability `resource_scopes`; and all authenticated participant credential ceilings;
3. each ancestor agent's compiled policy **delegable ceiling**, including explicit deny, default deny, resource exact-match and data rules, and any approval requirement (no skipping a parent's approval by granting the child ALLOW);
4. all grant/credential validity windows and revocation epochs, plus per-ancestor budget ceilings.

Use current exact capability/resource matching and `intersect_scopes` semantics; do not invent URL/path normalization. Distinguish missing restriction (`None`), explicit empty capability set (deny all), empty resource set for a capability (deny all) and absent resource key (unrestricted for that capability). Reject cross-task chain rather than implicitly changing task IDs. All path grants must be bound to the actual evaluated chain, never selected by only a caller-submitted `delegation_id`.

Factor reusable, **pure, protocol-independent** compiled-policy ceiling logic out of `policy/native.py` where needed; do not independently reimplement different precedence for ancestors. Compose outcomes `DENY/ERROR > REQUIRE_APPROVAL > ALLOW`, preserving existing deny precedence, default deny and data restrictions. For ancestor REQUIRE_APPROVAL, a single combined broker request must identify all requiring plan/rule commitments, and digest-bind the final descendant action, immutable graph snapshot, path grants, participants and current policy/trust/route/data context. In the absence of a safe aggregation implementation, conservatively DENY—not silently ALLOW—ancestor-required approval. Parent plans are evaluated as ceilings for the descendant action, **not** by forging a normal `PolicyRequest` with the ancestor principal and claiming the child is that agent.

### 4.4 Compilation/versioning

Add a **deliberate Phase 9 opt-in** compiled representation (`phase9-v1` or equivalent explicit mode) for multi-agent execution; standalone `compile_contract(...)` behavior and `phase6-v1` identities must remain unchanged. The opted-in plan should represent supported delegated-agent limits and graph-bound policy semantics without embedding a mutable graph or bearer credential. Ensure `max_delegated_agents` is marked supported **only** when a real graph counter and coverage are wired; do not flip historical semantic atoms globally. Store graph/authority runtime identity in a separate digest, not the authored `effective_policy_hash` or the old `compiled_plan_digest`. Add versioned discriminators and migration/legacy negative tests. Generated schemas come from models only.

## 5. Agent-to-agent identity and registration

Provide a protected local `MultiAgentSession`/coordinator that registers each participating agent with its **own** contract/compiled plan and Phase 6 provider result. The authenticated principal must equal the node's protected `PrincipalRef` and the contract principal; `acts_on_behalf_of` names the immediate parent exactly. Static mode remains explicitly labeled trusted config; JWT mode verifies pinned keys/subject mapping and finite validity via current Phase 6 machinery. Unknown/mismatched identities, expired parent or child, duplicate principals and cross-session credentials fail registration.

Enrollment is an authorization-sensitive operation, never ordinary child messaging. Define parent/child binding and a fixed operator-provided per-peer route before any content passes. Guard parent and child identity freshness at message ingress and dispatch. Only live authenticated sessions with the same protected graph generation can communicate; a `sender_id` string in a message is not authentication. Do not expose bearer/JWT strings, private keys or arbitrary external claims in any `GraphSnapshot`, event, approval, replay bundle, error or test golden.

The root principal may be a protected external USER/SERVICE anchor, but must have an explicit trusted finite root grant into the first agent; do not fabricate an authenticated user token. State precisely which root assertions are locally trusted and which are cryptographically verified. A grant from A→B is valid only if A's session was admitted with effective authority; a stale or revoked A cannot launder old grants to B.

## 6. Message provenance, flow policy and delivery

Implement a small protected **in-process** parent/child message route with a real local demonstration. Permit only configured adjacent peers, with an optional explicit response direction; sibling and cross-root messaging must be rejected unless a different reviewed route is added later. A message may carry untrusted content, but may not carry executable graph/identity/authority assertions.

**Outbound authorization:** represent `agent.message.send` (or one documented fixed capability name) as an actual protected action via the **sender's existing `RuntimeGateway.call`** and a reviewed `ToolDescriptor`/fixed peer binding. Sender contract must explicitly allow it; parent policies and task scopes apply; `data_destination` is bound to the actual receiving peer by protected config, not user args; Phase 4 data rules inspect sender's current exposure frontier. Existing broker, budgets, trust, response and evidence order stay in force. An alternate equivalent shared gateway path requires a detailed proof that it does not bypass any of those checks.

**Transfer and import:** derive content hash/size locally, bind source event/run/trace and current `DataArtifactRef`s, add `UNTRUSTED_CONTENT`/`USER_PROVIDED` where appropriate and **monotonically union labels**. Before delivery to the receiving model, the recipient checks protected sender identity, allowed peer edge, graph/authority generation, freshness, canonical envelope, replay/duplicate message ID, graph depth/resource limits, and commits a safe recipient provenance import so subsequent recipient tools see inherited labels. Parent graph lineage is *referenced* (no pretending a foreign node is locally verified data). Evidence records send/receive correlation and safe content digest/labels, never message body.

**Delivery boundaries:** authorize before bytes leave the sender session. If receiver evidence/import fails in ENFORCE, do not release bytes to the receiver; if sender-side dispatcher entry occurred, do not claim the send had no effect. Cancellation, partial delivery and return-path failures must carry explicit `UNKNOWN`/`UNCONFIRMED` status, preserving source/recipient causal IDs. SHADOW may transmit with honest would-block signals, but cannot turn inferred labels/identity into verified facts. DISABLED remains visibly non-protective.

**Privacy:** do not log message text, authorization tokens, resource values or raw argument keys. Bound payload sizes, count, fanout and reference depth; redact content-derived identifiers where necessary while preserving independent hashes for replay.

## 7. Recursive budgets and delegated-agent limits

Implement one **session-owned hierarchical ledger** or similarly atomic coordinator, not independent child budgets. Every tool/message call by node N consumes its local counter and each ancestor's subtree counter, including the root/session ceiling if configured; every reservation is atomic over the whole path, before approval. Track existing supported classes: tool calls, external writes, destructive calls and monotonic wall-clock runtime. Reserve with a token bound to exact node/path, action and graph generation; commit **once** at the final no-await dispatch boundary; release on deny, approval failure, expiry, trust drift, cancellation before dispatcher entry, or evidence failure; do not refund after possibly-effectful entry. Failed dispatch is still charged unless existing runtime semantics explicitly distinguish pre-entry failure.

Concurrent children must not overspend the common parent budget, even with pending approvals. Use one lock/transaction or prove deterministic lock ordering; test simultaneous reservations, cancellation/timeout, budget exhaustion, session close, generation change, rollover and exception paths. Avoid decrement-by-tool without a unique reservation identity; amend the existing `BudgetLedger`/gateway token/refund interface carefully if needed, preserving standalone behavior and compensating a failed *pre-entry* critical evidence write exactly once.

`max_delegated_agents` means **distinct descendant agent identities ever admitted under an ancestor in that local session**, not number currently running (prevents churn bypass). Count across every ancestor subtree on enrollment, atomically and before the new agent can act; do not allow shrinking/reusing a name to evade the limit. A validated protected reload may narrow limits but must invalidate affected paths. No fake global/cross-host budget guarantees. Model-call count, dollars and arbitrary token quotas remain unsupported and fail contract coverage when requested.

## 8. Runtime ordering and revocation guarantees

Maintain the current `RuntimeGateway` order and add graph gates at **preapproval** and **final dispatch**. Recommended order:

1. Bind authenticated node, verified graph/path and immutable generation; reject unknown peer/principal/plan, revoked/expired path, unsupported phase or missing coverage.
2. Snapshot provenance/data destination/trust/route; construct one complete normalized action and graph-bound policy input; emit minimized request evidence.
3. Compute descendant contract + ancestor ceilings; record decisions and any multi-agent denial signals. No broker call on denied/invalid graph.
4. Atomically reserve all ancestor budgets, then use the existing protected broker for any aggregate approval. Bind full path, generation, source/recipient and scopes into exact action digest.
5. After awaits: recheck credential/grant expiration and graph generation/revocation, trust snapshot, route/resource binding and ledger validity **synchronously with no intervening await** before commit, critical dispatch evidence and dispatcher entry.
6. On pre-entry failure release all pending reservations and invalidate one-shot approvals. On post-entry cancellation/failure retain potentially-effectful accounting and emit uncertainty.

Do not make dynamic graph membership silently compatible with historical one-hop approval digests. Avoid TOCTOU between epoch revalidation and dispatch; if the coordinator cannot enforce a stable protected snapshot across threads/event loops, explicitly reject unsupported concurrency. `finish()` of an ancestor invalidates descendant authority for new calls; explain treatment of already-dispatched actions.

## 9. Evidence, replay, evaluation and incident lifecycle

### 9.1 Event model

Use minimal additive versioned graph/message payloads and explicit category/reason codes (or a versioned graph-specific event kind) to distinguish graph admission, edge activation/revocation, message send/deliver/reject, ancestor ceiling decision, budget reservation/commit and uncertain delivery. Preserve canonical `SecurityEvent` ordering and payload/event-type validation; event IDs remain unique, causal references bounded, source run/trace vs recipient run/trace distinguishable. Graph path/digest/generation and ancestor decisions should be inspectable without disclosing raw grants/resource scopes or message content. Treat graph redactions as **material replay blockers** if the complete protected facts are unavailable.

### 9.2 Offline replay and regression

Replay reconstructs a source graph from canonical **recorded** commitments and optional independently supplied protected graph/authority material; verifies content digest/generation/path and event ordering; reuses pure policy/ledger semantics at recorded times. It must never issue a JWT, call a model/tool, deliver a real message, fetch remote peer data, mutate live protected policy, refresh a key or run Docker. Candidate graph/contract/route comparison is a separate result from source trace semantic fidelity, mirroring Phase 7/8 distinctions. Missing/redacted material, fake identity assertions, missing ancestor plans, unknown destination labels or stale source commitments yield `INCOMPLETE`/blockers, not synthetic assurance or `UNCHANGED`.

Add promotion into safe deterministic regressions for: ancestor deny/approval bypass, forged peer, over-budget sibling fanout, expired parent, path replacement during approval and cross-agent exfiltration. Preserve original incident commitments and explicit assertions; never edit security contracts during promotion.

### 9.3 Evaluation/conformance

Add deterministic local fixtures for 2- and 3-hop graph tests; integrate with existing Phase 1 scenario/assertion/trajectory machinery **without enabling a free-form model harness**. When compiled Phase 9 semantics are active, generate negative probes for transitive scope, delegated-agent cap, budget sharing, parent approval, data-label transfer and identity mismatch. Avoid claiming synthetic tests prove the semantics of an arbitrary model message, full data-flow coverage or remote authentication. Maintain complete coverage reporting for unsupported graph combinations.

## 10. Public surface, examples and documentation

**Usable vertical slice:** a small local example with USER → coordinator A → worker B → worker C (at least two delegations beyond the root where feasible), distinct authenticated agent sessions/contracts and an explicit protected graph; demonstrate allowed read, denied write due to ancestor limit, protected message relay/response with labels, parent shared budget exhaustion, changed graph while approval waits and a forged sibling failure. The program must actually call the shared gateway; assertions cannot be mocked policy booleans.

Expose a strict bounded offline graph validator/inspector through CLI (e.g. `agentsec graph validate --config ...`), showing minimized IDs/digests/reasons and no secrets. Do not silently load unknown remote agents or auto-approve grants. Optional developer output to compare two reviewed graph snapshots is acceptable only if deterministic and safe. Do not add an orchestration daemon.

Update focused docs for multi-agent trust/modes, identity delegation, provenance, evidence, replay, threats, architecture appended Phase 9 semantics, README/docs map, examples, schemas and reports. Clarify that Phase 8 `TrustLock` pins **tool implementations** and does not authenticate remote agents or approve delegation. Correct stale claims such as “parent chains remain unsupported” only where Phase 9-enabled behavior truly exists; preserve historical descriptions as historical.

## 11. Sequenced workstreams with stop conditions

| Workstream | Implementation | Done when |
| --- | --- | --- |
| W0 — Reconcile | Read latest repo/AGENTS/docs/reports; baseline commands; identify exact call and replay extension seams; record release gates | Current HEAD, dirty files, baseline/tests and architectural deltas recorded |
| W1 — Domain/graph | Typed versioned graph/edge/path/envelope, strict parse/limits/canonicalization, nonaliasing snapshots and generated schema hooks | Adversarial graph invalid/ordering tests pass |
| W2 — Authority | Phase 9 opt-in compilation; parent chain validation; identity/provider binding; common pure ancestor policy intersection including data and approval semantics | Parent cannot confer what root, any ancestor contract or grant forbids |
| W3 — Hierarchical budget | Atomic ancestor ledgers, unique reservation/compensation tokens, delegated-agent cap and final validity | Concurrent siblings and cancellation cannot overspend or hide effect |
| W4 — Gateway integration | Protected session enrollment, pre/final graph gate, exact action/approval digests, modes, epoch/revocation, trust/isolation composition | No alternate adapter/direct gateway path bypasses checks |
| W5 — Messaging | In-process adjacent peer adapter through sender gateway; recipient verified import; safe envelopes/causality/labels | Fake peer, relabel, forbidden destination and evidence failure deny delivery |
| W6 — Evidence/assurance | Additive events, redaction, offline replay/fidelity blockers, regression and synthetic conformance | No live side effects/re-auth in replay; historical hashes stable |
| W7 — UX and finish | CLI validate, three-principal example, tests/fixtures, docs, schema regeneration, full test/lint/type/build, implementation report | Reproducible demo and honest limitations; review-ready |

At each workstream, run focused tests and conduct an independent threat-oriented check. If a required safety property cannot be implemented within scope, **reject that path with an explicit unsupported error and record the limitation**; do not simulate proof with a Boolean, loosen validation, or silently defer a mandatory requirement. Preserve unrelated changes.

## 12. Adversarial test matrix (minimum)

| Area | Required success test | Required failure/race test |
| --- | --- | --- |
| Topology | USER→A→B→C with exact plan/principal path | Cycle, multi-parent, duplicate, orphan, bogus parent delegation ID, self-edge, depth/node/size overflow |
| Identity | Pinned JWT or explicit static config per node | Spoofed sender, missing proof, wrong parent, changed subject/key, stale parent, cross-session reuse |
| Grants | Child exact narrower task/resource, empty ceiling semantics | Child broader than root/parent, conflicting tasks, sibling grant substitution, missing grandparent |
| Policy | Parent+child ALLOW, inherited approval goes through shared broker | Parent default/explicit DENY, ancestor data DENY, ancestor approval laundered into child ALLOW |
| Approval/revocation | Exact graph/action-bound approval with stable generation | Graph A→B→A generation change while awaiting broker; expiry or revocation just before dispatch; no budget/effect |
| Budgets | Shared parent limit consumed by parent plus descendants | Concurrent siblings pending/reserved, retries, timeout, cancellation, evidence sink failure, cap churn |
| Messaging | Adjacent allowed send/receive, labels inherited | Unauthorized sibling, reparented recipient, duplicate/replayed message, forged labels, secret-to-denied-peer |
| Modes | ENFORCE blocks; SHADOW would-block evidence; DISABLED honest | SHADOW/DISABLED incorrectly claiming authenticated/authorized outcomes or weakening transport safeguards |
| Adapters/trust | Native and at least one real MCP/Phase 7 integration through same guard | Direct `RuntimeGateway.call` or rebound provider/HTTP/process route bypasses graph or Phase 8 pin |
| Evidence/replay | Safe causal reconstruction, recorded-time policy replay, historical fixture round-trip | Missing/tampered graph material, redacted scope, duplicate event, forged source replayed as verified; zero live effects |
| Serialization | Deterministic canonical sorted objects and generated schemas | Unknown field/version, coercion, oversized payload, unstable digest; all historical golden digests unchanged |

Include at least one test with a real awaiting broker and concurrent change; one with actual evidence failure before effect; one with a receiver that refuses import; and one with no-await final race proof. Distinguish a checked mock tool effect counter from claims about real arbitrary tools.

## 13. Acceptance criteria and verification

All are required for the shipped local slice:

1. A real protected 3+ agent topology with multi-hop grants and distinct identity bindings can execute allowed calls and safe adjacent messages through existing gateway semantics.
2. No child can exceed **any** ancestor edge grant, credential/task/resource ceiling, compiled policy/data restriction, approval requirement or supported budget. Missing proof fails closed.
3. Graph, identity, message and budget state is operator-owned and immutable/detached; exact action binding, epoch/freshness and pre-effect validation resist mutation during approval.
4. Recursive budget reservations are atomic and token-compensated; `max_delegated_agents` is truthfully executable in Phase 9 mode only; other unsupported budget fields stay unsupported.
5. Labels and message provenance propagate monotonically and are enforced before receiving-agent exposure; data egress through messaging is itself authorized.
6. ENFORCE/SHADOW/DISABLED claims remain truthful; Phase 7 effect/isolation and Phase 8 trust restrictions are neither bypassed nor redefined.
7. Offline replay cannot authenticate/deploy/send/execute; unknown/redacted identity/lineage facts downgrade fidelity, never manufacture a pass.
8. Legacy Phase 6 standalone behavior, old plans/digests/action/event serialization, golden fixtures and existing regressions remain compatible.
9. High-quality negative/race/integration tests cover the matrix; generated schemas pass current check; focused docs and a substantive implementation report explain reality, deviations and release gates.

**Run commands (adapt interpreter location):**

```bash
python -m pytest -q tests/unit/test_multi_agent.py
python -m pytest -q tests/integration/test_multi_agent.py
python -m pytest -q
ruff check .
ruff format --check .
mypy src
agentsec schema export --out schemas/generated
agentsec examples validate
agentsec eval examples
agentsec regression run --root examples/regressions
python -m build --no-isolation
git diff --check
```

Names of new test files and CLI entries are suggested, not a license to claim they exist. Baseline full-suite failures due to environment permissions (e.g., local test-server socket binding) must be reported and distinguished from product failures. Never weaken existing checks to get green tests. Regenerate schemas from Python models, never manually modify generated JSON.

## 14. Implementation report and handoff

Create `docs/reports/phase-9-implementation-report.md` with: initial/final commit/status and inherited release gates; read sources and conflicts; exact module/API/plan mapping; threat model and operator vs agent inputs; chain proof and approval composition; recursive budget concurrency model; message causal/data-flow boundary; modes and trust/isolation integration; test matrix and exact commands/results (including failures/retries/permission limits); historical compatibility digests; replay fidelity/unsupported claims; scoped deviations and alternatives; known risks; next-phase readiness. Explain what is **not** proved (remote peers, cross-host quota, semantic content exfiltration, loaded-code attestation, full model-internal taint).

Do a final self-review for spoofing, direct gateway bypass, parent/child role confusion, graph mutation, mutable aliasing, unintended authority widening, approval laundering, data-flow laundering, sibling budget overspend, inaccurate event/effect claims, stale docs and unsafe error disclosures. An independent reviewer must be able to inspect the implementation *without accepting this plan as ground truth*.

**Exit principle:** Phase 9 is complete only when a child cannot become more privileged, leak more classified data or consume more protected budget merely by crossing an agent boundary—and the evidence states precisely what was checked, what was unknown and what may already have taken effect.
