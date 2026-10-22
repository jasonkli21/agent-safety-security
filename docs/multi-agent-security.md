# Local multi-agent security

Phase 9 adds an explicitly enrolled, single-process tree of distinct agent principals and
contracts. It does not run models or schedule agents. Operator application code constructs
`MultiAgentSession`, supplies one protected contract and trusted Phase 6 `IdentityProvider` per
node, then activates ancestors before descendants. Give agents only their own protected tool
and fixed message handles. Python object privacy is a wiring convention, not isolation from
hostile Python code in the same interpreter.

```bash
.venv/bin/python examples/multi_agent/local_session.py
.venv/bin/agentsec graph validate --config examples/multi_agent/graph.json
.venv/bin/pytest -q tests/unit/test_multi_agent.py tests/integration/test_multi_agent_integration.py
```

The example executes USER → A → B → C with a finite explicit root grant. A permitted read enters
the existing gateway; C's write is denied by A even though C allows it. It exercises a labeled
adjacent relay, shared ancestor budget exhaustion, rejected sibling route, and graph replacement
during a real awaited approval. Tools are synthetic and do not read files or contact services.
The fixed example clock is a reproducible fixture, not a credential for a live deployment.

## Protected state and identity

`GraphSnapshot` is strict versioned `agentsec.graph.v1` configuration. Node and edge ordering is
canonical. Caps: 32 nodes/edges, one finite root edge, depth 8, fanout 8, canonical grant 8 KiB,
complete graph 128 KiB. Every node has exactly one parent grant; duplicate principals, IDs,
cycles, orphans, wrong parent grant IDs, invalid principal bindings, cross-task chains and child
validity outside parent validity are rejected. Grants are canonical JSON strings; a property
returns a detached parsed grant, so nested resource maps cannot alias protected state.

Each node binds an exact `phase9-v1` plan and independently verified minimized credential.
The external USER/SERVICE root and root grant are explicit operator assertions. Static providers
mean local trusted configuration. The existing pinned JWT provider verifies signatures and
mapped workload identity; it does not establish remote peer transport authentication. Raw JWTs,
keys and arbitrary claims are not retained in graph state or evidence. Message sender/recipient
strings, model text and discovery never enroll peers or grant authority.

`compile_contract(contract)` remains `phase6-v1`, with unchanged historical serialization and
one-hop semantics. `compile_contract(contract, multi_agent=True)` opts into `phase9-v1` and
executable `max_delegated_agents`. A standalone native policy call rejects Phase 9 plans: a graph
commitment alone is not proof of a live admitted session. Model-call and cost budgets stay
unsupported, including configured zero values.

## Authority and finality

Every gateway call on an enrolled gateway binds the node, full path, graph digest/generation and
complete path authority digest into both policy input and exact normalized approval action.
All grants, task/resource restrictions and participant credential ceilings restrict each action.
Missing restriction differs from an explicit empty capability/resource set. Resources match
exactly; no path/URL normalization is inferred. All ancestor compiled tool/task/data ceilings use
the same pure evaluator as standalone policy. DENY/ERROR beats approval, which beats allow.
Decisions retain per-ancestor plan identities, outcomes, reasons and matching rules.

An ancestor approval becomes one real combined session-broker approval of the complete action.
The strictest ancestor timeout applies. No contract or graph is edited by approval. The gateway
checks path freshness before authorization and after awaits, and again after critical dispatch
evidence, immediately before dispatcher entry. Phase 8's trust final check remains active;
Phase 7 transport validation and configured isolation still apply, with no host fallback.

Only the constructing thread and first running event loop can use/mutate a session. No await
separates final checks, atomic commit, critical evidence and dispatcher entry. Synchronous
reentrant evidence callbacks that revoke a path are caught by the final graph check. Trusted
application code, evidence sinks and downstream implementations remain part of the TCB.

`replace_graph` requires a strictly greater generation even when restoring identical content.
It accepts complete validated snapshots with existing node/principal/plan bindings and root.
New principals/plans require a new session; no live reauthentication or arbitrary reparenting is
implemented. Removed nodes retire, and reconfiguration emits content-free commitments. Failure
to record replacement retires all active nodes. Revocation/finish retires a node permanently;
a live-path check prevents descendants acting even when their own gateway remains open.
Already-entered actions may still finish; revocation does not undo effects. A dispatch event
records entry intent and may precede a final reentrant rejection; it is not effect verification.

## Budgets

One session-owned `HierarchicalBudgets` coordinator atomically reserves the child's complete
ancestry under one critical section. Pending approvals consume shared capacity. Calls, external
writes, destructive actions and monotonic elapsed runtime count against every ancestor. Direct
parent use and descendant use share the same counters. Reservations bind exact path, graph
generation and action digest. Unique tokens transition pending → committed → nonrefundable
entry; pre-entry evidence failure compensates that exact receipt at most once. No decrement-by-
tool refund remains. Denial, cancellation, timeout and stale graph release pending tokens.
Post-entry failures retain accounting and carry uncertainty.

`max_delegated_agents` counts distinct descendant principal IDs ever admitted under each ancestor
in this local session. Failed later startup does not reset admission history. Retired nodes cannot
reactivate, graph replacement cannot replace a principal, and counters persist across graph
replacement. There is no global quota across processes or new sessions.

## Message route and provenance

`MessageRoute(session, sender, recipient)` is protected operator wiring for one adjacent pair,
including an explicitly constructed reverse route. No sibling/nonadjacent route is accepted.
`send(body)` accepts only bounded text, with no sender, labels, artifact refs or destination input.
The fixed `agent.message.send` action runs through the sender's existing gateway, broker, ancestor
budgets, data-destination rules and trust guard. Its reviewed destination is `agent:RECIPIENT`.
`route.tool` returns detached operator metadata for offline trust review. Provider/framework
rebinding does not remove gateway graph or trust checks.

The route snapshots the sender's actual provenance frontier before authorization; a message
inherits its labels and adds USER_PROVIDED/UNTRUSTED_CONTENT. Arbitrary input text is not classified
for secrets. SECRET/PII labels must come from protected sources already tracked by the runtime.
Receiver admission rechecks both live paths, exact graph epoch, adjacency, unique message ID,
source dispatch event/run/trace and source refs before import. Foreign lineage is digest-referenced,
not registered as if it were locally verified. The receiving artifact unions local frontier labels
and sender labels; critical recipient evidence precedes frontier commit and body release, with
no await between them. Subsequent recipient tools see inherited labels. At most 64 source and
receiver frontier refs, 64 KiB per message and 1024 successful messages per session are admitted.

Evidence includes correlated send/import facts, graph commitments, safe artifact metadata,
content hash and byte count. It contains no body, raw resources, arguments, JWT or arbitrary
claims. Message content stays untrusted data/instructions. Receipt says RELEASE_COMMITTED, not
model ingestion or external effect verified. Failure/cancellation after sender dispatcher entry
is potentially effectful; evidence/import failure withholds recipient content. Operator application
code calls `receive(node)` through a fixed node-bound wrapper, never with a model-selected node.

## Modes, assurance and unsupported paths

This Phase 9 slice supports ENFORCE sessions only and requires critical evidence. Passing a graph
guard to SHADOW/DISABLED refuses startup (`GRAPH_MODE_UNSUPPORTED`). Legacy standalone mode
behavior remains unchanged. No forwarded call is mislabeled as authenticated graph enforcement.

`graph_conformance(material, now)` generates finite independent path-policy partitions, missing
identity/graph, stale generation, unknown capability, expired ancestor and bounded ledger probes.
It performs no tool/model/provider operation. Broker/label-transfer/agent-cap lifecycle coverage
remains explicitly NOT_RUN in this pure report; real gateway tests cover those stateful properties.
Single-plan conformance reports graph-session-required rather than substituting Phase 6 authority.
Synthetic tests prove the exercised structured semantics, not linguistic laundering detection.

`replay_graph(GraphReplayInput(...))` consumes protected recorded graph/participant material,
ordered source events, reviewed tool metadata and optional exact redacted requests/actions.
It reuses pure ancestor policy, the hierarchical coordinator, approval ledger and provenance at
recorded times. It never calls a provider, verifies a JWT afresh, delivers content, invokes a tool,
starts isolation or contacts a model/network. Source evidence digest and candidate graph equality
are distinct. Matching evidence hashes do not authenticate the source storage. Content hashes
prove equality commitments, not what was said or whether a model consumed it.

Supported replay is one recorded graph epoch. Missing ancestors, changed path commitments,
forged sender/delivery/labels, missing exact approval actions, unresolved reservation lifecycle,
material redaction, unknown monotonic duration or epoch changes yield INCOMPLETE with blockers.
Compiled task scope can be recovered only from separately supplied matching protected material;
its full request digest must match. Candidate graph comparison is separately UNKNOWN/CHANGED/
UNCHANGED/INCOMPLETE and becomes INCOMPLETE when source fidelity is blocked.

The historical bundle/classification/promotion pipeline recognizes Phase 9 source plans, preserves
commitments and explicit assertions, and blocks single-agent substitution with
GRAPH_SESSION_REPLAY_REQUIRED. Such promotions remain DRAFT, without an exported protected
program. Automatic ACTIVE export of graph/resource/authority material is deliberately unsupported;
review the protected session replay and create explicit reviewed regressions. Graph replay does
not claim arbitrary epoch-history reconstruction or model branching.

Remote authentication/transport, dynamic new membership, multi-parent graphs, hosted services,
model/cost accounting, semantic secret classification, total model-internal taint, running-code
attestation and distributed budget consistency remain outside this implementation. Independent
Phase 7–8 acceptance remains unconfirmed; Phase 9 requires independent review as well.

A separate reviewed graph promotion API, `promote_graph(bundle, incident, source, node_id)`, can
produce an ACTIVE **minimal manifest** when complete separately supplied session replay passes
and expectations are explicit TOOL_NOT_CALLED/MAX_TOOL_CALLS/APPROVAL_REQUIRED assertions.
`run_graph_case(case, source)` requires the exact protected source again; the manifest contains
only safe assertions, node selection and source commitments. It does not embed requests, action
arguments, grants or credentials. Generic historical promotion still returns DRAFT. A blocked
source or unsupported expectation cannot become an active assurance claim. This separation
supports CI without exporting protected source material as part of incident promotion.

```bash
.venv/bin/agentsec graph replay --config examples/multi_agent/replay.json
.venv/bin/agentsec graph regression --case examples/multi_agent/regression.json \
  --source examples/multi_agent/replay.json
```

The checked-in source is deliberately synthetic public configuration and content-free evidence;
real protected replay inputs need independent access controls. Phase 1 trajectory validation and
assertion semantics are reused. A graph candidate equality result does not execute a candidate
policy or claim a successful remediation under changed authority.
