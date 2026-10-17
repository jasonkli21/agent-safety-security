# Evidence model v0.1

The [event schema](../schemas/generated/security-event.schema.json) records typed facts shared
by future evaluation and runtime. Every event has required string schema version `0.1`, stable
`event_id`, `event_type`, aware `occurred_at`, `run_id`, `trace_id`, nonnegative integer `sequence`,
and typed `payload`. Optional actor is a principal reference, subject is an ID, and labels are a
set of data classifications. Payload `kind` discriminates a closed union and must equal the
envelope type. Both Python validation and exported JSON Schema reject mismatches.

| Event / payload | Evidence represented; limits |
| --- | --- |
| RUN_STARTED | Contract ID, effective policy hash, optional scenario and compiled plan identity; does not authenticate a run. |
| TOOL_REQUESTED | Privacy-minimized PolicyRequest, exact-action digest, full policy-input digest, and explicit redacted-field metadata with per-field digests; intent, not permission. |
| POLICY_EVALUATED | PolicyDecision including outcome, reason codes and policy identity; not dispatch. |
| APPROVAL_REQUESTED | ApprovalRequest with request ID, action digest and expiry; no approval granted. |
| APPROVAL_DECIDED | ApprovalDecision with approver, outcome and one-shot scope; does not prove authentication or execution. |
| TOOL_DISPATCHED | Unique dispatch attempt ID, request/tool/action digest, decision ID and optional approval ID; records dispatch, not successful return. |
| TOOL_RETURNED | Dispatch attempt ID, request/tool IDs, success boolean, optional response hash and artifact references; a success response alone does not prove an external effect. |
| DATA_EXPOSED | Dispatch/request/tool IDs plus a content-free artifact committed to guarded context release; distinct from returned data and not proof of model ingestion or transport delivery. |
| EFFECT_VERIFIED | Dispatch attempt ID, request, verifier principal, verified boolean and nonempty observation artifact IDs; records a verifier's claim, not independent proof of its honesty. |
| SECURITY_SIGNAL | Category, ordered severity, artifact references, optional redacted summary; indicator needing interpretation. |
| RUN_TERMINATED | Stable reason code; termination can be abnormal or budget-related. |
| RUN_FINISHED | Output artifact IDs; completion alone says nothing about security or utility. |

Each dispatch, return, and verified effect carries a `dispatch_id` that identifies one concrete
execution attempt. Retries may share a `request_id` while using distinct dispatch IDs. These events
support `requested → denied` and `requested → approval → dispatched → returned` without confusing
the stages. See the tested [approval run](../tests/fixtures/events/approval-run.json)
and [denied run](../tests/fixtures/events/denied-run.json). An effect observation can follow a
return. An external side effect may occur without a response, so the model does not assert the
converse. The synchronous `EventSink.append(SecurityEvent)` protocol now has copy-safe in-memory
and canonical JSONL implementations in Phase 1. There is no signature chain; Phase 5 adds integrity-checked offline replay (see below).

## Ordering and integrity

`validate_event_sequence(events)` rejects duplicate event IDs, duplicate/decreasing sequence
numbers within a run, and trace changes within a run. Interleaved runs and sequence gaps are
valid; an empty stream is valid. Sequence is the ordering authority; wall-clock monotonicity,
global distributed ordering, contiguous sequences, lifecycle completeness, causal references,
and decision/approval/dispatch consistency are not established by this validator. Phase 1 adds separate evaluation trajectory validation (see [evaluation](evaluation.md));
Phase 2 must enforce binding at a real dispatch boundary.
A structurally valid fabricated stream is still fabricated.

## Content minimization

No event requires raw prompts, responses, credentials, or full action arguments. Prefer artifact
IDs, SHA-256 content digests, metadata, and redacted summaries. `DataArtifactRef` carries origin,
trust class, labels, optional content hash/time, and parent artifact IDs. References do not
require embedding graph nodes or sensitive content. Hashes can leak equality and do not encrypt
content. Summary redaction and trustworthy classifications are producer responsibilities;
Phase 0 does not scan or redact automatically. Only scenario fixtures intentionally include
synthetic canary content. Evidence storage is security-sensitive and should be outside agent
write authority.

A signal is an observed indicator; a finding is an interpreted security result referencing exact
event/artifact IDs, severity, expected/observed behavior and optional remediation. An incident
is an investigation derived from findings/events. Phase 0 implements findings, not incidents or
replay manifests, following the narrower phase plan. Evidence references remain externally
resolvable; validation does not fetch or verify their content.

## Phase 1 completeness and content

The evaluation observation explicitly declares event, argument, final-output, external-sink,
and finding completeness. Canonical events are the lifecycle truth source. Ephemeral text
capture supplies content that minimized events intentionally omit. JSONL alone supplies no
proof of output coverage. An evidence write failure makes the result ERROR.
The fixture target omits raw arguments/responses/output/signal summaries from evidence and
redacts canaries in resource summaries while retaining exact-action digests. Evaluation adds
causal reference, one-shot approval, expiry, terminal, and identity checks without changing
`validate_event_sequence` or existing event schemas.

## Phase 2 runtime representation

`TOOL_DISPATCHED.enforcement_mode` defaults to `ENFORCE` for older streams. SHADOW may
reference a DENY, ERROR or REQUIRE_APPROVAL decision while forwarding; the original decision
is retained. DISABLED requires null `decision_id`/`approval_id` and makes no policy claim.
ENFORCE and SHADOW require a decision ID. Schema version remains `0.1` for this additive,
pre-1.0 extension; older strict consumers need the regenerated event schema to read new fields.
Phase 1 trajectory evaluation rejects non-ENFORCE dispatches, preserving its authorization checks.
Runtime request evidence omits resources/task scope and argument summaries; the ephemeral full
request still drives policy and the complete NormalizedAction drives exact approvals. When
resource or task scope is omitted, `redacted_fields` distinguishes that from factual absence,
field digests preserve equality linkage, and `policy_input_digest` commits to the complete
request used for the decision. The decision references the same request ID, so trajectory
validation preserves the request-to-decision link without treating redacted `None` as the policy
input. In SHADOW, a call with an uncovered required resource input records a policy ERROR rather
than treating `resource=None` as an observed absence.
See [MCP runtime](runtime-mcp.md) for counter, response, failure and privacy semantics.


## Phase 4 returned and exposed artifacts

TOOL_RETURNED.artifacts contains content-free returned response refs with parent IDs, exact
labels, trusted tool-output origin, timestamp and response hash. DATA_EXPOSED references the
same artifact only after the response guard permits release. ENFORCE records this critical event
under the provenance frontier lock before committing exposure/returning; a write failure prevents
release and poisons subsequent calls. Withheld responses remain returned but unexposed.
Tool error bodies that are released are also exposed; transport exceptions create no artifact.
Because a transport exception confirms no upstream response, it emits no `TOOL_RETURNED` event;
the dispatch event remains the last confirmed lifecycle fact.
SHADOW forwards and tracks actual output while preserving deny/error evidence and signals.
DISABLED exposure makes no enforcement claim. Phase 1 trajectory validation reconstructs the
exposed frontier, requires request provenance to match the snapshot at request time, and validates
returned artifact parents and inherited labels. Exposure must match a prior returned artifact/
dispatch; duplicate exposure for a dispatch is rejected.
Request evidence retains content-free provenance refs and sink category; the full input/action
digests include them. Schema remains 0.1; strict older consumers need regenerated schemas.

## Phase 5 offline lifecycle

See [replay and incidents](replay-incidents.md) for strict evidence bundles, exact versus legacy
source plan binding, offline substituted security replay, semantic trace diff, evidence-backed
classification, safe assertion promotion and the local/CI regression gate. Historical evidence
remains immutable; missing or redacted material is never reconstructed. This does not extend
model/context coverage or authorize any live execution.


## Phase 6 authority evidence

RUN_STARTED optionally carries a typed AuthoritySummary with actor/assurance, OBO principal,
delegation ID/digest, computed authority digest, earliest expiry, setup error and enforcement
status. No raw JWT or arbitrary external claims are recorded. Requests bind canonical authority
into the full policy-input digest. Resource-bearing grant context is explicitly redacted with
an authority digest; otherwise minimized canonical facts support offline replay. Static trust
is never labeled cryptographic authentication. DISABLED records enforcement_enabled=false;
failed verification records no authenticated actor. Absent additive fields serialize as absent,
preserving historical event identities. See [identity and delegation](identity-delegation.md).

## Phase 7 adapter integration

See [adapters/isolation](adapters-isolation.md). New protected calls bind execution-route identity
to exact actions and record safe route facts on dispatch. Absent fields preserve old serialization;
offline replay substitutes these facts without live execution. Generic schema, argument and
resource/data coverage checks are shared with MCP. Compiler and authored hashes are unchanged.
