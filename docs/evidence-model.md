# Evidence model v0.1

The [event schema](../schemas/generated/security-event.schema.json) records typed facts shared
by future evaluation and runtime. Every event has required string schema version `0.1`, stable
`event_id`, `event_type`, aware `occurred_at`, `run_id`, `trace_id`, nonnegative integer `sequence`,
and typed `payload`. Optional actor is a principal reference, subject is an ID, and labels are a
set of data classifications. Payload `kind` discriminates a closed union and must equal the
envelope type. Both Python validation and exported JSON Schema reject mismatches.

| Event / payload | Evidence represented; limits |
| --- | --- |
| RUN_STARTED | Contract ID, effective policy hash, optional scenario; does not authenticate a run. |
| TOOL_REQUESTED | Structured PolicyRequest and exact-action digest; intent, not permission. Argument summary can be redacted/absent. |
| POLICY_EVALUATED | PolicyDecision including outcome, reason codes and policy identity; not dispatch. |
| APPROVAL_REQUESTED | ApprovalRequest with request ID, action digest and expiry; no approval granted. |
| APPROVAL_DECIDED | ApprovalDecision with approver, outcome and one-shot scope; does not prove authentication or execution. |
| TOOL_DISPATCHED | Unique dispatch attempt ID, request/tool/action digest, decision ID and optional approval ID; records dispatch, not successful return. |
| TOOL_RETURNED | Dispatch attempt ID, request/tool IDs, success boolean, optional response hash and artifact references; a success response alone does not prove an external effect. |
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
and canonical JSONL implementations in Phase 1. There is no signature chain or replay system.

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
