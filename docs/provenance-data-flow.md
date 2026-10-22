# Tracked provenance and data-flow security (Phase 4 semantics; current compiler phase6-v1)

Phase 4 enforces explicit data labels over content-free provenance supplied by trusted code.
It tracks released tool outputs conservatively; it does not detect secrets in arbitrary text,
observe initial user/model context, or prove which tokens influenced an argument. Source
classification is an operator assertion. An absent label is not evidence of clean content.

## Restrictive policy semantics

Historical `phase4-v1` plans include frozen canonical `DataRule` values in the immutable plan.
Current `phase6-v1` plans retain those data semantics and add identity authority checks. Data
atoms are compiled/runtime-supported and adapter-required. Effective-policy hashing already
included authored data rules and its projection is unchanged. Plan identity still binds the
complete compiled content, compiler version, contract ID and effective-policy hash.

Ordinary tool/task/identity authorization runs first. DENY/ERROR remains unchanged. For
ALLOW/REQUIRE_APPROVAL, union the labels of the trusted request artifacts and apply every rule
whose exact label is present:

- Denied capability membership blocks; a nonempty allowed-capability set excludes its complement.
- If either destination set is nonempty, a trusted destination category is required. Denied
  destination membership blocks; a nonempty allowed-destination set excludes its complement.
- Empty allowed sets impose no restriction. Labels without a rule impose no additional restriction.
- Any explicit denial wins across labels, yielding DENY / `DATA_FLOW_DENIED`. Otherwise missing
  required destination yields ERROR / `DATA_FLOW_CONTEXT_MISSING`. Otherwise preserve the base result.

A flow-stage result retains all matching tool IDs and all applicable data-rule IDs, including
applicable rules that did not independently block. Explicit denial precedes missing context,
independent of rule ordering. Base-denied decisions retain only their original provenance.
Data policy never grants tool permission or bypasses task scope/approval. Destinations and labels
match exactly; there is no implied confidentiality lattice, URL/path matching or classifier.

`PolicyRequest` and `NormalizedAction` bind `data_destination` and canonical artifact refs.
Refs sort by artifact ID; duplicate IDs are rejected. The complete policy-input digest includes
both fields, as does the exact action digest used for approval. Older approval/action digests
must be regenerated; this is an additive pre-1.0 schema `0.1` change with a new compiler version.

## Provenance ownership and causality

`provenance.ProvenanceEngine` is protocol-independent. It stores immutable artifact refs and
parent IDs, never content. Registration rejects reused IDs, unknown parents and loss of parent
labels. Derivation unions all parent labels with explicitly assigned labels. Clock and ID
factories are injectable. Origin identifies the observed source; it grants no authority and
never erases inherited labels. There is no sanitizer/declassification operation.

Locked synchronous snapshot/expose operations serialize frontier changes. Each request snapshots
the current exposed frontier before authorization; its later response uses exactly those parents.
An exposed response replaces only its direct frontier parents, preserving concurrent branches.
No lock spans an await, network dispatch or human approval. A later request sees committed
exposures; an earlier request is not retroactively tainted. The graph retains session lineage
with O(number of artifacts) nodes; ordinary sequential requests carry one frontier ref rather
than a growing copy of all ancestors. Wide concurrency can grow frontier width. There is no
persistent graph, cross-session propagation, eviction or general graph database.

Runtime provenance is protected application state. Tool arguments never supply/clear artifact
IDs, labels, parents or sink category. The core policy API accepts structured requests and
requires non-null trusted `AuthorityContext` for every `phase6-v1` decision. Matching
`PolicyRequest.principal` text alone does not prove identity. Static trusted configuration and
pinned signed-JWT verification are the supported Phase 6 authority sources; historical
`phase4-v1` replay keeps its prior meaning. Capability and source/sink classification still come
from trusted producers.

## MCP boundary and response release

New binding fields are deliberately distinct from existing `data_access_labels` risk metadata:

| Field | Meaning |
| --- | --- |
| `output_data_labels: null` | Unreviewed output classification. |
| `output_data_labels: []` | Reviewed; no extra labels beyond automatic tool-output labels. |
| `output_data_labels: [SECRET]` | Reviewed; add the exact declared labels to output artifacts. |
| `data_sink_destination` | Static trusted opaque sink category; null is unknown. |

All returned bodies, including upstream tool errors, receive `TOOL_OUTPUT` and
`UNTRUSTED_CONTENT`, explicit output labels, and inherited request labels. A transport exception
without returned content creates neither an artifact nor a `TOOL_RETURNED` event; dispatch remains
the last confirmed lifecycle fact. `TOOL_RETURNED.artifacts` records factual returned artifacts
before output validation. An ENFORCE-rejected response never updates exposed context.

For a response committed to release, the engine holds its frontier lock, emits typed
`DATA_EXPOSED` evidence, and then commits the frontier before runtime returns. There is no await
between these operations and the return. A failed critical write prevents ENFORCE release and
poisons subsequent calls. Exposure records boundary release, not proof of network delivery or
model ingestion; a process crash can interrupt transport after the release commitment. SHADOW
keeps actual flow DENY/ERROR decisions/signals while forwarding and tracking released output.
DISABLED still tracks output but emits no policy decision or enforcement claim.

Source/sink coverage is deliberately conservative. If any active rule uses a label other than
automatic TOOL_OUTPUT/UNTRUSTED_CONTENT, every configured/discovered bound tool must declare
reviewed output labels. If any rule constrains destinations, every such tool needs a sink
category, including read tools that receive ambient context. Missing classification refuses
ENFORCE startup; SHADOW records gaps and affected calls get explicit context ERROR. The existing
`UNSUPPORTED_RESOURCE_COVERAGE` startup code now covers binding input gaps, with exact
`data_source_classification:NAME` / `data_sink_destination:NAME` details. No-rule configurations
remain compatible. Discovery proof binds exact plan and serialized bindings; changing source
labels or sink category invalidates old proof. Proof is trusted metadata, not attestation.
Coverage reports classification completeness separately from per-rule runtime reachability:
`source_runtime_status` requires an actual bound source with the exact explicit label (or any
bound source for automatic output labels), while `sink_runtime_status` requires a bound sink in an
exact destination named by that rule. Thus reviewed empty labels can be classification `COVERED`
while a SECRET rule's source reachability is `UNREACHABLE`. `adapter_status=COVERED` requires both
complete classifications and required reachability. This establishes a possible adapter witness,
not that a real runtime flow was executed; generated synthetic policy probes remain a separate
proof dimension.

## Verification and examples

Use the existing synthetic server with:

```bash
agentsec protect mcp --contract examples/mcp/flow-contract.yaml --config examples/mcp/flow-gateway.yaml --check
agentsec contract test examples/mcp/flow-contract.yaml
agentsec contract coverage examples/mcp/flow-contract.yaml --run
```

The server is synthetic and never sends email or writes memory/files. In one session, call
`search` first. Its released response carries SECRET/UNTRUSTED_CONTENT. A subsequent
`send_email` is otherwise allowed but denied at destination `external`; a `write_file` is
otherwise allowed but denied at destination `memory`. A direct sink call before any source
has no tracked labels and therefore only exercises ordinary authority. This limitation is
intentional; real integrations must conservatively classify all relevant sources.

Generated conformance has independent set-based expectations, exact reasons/rule IDs, and
base-permitted witnesses for each capability/destination axis. Unreachable obligations are
explicit NOT_RUN with a reason. Direct policy probes may use synthetic refs. Generated Phase 1
flow cases instead emit a source request, returned labeled artifact and DATA_EXPOSED event before
the sink request. The trajectory validator reconstructs that exposed frontier, verifies each
request snapshot and checks returned parent IDs and inherited labels while preserving concurrent
sibling branches. This proves the synthetic evidence path; separate local MCP tests establish
actual source release, cross-call blocking, response rejection and shadow behavior. Coverage
reports keep classification, runtime reachability, generated obligations and execution separate,
and state the unobserved-context boundary.

Diff compares ordinary authority separately from the data clamp. For data, it gives both plans
the same synthetic base grant and invokes the native evaluator across the union of labels,
capabilities, destinations, unknown destination and collision-free OTHER sentinels. Because the
rules compose by any-deny-wins without inter-label predicates, single-label partitions cover
the exact per-label restriction semantics. It reports data tightening/relaxation, explanation
changes and authored set changes. This is finite exact set-policy comparison, not general formal
equivalence or content analysis. Nothing activates a policy automatically.

## Phase 5 offline lifecycle

See [replay and incidents](replay-incidents.md) for strict evidence bundles, exact versus legacy
source plan binding, offline substituted security replay, semantic trace diff, evidence-backed
classification, safe assertion promotion and the local/CI regression gate. Historical evidence
remains immutable; missing or redacted material is never reconstructed. This does not extend
model/context coverage or authorize any live execution.


## Phase 9 local graph composition

Explicit `phase9-v1` operator-created ENFORCE sessions now add bounded single-parent graphs,
all-ancestor authority/approval/data ceilings, atomic recursive budgets and protected adjacent
messages. Standalone `phase6-v1` behavior and historical digests retain their existing meaning.
The gateway guard applies to direct calls and adapter rebinding. Phase 8 pins restrict tools;
they do not authenticate peers or approve delegation. See [local multi-agent security](multi-agent-security.md)
for ownership, evidence-before-import, finality, source replay blockers, DRAFT graph promotion,
unsupported modes and exact limitations. Earlier one-hop/future-graph statements describe their
original phase boundary. Independent Phase 7–8 acceptance remains unconfirmed.
