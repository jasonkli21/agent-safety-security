# Agent Security Contract v0.1

A contract describes reviewed security intent outside agent context. Phase 0 validates the
representation; it does not authorize, execute, or protect a running agent. The source of truth
is `src/agentsec/contracts/models.py` and the generated
[contract schema](../schemas/generated/agent-security-contract.schema.json).

## Authoring and field reference

Use UTF-8 YAML or JSON with a required string `schema_version: "0.1"`. Unknown fields are errors
at every model level. All identifiers are 1–128 ASCII characters, start with an alphanumeric,
and then contain only alphanumerics or `_ . : / -`. IDs are case-sensitive; whitespace is never
trimmed. Capability IDs are lowercase dot-separated components, each starting with a letter
and continuing with letters, digits, or underscores (3–128 characters). Wildcards have no
special meaning and are rejected in capability IDs.

| Section | Fields and meaning |
| --- | --- |
| `metadata` | Required `contract_id`, `name`; optional `description`, `contract_version`. Version is authored revision metadata, separate from schema version. |
| `agent` | Required `agent_id`, `name`, `environment`; optional `owner` principal, opaque `trust_level` identifier, `framework`, `model_provider`, `model_name`. The trust-level identifier is future-facing context with no authority by itself; it is distinct from provenance `TrustClass`. These context strings carry no credentials or implicit authority. |
| `identity` | Required `principal`; optional `acts_on_behalf_of`. Each is a `principal_id` plus `principal_type` (`USER`, `AGENT`, `SERVICE`). References are external; there is no contained principal registry or authentication check. |
| `task_scope` | Optional `task_id`, `description`, `requested_capabilities`, `resource_scopes` model. Within a supplied scope the first two are required. Resources map capability IDs to sets of opaque resource strings. Scope expresses requested work and never grants permission. |
| `tools.rules` | Unordered rules with required `rule_id`, `capability`, `decision`; optional opaque exact `resource` selector. Decisions are `ALLOW`, `DENY`, `REQUIRE_APPROVAL`. Omitted `tools` or rules means no explicit grants. No argument constraint language exists yet. |
| `data.rules` | Unordered rules with required `rule_id`, `label`; sets `allowed_destinations`, `denied_destinations`, `allowed_capabilities`, `denied_capabilities` default empty. Destination names are opaque category IDs; no URL/glob matching is implemented. Each label has at most one rule. Phase 4 compiles these as restrictive tracked-data semantics; see below. |
| `budgets` | Optional nonnegative `max_model_calls`, `max_tool_calls`, `max_external_writes`, `max_destructive_calls`, `max_runtime_seconds`, `max_delegated_agents` (strict integers), and finite nonnegative `max_cost_usd` (JSON number). Zero is valid; omitted/null is unspecified, never an implicit grant. |
| `approvals` | `default_timeout_seconds`, positive strict integer, defaults to 120. |
| `invariants` | Unordered declarations: required `id`, `description`; optional taxonomy `category`. These are prose intent, not executable predicates. |
| `environment` | Required `mode`, which must equal `agent.environment`. |

Strings marked nonempty in the schema have a maximum length of 8192. Tool and data rule IDs
share one namespace within a contract. Duplicate IDs, identical capability/resource selectors
(including identical duplicate decisions), repeated data labels, allow/deny intersections, and
duplicate invariant IDs are rejected. Broader overlapping scopes are not solved for satisfiability.
Different resource selectors can coexist for the same capability.

A missing/null `requested_capabilities` or `resource_scopes` means unspecified; an explicit
empty collection means none requested. These serialize distinctly and have different policy
hashes. They must later be intersected with explicit policy and delegation, never treated as
standalone grants. Missing/null `task_scope` means no task scope is specified.

## Policy and approval semantics

The future decision precedence is explicit deny > required approval > explicit allow >
default deny. Unknown capabilities have no implicit grant. `ERROR` is a decision result, not
an authored rule. There is only a `PolicyEngine` protocol accepting `PolicyRequest` and a
contract; Phase 0 does not implement this precedence as an engine.

A `PolicyRequest` identifies principal, agent, capability, optional tool/resource/task/delegation,
structured argument summary, artifact/trajectory references, environment, and timestamp. Its
environment must equal `agent.environment`; a mismatch is rejected as `INVALID_SCHEMA` at path
`environment`. It is not a prompt. `PolicyDecision` carries request/contract references, effective policy hash,
matched rule IDs, nonempty stable reason codes, outcome, timestamp, and optional explanation.

Approval models have their own [schemas](../schemas/generated/approval-request.schema.json).
An approval request requires a policy request ID and an action digest. `NormalizedAction`
requires schema version `0.1` and contains principal, agent ID, environment, task/delegation IDs, tool ID, capability, resource,
**complete arguments**, tool schema/description hashes, and effective policy hash. Compute
`action_digest()` from this model, never from a lossy/redacted summary. Map ordering is ignored;
argument array ordering is preserved. Any bound field change changes the digest. Raw action
arguments need not be persisted in evidence. `ApprovalDecision` names the approver and request,
uses `APPROVE`/`DENY`, and only permits `ONE_SHOT` scope. Timestamps must be timezone-aware;
expiry must strictly follow creation. Phase 0 does not authenticate approvers, redeem approvals,
check freshness at dispatch, or prevent reuse. An approval is not proof of execution.

## Loading and structured errors

Use `load_contract(Path(...))`, `load_contracts([...])`, or `validate_data(Model, json_value)`.
The latter uses strict Pydantic JSON semantics so wire enum strings, ISO timestamps, and JSON
arrays representing sets/tuples are accepted consistently. Python constructors are stricter
and expect enum/set/datetime instances. String booleans and numbers, numeric booleans, unknown
enums, naive timestamps, non-finite numbers, and unexpected fields are rejected.

The loader reads at most 1 MiB and allows nesting depth at most 64. It rejects YAML anchors,
aliases, explicit tags, duplicate mapping keys, multiple documents, non-string map keys, and
non-UTF-8 input. The literal string key `<<` is accepted as ordinary data; merge-key resolution
is disabled, so it never merges mappings. Only lowercase `true`/`false` and JSON number spellings receive
boolean/number interpretation; YAML `yes`, `off`, leading-zero numbers, and dates remain strings.
Use quoted schema versions. File suffix must be `.yaml`, `.yml`, or `.json`.

`ArtifactValidationError.issues` contains `ValidationIssue` records with `code`, `message`,
`path`, and severity. Schema failures omit raw input values. Semantic checks run after schema
validation, including when constructing models directly. Paths into rule arrays refer to
normalized rule order. Loaded sets also reject duplicate contract IDs. A JSON Schema validator
covers structural types; Python semantic validation additionally checks cross-field constraints.

## Canonicalization and the two identities

`canonical_contract()` emits compact UTF-8 JSON with sorted object keys, explicit defaults and
nulls, stable enum values, sorted mathematical sets, and rules/invariants sorted by ID. Generic
JSON arrays remain ordered. Timezone-aware timestamps normalize to UTC `Z`. The project format
is not RFC 8785: it does not normalize Unicode or equate arbitrary numeric spellings such as
JSON argument `1` and `1.0`. Equivalent authored YAML/JSON contract values do normalize alike.
Never use an ordinary unsorted `model_dump_json()` for signing or identity comparison.

`document_hash()` is SHA-256 over the full normalized authored contract. It includes display
names, descriptions, revision metadata, model/framework context, and security fields. There
are no generated load timestamps or stored derived hashes in the authored contract.

`effective_policy_hash()` uses an explicit projection: schema version; agent ID, environment,
owner and trust level; principal bindings; task ID, requested capabilities and resource scopes;
tool/data rules; budgets; approval settings; invariants; environment. It excludes metadata,
agent display name/framework/model context, and task description. Invariant prose remains
included conservatively because it is security intent, despite not being executable yet.
Rule/invariant IDs are included for evidence binding. Cosmetic contract description changes
alter only document identity; rule/budget/principal/data changes alter effective policy identity.
A new field must receive a deliberate projection decision before release.

Models freeze attribute assignment and use tuples/frozensets for modeled collections. JSON
objects and their nested arrays remain mutable values; frozen models are not a sandbox or deep
immutability guarantee. Keep validated artifacts within trusted code, revalidate at ingestion,
and recompute hashes before relying on a snapshot. Never expose protected configuration to
agent mutation. Hashes detect changes; they are not signatures or authentication.

## Examples and versioning

The tested public examples are [research](../examples/contracts/research.yaml),
[support with approval](../examples/contracts/support.yaml), and
[coding](../examples/contracts/coding.yaml). Validate with:

```bash
agentsec contract validate examples/contracts/research.yaml
agentsec examples validate
```

Schema `0.1` is the only accepted version. No migration or compatibility fallback is implicit.
Before 1.0, schema changes require review of generated schemas, golden forms, and these hash
projections. Delegation subset checks, resource matching, argument constraints, budget metering,
the later scope is governed by the current focused runtime/provenance docs.

## Phase 2 executable subset

The native runtime engine now implements the documented exact rule precedence, task ceilings,
identity consistency, exact approval redemption, and supported session budgets. Unsupported
active semantics refuse ENFORCE startup. MCP resource-dependent semantics additionally require
binding-aware coverage after discovery: required resource inputs must have an extraction path,
and a stricter resource exception below a broader ALLOW requires an explicit `opaque_exact`
operator assertion. This does not add a generic resource canonicalizer. Phase 1's scripted
evaluation remains independent; it does not implicitly execute contract rules. See
[runtime coverage](runtime-mcp.md).

## Phase 3 compilation and inspection

The supported tool rules, protected identity, task ceiling, runtime budget configuration and
approval timeout compile into an immutable `CompiledSecurityPlan`. Its explicit version,
compiler version, contract ID, effective policy hash and source-linked semantic atoms make
executable intent inspectable. Invariants, acts-on-behalf-of and unsupported
budgets remain gaps; compilation does not enforce them. ENFORCE still refuses those gaps.

`contract compile` intentionally exposes authored policy values, including exact resources.
Conformance/coverage/diff reports minimize content using IDs/digests and outcomes. They do not
persist runtime arguments/responses. Exported schemas cover all four new public artifacts.
See [contract conformance](contract-conformance.md) for commands and precise coverage limits.


## Phase 4 executable data rules

`phase4-v1` additionally freezes data rules in the compiled plan. Applicable labels union over
trusted request artifact refs. Capability/destination deny membership or exclusion from a
nonempty allowlist clamps base ALLOW/REQUIRE_APPROVAL to DENY / DATA_FLOW_DENIED. Empty allow
sets impose no restriction. If a destination-constrained applicable rule lacks trusted context,
ERROR / DATA_FLOW_CONTEXT_MISSING results unless an explicit flow denial already applies.
Base DENY/ERROR remains unchanged. Matching flow decisions retain matching tool IDs and all
applicable data-rule IDs. Labels do not implicitly imply other labels. No rule grants authority.

PolicyRequest and NormalizedAction add an optional exact data_destination and bind canonical
artifact context (unique IDs sorted deterministically). Full policy-input and action digests
cover these fields. Existing effective-policy hashing already includes data rules and is
unchanged. Schema stays 0.1 for additive pre-1.0 changes; strict consumers and old approvals need
regeneration. See [tracked provenance](provenance-data-flow.md) for classification, release,
concurrency and unobserved-context limitations.
