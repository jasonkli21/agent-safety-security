# Threat model v1 — Phase 0

This model covers local parsing, canonical specification, and evidence representation. It does
not claim that Phase 0 prevents attacks against a running agent.

## Assets

User data, personal information, credentials, external write authority, filesystem/code
execution, infrastructure/financial authority, security contracts/policy, approval records,
evidence/audit logs, agent memory, and tool schemas/descriptions all need protection. A contract
can describe these concerns; describing one does not establish an enforcement boundary.

## Adversaries and failure sources

A malicious end user or content author may inject privileged-looking instructions. Compromised
tools/MCP servers, malicious plugins/skills, dependencies, and other agents may supply misleading
metadata, outputs, or authority claims. A compromised agent can request arbitrary actions.
An over-permissioned benign agent can still cause damage. Operator configuration mistakes,
typographic errors, ambiguous rules, stale approvals, and incomplete evidence are accidental
sources of the same failures. A local process with permission to edit policy or evidence is
inside the trusted computing base; these types do not constrain that process.

## Trust boundaries

```text
Developer-reviewed configuration (trusted intent)
                 |
                 v
Bounded parser -> strict models -> semantic checks -> canonical identities
                 |                               |
                 v                               v
Future structured policy boundary          Security-sensitive evidence
                 ^                               ^
                 |                               |
User content / model output / retrieved documents / tools / other agents
       (context or proposals; never authority merely by existing)
```

Configuration is trusted only when controlled outside the protected agent's write scope.
Model output and generated policy suggestions are untrusted. User content has contextual trust,
not automatic privilege. External retrieval and tool responses can be malicious, even from a
local tool server. Evidence storage is security-sensitive and requires access control later.
A declared TRUSTED_CONFIG label alone authenticates nothing.

## Threat coverage and boundaries

Every canonical category is defined in [taxonomy](taxonomy.md). Their Phase 0 treatment is:

| Family / categories | Representation and residual risk |
| --- | --- |
| Goal manipulation: PROMPT_INJECTION, GOAL_HIJACKING | Scenario injections preserve untrusted content separately from structured policy. No detector or prevention. |
| Tool misuse: UNAUTHORIZED_TOOL_USE, EXCESSIVE_AGENCY, ARGUMENT_VIOLATION | Capabilities, task/resource scopes and typed requests separate intent from authority. No tool dispatch or argument enforcement. |
| Approval/control: APPROVAL_BYPASS, POLICY_BYPASS | Exact-action digests, explicit outcomes, request references, separate dispatch evidence. No broker, redemption, authentication or runtime guard. |
| Data loss: SECRET_EXFILTRATION, PII_EXPOSURE | Data rules, labels, canary assertions and content-free artifact references. No egress inspection, redaction, taint tracking or automatic classification. |
| Persistent context: MEMORY_POISONING | Static memory artifact references and injection source/trust representation. No memory-write controls. |
| Tool/supply chain: TOOL_POISONING, SUPPLY_CHAIN_CHANGE | Stable tool IDs and separate schema/description SHA-256 fingerprints. No signature validation, trusted registry or change monitor. |
| Resource abuse: RESOURCE_EXHAUSTION | Strict nonnegative budgets and deterministic assertion types. No runtime counters, deadlines or cost metering. |
| Delegation: DELEGATION_ESCALATION | Explicit principals, task/capability scopes, aware issue/expiry ordering and parent IDs. No subset, authenticity, freshness or recursion enforcement. |
| Evidence: TRACE_INTEGRITY_FAILURE | Typed payloads, matching event kinds and per-run increasing sequences/unique IDs. No tamper-proof storage, causal verification or side-effect oracle. |

## In-scope guarantees established by tests

The local loader bounds byte size and nesting, rejects unsafe YAML constructs, duplicate keys,
unknown fields/versions, malformed types, invalid time windows, negative budgets, duplicate IDs,
and exact-selector contradictions. Canonical identities are deterministic under documented
map/set/rule ordering. Tool identity does not depend on mutable metadata. Approval digests
change when bound action fields change. Evidence distinguishes requested/decided/approved/
dispatched/returned/verified stages without requiring secret content. Generated schemas and
examples are checked locally. Network attempts in the default test suite fail.

These guarantees concern accepted representations. SHA-256 fingerprints are ordinary content
hashes, not signatures. Duplicate references to external resources or malicious but structurally
valid schemas/content remain possible. Resource categories and assertion semantics require
precise execution definitions in future phases.

## Non-guarantees and assumptions

Phase 0 does not authenticate principals/agents, sandbox code, prevent prompt injection,
authorize real actions, enforce policy/delegation/budgets, propagate provenance, encrypt secrets,
verify external effects, or implement hosted tenancy. Producers must supply truthful metadata
and redacted summaries. Frozen models prevent attribute reassignment but nested JSON objects
remain mutable; trusted callers must revalidate input and compare fresh hashes before use.

The parser's 1 MiB/64-depth limits bound document processing rather than offering a CPU/memory
sandbox for arbitrary library callers. Tool schema validation checks Draft 2020-12 schema
structure locally; it does not validate a tool implementation or resolve external `$ref` targets.
A valid scenario is a test specification, not a successful test result. A valid event stream is
an evidence representation, not proof that the events happened. Protected security policy must
remain outside ordinary agent write access when runtime enforcement is added.

## Phase 8 trust composition

The optional operator-owned supply-chain guard restricts protected implementations through
RuntimeGateway; it never grants contract or delegated authority. Metadata pins and Ed25519
signatures do not attest runtime code. Current residual threat: a substituted local MCP executable
may have startup effects before tool discovery. Trust-enabled ENFORCE requires an externally
controlled launch boundary, which agentsec does not verify. Arbitrary observed file bytes are not
bound to a callable/process. Required candidate presence is explicit and optional. See
[supply-chain trust](supply-chain-trust.md) for exact proof limits. Independent Phase 7 acceptance
is still unconfirmed.
