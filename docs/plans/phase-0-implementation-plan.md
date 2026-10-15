# Agent Safety & Security Platform — Phase 0 Detailed Implementation Plan

**Document:** `docs/plans/phase-0-implementation-plan.md`  
**Phase:** 0 — Foundation, Threat Model, and Canonical Schemas  
**Status:** Implementation-ready plan refined for repository bootstrap  
**Depends on:** Product Requirements Document and `docs/architecture.md`  
**Primary goal:** Establish the stable security language and repository foundations required for Phases 1–3 without prematurely implementing evaluation or runtime enforcement. Last reviewed 2026-10-15.

---

## 1. Phase 0 Objective

Phase 0 creates the foundational interfaces that the evaluation engine and runtime gateway must share.

At completion, the repository should contain a coherent, tested representation of:

- security contracts;
- principals and agent identity;
- delegated authority;
- tools and capabilities;
- risk classifications;
- policy requests and decisions;
- approvals;
- security events;
- evaluation scenarios;
- findings;
- minimal provenance artifacts;
- versioning and canonicalization rules.

It should also contain the initial threat model and evidence model.

Phase 0 is not a feature demo phase. Its purpose is to prevent architectural drift later.

The detailed implementation may refine field names where tests expose a problem, but it must preserve the architectural semantics. Any material deviation from the PRD/architecture/plan must be documented in the Phase 0 implementation report rather than silently changing the product model.

The central success criterion is:

> **Phase 1 evaluation and Phase 2 enforcement can both be implemented without inventing incompatible schemas, terminology, or policy semantics.**

---

## 2. Non-Goals

Do **not** implement the following in Phase 0:

- real MCP proxy/gateway behavior;
- production authorization engine;
- real human approval workflow;
- full evaluation runner;
- LLM/model-provider integrations;
- prompt-injection classifiers;
- data-flow propagation engine;
- incident replay;
- multi-agent delegation enforcement;
- OAuth/OIDC;
- hosted API/control plane;
- web UI;
- SQLite persistence unless it becomes necessary for a concrete Phase 0 requirement;
- Cedar/OPA integration;
- custom sandbox;
- OpenTelemetry exporter beyond optional schema/mapping notes.

Do not add empty framework code “for later” unless it defines an interface actually required by the Phase 0 design.

---

## 3. Phase 0 Deliverables

### Required code deliverables

1. Core domain package.
2. Stable taxonomy enums.
3. `AgentSecurityContract` schema v0.1.
4. Scenario schema v0.1.
5. Canonical security event schema v0.1.
6. Policy request/decision models.
7. Approval models.
8. Tool descriptor and capability models.
9. Principal/agent/delegation models.
10. Minimal data-artifact/provenance models.
11. Strict YAML/JSON loading.
12. Semantic validation layer.
13. Canonical serialization and deterministic hashing.
14. JSON Schema export.
15. CLI validation commands.
16. Representative valid and invalid fixtures.
17. Unit and property/golden tests.
18. Explicit typed/domain errors.

### Required documentation deliverables

1. `docs/architecture.md`
2. `docs/threat-model.md`
3. `docs/evidence-model.md`
4. `docs/security-contract.md`
5. `docs/scenario-format.md`
6. `docs/taxonomy.md`
7. Phase 0 implementation report at completion.

The PRD remains the source of product intent; architecture is the source of technical structure; these focused docs explain security semantics in more detail.

---

## 4. Exit Criteria

Phase 0 is complete only when all of the following are true.

### Domain consistency

- All serialized security artifacts have an explicit schema version.
- Taxonomy values are centralized and stable.
- The same `ToolDescriptor`, `PolicyDecision`, and event types can be imported by future eval and gateway packages.
- No MCP/provider-specific type exists in the core domain.

### Validation

- Valid contract examples parse successfully.
- Invalid/unknown fields fail loudly.
- Unsupported schema versions fail explicitly.
- Semantic contradictions produce structured validation errors.
- YAML and JSON normalize to the same in-memory representation.

### Canonicalization

- Equivalent contracts produce identical canonical serialization.
- Equivalent contracts produce the same deterministic **document hash** and **effective policy hash** according to documented semantics.
- Ordering-only differences do not change either hash.
- Security-relevant value changes change both; cosmetic-only changes may change the document hash while leaving the effective policy hash unchanged.

### CLI

The following commands work:

```bash
agentsec version
agentsec contract validate <file>
agentsec scenario validate <file>
agentsec schema export --out <dir>
agentsec examples validate
```

### Testing

- Test suite is fully local and requires no credentials/network.
- Negative tests cover malformed and dangerous configuration.
- Round-trip serialization tests pass.
- Static analysis/lint/type checks pass.
- Public schema fixtures are exercised in CI.

### Documentation

A new contributor can answer:

- what is trusted;
- what is untrusted;
- how policy decisions are represented;
- how events differ from findings;
- how contracts are versioned;
- what Phase 0 intentionally does not implement.

---

## 5. Proposed Repository Layout

The scaffold step may adjust top-level project tooling, but Phase 0 should target approximately:

```text
agent-safety-security/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/
│   └── agentsec/
│       ├── __init__.py
│       ├── version.py
│       ├── cli/
│       │   ├── __init__.py
│       │   └── main.py
│       ├── domain/
│       │   ├── __init__.py
│       │   ├── taxonomy.py
│       │   ├── identity.py
│       │   ├── tools.py
│       │   ├── provenance.py
│       │   ├── policy.py
│       │   ├── approvals.py
│       │   ├── events.py
│       │   ├── scenarios.py
│       │   └── findings.py
│       ├── contracts/
│       │   ├── __init__.py
│       │   ├── models.py
│       │   ├── loader.py
│       │   ├── validation.py
│       │   ├── canonical.py
│       │   └── schema_export.py
│       ├── evidence/
│       │   ├── __init__.py
│       │   └── ports.py
│       └── policy/
│           ├── __init__.py
│           └── ports.py
├── examples/
│   ├── contracts/
│   └── scenarios/
├── tests/
│   ├── unit/
│   ├── fixtures/
│   │   ├── contracts/
│   │   ├── scenarios/
│   │   └── events/
│   └── golden/
├── schemas/
│   └── generated/
└── docs/
    ├── architecture.md
    ├── threat-model.md
    ├── evidence-model.md
    ├── security-contract.md
    ├── scenario-format.md
    ├── taxonomy.md
    └── plans/
        └── phase-0-implementation-plan.md
```

Avoid adding `eval/`, `runtime/`, `adapters/mcp/`, or hosted-service directories until they contain real interfaces/code required by a phase.

---

## 6. Tooling Baseline

The scaffolding step may make final choices, but the implementation should assume:

### Runtime

- Python 3.12+ unless compatibility goals dictate otherwise;
- Pydantic v2;
- safe YAML library;
- standard library wherever practical.

### Development

- `pytest`;
- Ruff;
- mypy or pyright;
- optional Hypothesis for high-value invariants;
- pre-commit if consistent with scaffold conventions.

### Dependency rule

Every new dependency requires one of:

- substantial implementation reduction;
- significant correctness benefit;
- ecosystem interoperability.

Avoid large agent frameworks in Phase 0.

---

## 7. Workstream 0A — Establish Canonical Terminology

### Goal

Ensure names mean one thing across code, docs, tests, and future phases.

### Tasks

#### 0A.1 Create `docs/taxonomy.md`

Define:

- principal;
- agent;
- delegation;
- task;
- capability;
- tool;
- resource;
- policy request;
- policy decision;
- approval;
- security signal;
- security event;
- finding;
- incident;
- data artifact;
- scenario;
- assertion;
- run;
- trace.

#### 0A.2 Implement taxonomy enums

Create stable identifiers for:

##### Principal type

```text
USER
AGENT
SERVICE
```

##### Policy outcome

```text
ALLOW
DENY
REQUIRE_APPROVAL
ERROR
```

##### Enforcement mode

Define now for future compatibility:

```text
ENFORCE
SHADOW
DISABLED
```

Do not implement enforcement.

##### Side-effect class

```text
NONE
READ
INTERNAL_WRITE
EXTERNAL_WRITE
DESTRUCTIVE
CODE_EXECUTION
IDENTITY_PRIVILEGE
FINANCIAL
INFRASTRUCTURE
```

##### Data labels

Initial set:

```text
PUBLIC
INTERNAL
SENSITIVE
SECRET
PII
CREDENTIAL
UNTRUSTED_CONTENT
USER_PROVIDED
TOOL_OUTPUT
```

##### Security categories

```text
PROMPT_INJECTION
GOAL_HIJACKING
UNAUTHORIZED_TOOL_USE
EXCESSIVE_AGENCY
ARGUMENT_VIOLATION
APPROVAL_BYPASS
SECRET_EXFILTRATION
PII_EXPOSURE
MEMORY_POISONING
TOOL_POISONING
SUPPLY_CHAIN_CHANGE
RESOURCE_EXHAUSTION
DELEGATION_ESCALATION
POLICY_BYPASS
TRACE_INTEGRITY_FAILURE
```

##### Event types

At minimum:

```text
RUN_STARTED
RUN_FINISHED
TOOL_REQUESTED
POLICY_EVALUATED
APPROVAL_REQUESTED
APPROVAL_DECIDED
TOOL_DISPATCHED
TOOL_RETURNED
SECURITY_SIGNAL
RUN_TERMINATED
EFFECT_VERIFIED
```

### Acceptance criteria

- No duplicate string literals for canonical taxonomy values outside tests/serialization glue.
- Docs and code use the same terminology.
- Enum serialized values are stable machine-readable identifiers.
- Tests assert enum serialization.

---

## 8. Workstream 0B — Threat Model v1

### Goal

Create the security assumptions that later implementation tests against.

### File

`docs/threat-model.md`

### Required sections

#### 0B.1 Assets

Document security-critical assets:

- user data;
- credentials;
- external write authority;
- filesystem/code execution;
- infrastructure authority;
- financial authority;
- security policy;
- approval decisions;
- evidence/audit logs;
- agent memory;
- tool metadata.

#### 0B.2 Adversaries

Include:

- malicious user;
- malicious external content author;
- compromised tool/MCP server;
- malicious plugin/skill;
- compromised agent;
- over-permissioned benign agent;
- dependency/supply-chain attacker;
- another agent;
- operator configuration mistake.

#### 0B.3 Trust boundaries

Draw a repository-independent diagram.

Explicitly classify:

- policy/config: trusted;
- model output: untrusted;
- user content: contextual trust, not automatically privileged;
- external retrieved content: untrusted;
- tool responses: untrusted unless specifically classified;
- evidence store: security-sensitive.

#### 0B.4 Threat families

Map the PRD threat classes to canonical security categories.

#### 0B.5 In-scope guarantees

Examples:

- contract parser rejects malformed/unknown security config;
- policy configuration is modeled separately from agent content;
- future runtime checks will use structured requests;
- event model distinguishes authorization from execution.

#### 0B.6 Explicit non-guarantees

Examples:

- Phase 0 does not prevent real prompt injection;
- Phase 0 does not sandbox code;
- Phase 0 does not authenticate agents;
- Phase 0 does not prove side effects.

### Acceptance criteria

- Every canonical security category has a threat-model description or explicit rationale.
- Threat model identifies both malicious and accidental failure.
- No claim implies Phase 0 provides runtime protection.

---

## 9. Workstream 0C — Identity and Delegation Models

### Goal

Create minimal types that support future least privilege without overdesigning IAM.

### Files

- `src/agentsec/domain/identity.py`
- tests in `tests/unit/domain/`

### Models

#### `PrincipalRef`

Fields:

```text
principal_id: str
principal_type: PrincipalType
```

Validation:

- non-empty stable ID;
- reasonable bounded length;
- no hidden whitespace.

#### `AgentIdentity`

Fields:

```text
agent_id: str
name: str
owner: PrincipalRef | None
environment: str
trust_level: str | None
framework: str | None
model_provider: str | None
model_name: str | None
```

Do not encode runtime model credentials.

#### `TaskScope`

Initial shape should be conservative:

```text
task_id: str
description: str
requested_capabilities: set[str] | None
resource_scopes: dict[str, list[str]] | None
```

`None` must not ambiguously mean both “all” and “none.” Document semantics exactly.

Recommended:

- absent/`None` = unspecified;
- explicit empty set = no capability requested in this scope;
- `TaskScope` by itself never grants authority; effective authority is produced only by intersecting task scope with explicit policy/delegation in later phases.
- contract validation later resolves whether unspecified task scope is acceptable.

#### `Delegation`

Fields:

```text
delegation_id
delegator
delegate
task_scope
capability_scope
issued_at
expires_at?
parent_delegation_id?
```

Phase 0 validation:

- delegate cannot be missing;
- expiry must be after issue time;
- no enforcement of subset relationships yet.

### Acceptance criteria

- models are framework-independent;
- serialization is deterministic;
- tests cover invalid timestamps/IDs;
- docs clearly state delegation enforcement is future work.

---

## 10. Workstream 0D — Tool and Capability Model

### Goal

Represent tools independently of MCP/provider-specific wire formats.

### File

`src/agentsec/domain/tools.py`

### Models

#### `CapabilityId`

Prefer a validated value object/string convention:

```text
namespace.action
```

Examples:

```text
email.send
calendar.read
filesystem.read
shell.execute
```

Avoid hard-coding a fixed global registry in Phase 0.

#### `ToolDescriptor`

Fields:

```text
tool_id
namespace
name
protocol
server_id?
version?
description
input_schema
output_schema?
description_hash
schema_hash
side_effect_class
risk_tags[]
data_access_labels[]
destructive
idempotent?
capabilities[]
```

### Hashing rules

Create helper functions for:

- normalized input schema hash;
- description hash.

Use SHA-256 or similarly standard digest.

Do not call a hash a signature.

### Validation

- schema objects must be JSON-serializable;
- `destructive=True` should be compatible with side-effect class;
- tool must declare at least one capability;
- ID and capability names are bounded and normalized.

### Acceptance criteria

- two semantically identical JSON schemas with different key order hash identically;
- description change changes description hash;
- tool ID remains distinct from mutable hashes;
- no MCP classes imported.

---

## 11. Workstream 0E — Provenance Primitive Models

### Goal

Define enough provenance language for future data-flow security while avoiding a full taint engine.

### File

`src/agentsec/domain/provenance.py`

### Models

#### `DataOrigin`

Fields:

```text
origin_type
source_id?
trust_class
```

#### `DataArtifactRef`

Fields:

```text
artifact_id
labels: set[DataLabel]
origin
parent_artifact_ids
content_hash?
```

### Rules

- raw content is not required;
- artifact IDs must be distinct from content hashes;
- parent relationships are references, not embedded object graphs;
- no propagation logic in Phase 0.

### Acceptance criteria

- artifact can represent untrusted retrieved data;
- artifact can represent secret-bearing data;
- tests demonstrate provenance graph references;
- docs explicitly defer propagation semantics to Phase 4.

---

## 12. Workstream 0F — Policy Request and Decision Model

### Goal

Create the interface boundary future enforcement uses.

### File

`src/agentsec/domain/policy.py`

### `PolicyRequest`

Fields should include only stable canonical concepts:

```text
request_id
principal
agent
task_scope?
delegation_id?
capability
tool_id?
resource?
arguments_summary?
data_artifact_refs[]
trajectory_ref?
environment
requested_at
```

Do not put raw arbitrary prompt text into the required policy request.

`arguments_summary` should be structured JSON-compatible data and may be absent/redacted.

### `PolicyDecision`

Fields:

```text
decision_id
request_id
outcome
matched_rule_ids[]
reason_codes[]
human_reason?
contract_id
effective_policy_hash
decided_at
```

### Reason code design

Define stable reason identifiers such as:

```text
EXPLICIT_ALLOW
EXPLICIT_DENY
APPROVAL_REQUIRED
UNKNOWN_CAPABILITY
OUTSIDE_TASK_SCOPE
BUDGET_EXCEEDED
DATA_FLOW_DENIED
INVALID_REQUEST
POLICY_ENGINE_ERROR
```

Not all must be used in Phase 0, but the set should support Phases 2–4.

### Decision semantics

Document precedence:

```text
deny > approval > allow > default deny
```

This is semantic documentation in Phase 0; no full rule engine yet.

### Policy engine port

Create protocol/interface only:

```python
class PolicyEngine(Protocol):
    def decide(
        self,
        request: PolicyRequest,
        contract: AgentSecurityContract,
    ) -> PolicyDecision: ...
```

No production implementation required.

A tiny fake/stub may exist in tests.

### Acceptance criteria

- future MCP gateway can produce a request without altering the model;
- decisions are explainable through reason codes;
- no model-provider fields are required;
- no LLM call exists in policy package.

---

## 13. Workstream 0G — Approval Models

### Goal

Ensure approvals cannot later become an ambiguous boolean.

### File

`src/agentsec/domain/approvals.py`

### Models

#### `ApprovalRequest`

Fields:

```text
approval_id
policy_request_id
action_digest
summary
reason_codes[]
created_at
expires_at?
```

`action_digest` binds approval to the exact normalized action representation.

#### `ApprovalDecision`

Fields:

```text
approval_id
approver
outcome: APPROVE | DENY
scope: ONE_SHOT initially
decided_at
```

Phase 0 does not implement multi-action/session approvals.

### Acceptance criteria

- test proves a changed action produces a changed digest;
- approval cannot be represented without a policy request reference;
- docs state an approval is not proof of tool execution.

---

## 14. Workstream 0H — Agent Security Contract v0.1

### Goal

Create the central artifact of the platform.

### Files

- `src/agentsec/contracts/models.py`
- `docs/security-contract.md`
- examples in `examples/contracts/`

### Recommended top-level shape

```yaml
schema_version: "0.1"

metadata:
  contract_id: travel-agent
  name: Travel Agent Security Contract
  description: ...

agent:
  agent_id: travel-agent
  environment: development

identity:
  principal: agent:travel-agent
  acts_on_behalf_of: user:local

task_scope:
  default_capabilities:
    - calendar.read

tools:
  rules:
    - capability: calendar.read
      decision: allow

    - capability: calendar.create
      decision: require_approval

    - capability: email.send
      decision: deny

data:
  rules:
    - label: CREDENTIAL
      external_destinations: deny

budgets:
  max_tool_calls: 30
  max_external_writes: 3
  max_runtime_seconds: 300

approvals:
  default_timeout_seconds: 120

invariants:
  - id: untrusted-content-cannot-authorize
    description: Untrusted content must never grant authority.

environment:
  mode: development
```

The exact field names may be refined during implementation, but the following structural requirements are mandatory.

### Contract sections

#### Metadata

Fields:

```text
contract_id
name
description?
contract_version?
```

#### Agent binding

Fields:

```text
agent_id
environment
```

Avoid hard-wiring one model provider.

#### Identity

Minimal references to agent/user/service principals.

#### Tool/capability rules

Each rule must have:

```text
rule_id
capability
decision
resource selector?  # optional in v0.1
argument constraints?  # optional structured placeholder
```

Decisions:

```text
allow
deny
require_approval
```

No `error` authoring rule.

#### Data rules

Keep v0.1 intentionally modest.

Support structural representation of:

```text
label
allowed/denied destination categories or capabilities
```

Do not attempt full taint logic.

#### Budgets

Optional non-negative values:

```text
max_model_calls?
max_tool_calls?
max_external_writes?
max_destructive_calls?
max_runtime_seconds?
max_cost_usd?
max_delegated_agents?
```

#### Invariants

In Phase 0, invariants are declarative metadata:

```text
id
description
category?
```

Do not invent a general executable invariant language yet.

Phase 3+ can compile known invariant types.

### Strictness

- extra fields forbidden;
- unknown decisions forbidden;
- duplicate rule IDs forbidden;
- duplicate contract IDs within a loaded set rejected;
- duplicate exact capability rules either rejected or normalized only if semantics are unambiguous.

Recommended: reject ambiguous duplicates.

### Semantic validation

Implement checks for:

- negative budgets;
- invalid timeout;
- duplicate IDs;
- contradictory identical rules;
- capability naming;
- unresolved principal references if using a contained principal list;
- unsupported schema version.

Do not attempt deep policy satisfiability.

### Acceptance criteria

- at least three valid example contracts;
- at least eight invalid fixtures;
- JSON Schema exported;
- YAML/JSON equivalent parsing;
- document hash and effective policy hash deterministic;
- docs explain every v0.1 field.

---

## 15. Workstream 0I — Contract Loading, Validation, and Canonicalization

### Files

- `contracts/loader.py`
- `contracts/validation.py`
- `contracts/canonical.py`

### Loader requirements

- YAML and JSON;
- safe parsing;
- bounded file size;
- explicit path errors;
- no custom object constructors;
- UTF-8;
- clear unsupported-version error.

### Validation architecture

Separate:

```text
syntax/schema validation
        ↓
semantic validation
```

Return structured error objects.

Example:

```text
code: DUPLICATE_RULE_ID
path: tools.rules[3].rule_id
message: Rule id "email-send" is duplicated.
```

Avoid only returning long Pydantic exception strings to callers.

### Canonical serialization

Requirements:

- stable key ordering;
- stable enum serialization;
- stable set ordering;
- omit fields consistently;
- UTF-8 JSON form suitable for hashing;
- no timestamps inserted during normalization.

### Hash

Expose:

```text
document_hash(contract) -> sha256:<hex>
effective_policy_hash(contract) -> sha256:<hex>
```

Tests must prove ordering-only differences do not alter either hash and cosmetic-only metadata does not alter the effective policy hash.

### Acceptance criteria

- valid YAML and JSON with same semantics hash identically;
- semantically relevant modifications alter hash;
- malformed YAML does not execute arbitrary constructors;
- structured errors include machine-readable code + field path.

---

## 16. Workstream 0J — Security Event Model v0.1

### Goal

Create the evidence language shared by evaluation and runtime.

### Files

- `src/agentsec/domain/events.py`
- `docs/evidence-model.md`

### Event envelope

Required fields:

```text
schema_version
event_id
event_type
occurred_at
run_id
trace_id
sequence
actor?
subject?
payload
labels[]
```

### Typed payloads

Create typed payloads for at least:

### `RunStartedPayload`
### `RunFinishedPayload`
### `ToolRequestedPayload`
### `PolicyEvaluatedPayload`
### `ApprovalRequestedPayload`
### `ApprovalDecidedPayload`
### `ToolDispatchedPayload`
### `ToolReturnedPayload`
### `SecuritySignalPayload`
### `RunTerminatedPayload`

`EffectVerifiedPayload` may be defined even if unused.

### Event semantics

Document clearly:

```text
TOOL_REQUESTED
!= POLICY_EVALUATED
!= TOOL_DISPATCHED
!= TOOL_RETURNED
!= EFFECT_VERIFIED
```

### Ordering

`sequence` is monotonic within a run.

Do not claim global distributed ordering.

### Content minimization

Payloads should be usable without raw prompts or secrets.

Where content references are needed, prefer:

```text
artifact_id
content_hash
redacted_summary
```

### Acceptance criteria

- sample full run event fixture validates;
- ordering validator catches duplicate/decreasing sequence;
- event types use typed payloads;
- evidence model documents what each event proves and does not prove.

---

## 17. Workstream 0K — Scenario Schema v0.1

### Goal

Define the input Phase 1 will execute.

### Files

- `src/agentsec/domain/scenarios.py`
- `docs/scenario-format.md`
- `examples/scenarios/`

### Top-level fields

```text
schema_version
scenario_id
title
description?
attack_family
tags[]
setup
task
injections[]
assertions[]
utility_assertions[]
```

### Setup

Phase 0 representation should support static fixtures:

```text
tools
data artifacts
mock responses
canaries
initial memory?
```

Do not implement setup execution.

### Task

```text
task_id
user_input
task_scope?
```

Raw user input is appropriate in a scenario artifact, unlike a canonical policy request.

### Injection

Represent:

```text
source
location
content or fixture_ref
trust_class
labels[]
```

Examples:

- malicious email content;
- tool response;
- web page;
- memory entry.

### Assertions

Define an extensible discriminated union.

Initial assertion types:

```text
TOOL_NOT_CALLED
TOOL_CALLED
CAPABILITY_NOT_REQUESTED
OUTPUT_NOT_CONTAINS_CANARY
APPROVAL_REQUIRED
MAX_TOOL_CALLS
RUN_TERMINATED_REASON
NO_FINDING_CATEGORY
FINDING_CATEGORY_PRESENT
```

Not all need executors until Phase 1.

### Utility assertions

Separate from security assertions.

Initial forms can be placeholders such as:

```text
EXPECTED_TOOL_CALLED
OUTPUT_CONTAINS
```

The distinction is architectural:

> A defense must be measured for both security and legitimate utility.

### Acceptance criteria

- valid indirect-injection example;
- valid exfiltration example;
- valid runaway-loop/budget example;
- invalid unknown assertion type rejected;
- schema supports deterministic evaluation without requiring an LLM judge.

---

## 18. Workstream 0L — Findings Model

### Goal

Create a stable result format for Phase 1 and runtime detections.

### File

`src/agentsec/domain/findings.py`

### Models

#### `Finding`

Fields:

```text
finding_id
category
severity
title
description
run_id?
scenario_id?
event_refs[]
artifact_refs[]
expected?
observed?
remediation_hint?
```

### Severity

Use explicit ordered enum:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Do not use floating-point severity scores yet.

### Finding vs signal

Document:

```text
SecuritySignal = observed indicator
Finding        = interpreted security result
Incident       = investigation/case derived from findings/events
```

### Acceptance criteria

- model supports eval and runtime provenance;
- no finding requires raw prompt storage;
- tests cover severity ordering/serialization.

---

## 19. Workstream 0M — Evidence and Policy Ports

### Goal

Provide only interfaces needed to preserve dependency direction.

### Files

- `src/agentsec/evidence/ports.py`
- `src/agentsec/policy/ports.py`

### Event sink

```python
class EventSink(Protocol):
    def append(self, event: SecurityEvent) -> None: ...
```

An async form can be chosen if the scaffold establishes async throughout. Do not provide both without need.

### Policy engine

As above:

```python
class PolicyEngine(Protocol):
    def decide(...) -> PolicyDecision:
        ...
```

### No unnecessary abstractions

Do not add:

- repository interfaces for every model;
- message buses;
- service locator;
- dependency injection framework.

### Acceptance criteria

- ports contain domain interfaces only;
- implementations can be replaced without changing domain types;
- no database/network dependency in the core.

---

## 20. Workstream 0N — JSON Schema Export

### Goal

Make schemas inspectable and consumable outside Python.

### File

`contracts/schema_export.py`

### Export at least

```text
agent-security-contract.schema.json
scenario.schema.json
security-event.schema.json
policy-request.schema.json
policy-decision.schema.json
```

### Requirements

- deterministic generated output;
- schema includes descriptions where practical;
- checked-in generated schemas are either:
  - committed and verified not stale; or
  - generated in CI and artifacted.

Recommended for an OSS developer tool: commit them and test regeneration produces no diff.

### Acceptance criteria

- `agentsec schema export` succeeds;
- CI stale-schema test passes;
- schemas validate repository examples independently where practical.

---

## 21. Workstream 0O — CLI Skeleton

### Goal

Provide real Phase 0 usability without pretending later features exist.

### File

`src/agentsec/cli/main.py`

### Commands

#### `agentsec version`

Outputs package version.

#### `agentsec contract validate <path>`

Output on success:

```text
VALID
contract_id: ...
schema_version: 0.1
document_hash: sha256:...
effective_policy_hash: sha256:...
```

Output on failure should show structured validation errors.

Non-zero exit code on failure.

#### `agentsec scenario validate <path>`

Same principle.

#### `agentsec schema export --out <dir>`

Exports schemas.

#### `agentsec examples validate`

Validates all checked-in public examples and fails if any are stale/invalid.

### Explicitly do not expose

```text
agentsec eval
agentsec protect
agentsec replay
```

until implemented in later phases.

### Acceptance criteria

- CLI has deterministic exit codes;
- output is usable by humans;
- errors do not dump unnecessary stack traces by default;
- optional verbose/debug flag may expose diagnostics.

---

## 22. Workstream 0P — Example Contracts and Scenarios

### Goal

Use examples as executable design tests.

### Example contract 1 — Read-only research agent

Capabilities:

- web.search: allow;
- web.fetch: allow;
- filesystem.write: deny;
- email.send: deny.

Purpose:
- simplest least-privilege contract.

### Example contract 2 — Support agent with approval

Capabilities:

- ticket.read: allow;
- ticket.update: allow;
- email.send: require approval;
- secrets.read: deny.

Purpose:
- demonstrate approval and external write.

### Example contract 3 — Coding agent

Capabilities:

- filesystem.read: allow;
- filesystem.write: approval or scoped allow;
- shell.execute: require approval;
- network.external: deny by default.

Purpose:
- demonstrate high-risk tools.

### Scenario 1 — Indirect prompt injection

Malicious email/web content asks agent to perform an unauthorized action.

Expected:

- unauthorized capability not requested or not allowed.

### Scenario 2 — Canary exfiltration

Fixture contains canary secret and malicious instruction.

Expected:

- canary absent from external sink/output.

### Scenario 3 — Resource exhaustion

Agent/tool fixture loops or repeatedly requests a capability.

Expected:

- future budget assertion representation is valid.

Phase 0 validates representation only.

### Acceptance criteria

- examples validate in CI;
- examples appear in docs;
- examples avoid real secrets;
- at least one invalid fixture exists for each important validation rule.

---

## 23. Workstream 0Q — Validation Error Model

### Goal

Make schema errors usable by CLI, CI, and future APIs.

### Create error codes

Examples:

```text
INVALID_SCHEMA
UNSUPPORTED_SCHEMA_VERSION
UNKNOWN_FIELD
INVALID_IDENTIFIER
DUPLICATE_RULE_ID
CONTRADICTORY_RULE
INVALID_BUDGET
INVALID_TIMEOUT
INVALID_TIMESTAMP_RANGE
INVALID_CAPABILITY
INVALID_TOOL_SCHEMA
INVALID_EVENT_SEQUENCE
UNKNOWN_ASSERTION_TYPE
```

### Structured error

```text
ValidationIssue
- code
- message
- path?
- severity
- context?
```

Use a custom exception only as a transport for one or more structured issues.

### Acceptance criteria

- CLI renders issues cleanly;
- tests assert codes, not full human prose;
- API-ready representation can serialize to JSON later.

---

## 24. Workstream 0R — Canonicalization and Hashing Test Matrix

### Required tests

### Contract ordering

Input A:

```yaml
budgets:
  max_tool_calls: 10
  max_runtime_seconds: 60
```

Input B with key order reversed.

Expected:
same canonical hash.

### Set ordering

Capabilities in different input order.

Expected:
same canonical hash if semantic set.

### Meaningful change

`max_tool_calls: 10` → `11`.

Expected:
different hash.

#### Description/cosmetic metadata change

Phase 0 must implement both named hashes rather than leaving the distinction unresolved:

```text
document_hash
effective_policy_hash
```

Required semantics:

- `document_hash` covers the complete canonical authored document except unstable/generated fields;
- `effective_policy_hash` covers only normalized security-relevant semantics;
- changing only human description text changes `document_hash` but not `effective_policy_hash`;
- changing a rule, budget, principal binding, data rule, or other security semantic changes `effective_policy_hash`.

Never expose an ambiguous generic `hash` or `contract_hash` in the public API.

### Tool schema hash

JSON object key ordering difference:
same hash.

Actual type/rule change:
different hash.

---

## 25. Workstream 0S — Documentation

### `docs/security-contract.md`

Must include:

- purpose;
- full field reference;
- decision precedence;
- default-deny philosophy;
- examples;
- versioning;
- validation semantics;
- explicit v0.1 limitations.

### `docs/scenario-format.md`

Must include:

- scenario anatomy;
- attacks vs assertions;
- security vs utility assertions;
- deterministic-first scoring philosophy;
- examples.

### `docs/evidence-model.md`

Must include:

- event lifecycle;
- what each event proves;
- content-minimization strategy;
- event ordering;
- event vs finding vs incident.

### `docs/taxonomy.md`

Must include all stable categories and definitions.

### `docs/threat-model.md`

As defined earlier.

### Acceptance criteria

- no docs duplicate contradictory field definitions;
- canonical schema/code remains source of truth;
- docs link to generated JSON Schemas;
- examples are copied from or tested against actual fixture files where practical.

---

## 26. Workstream 0T — Testing Strategy

### 26.1 Unit tests

Cover:

- every domain validator;
- enum serialization;
- timestamp validation;
- identifier validation;
- budget validation;
- tool hash functions;
- contract semantic validation;
- scenario validation;
- event payload discriminators;
- approval digest binding.

### 26.2 Golden tests

Store representative canonical JSON.

Verify changes are intentional.

Golden tests for:

- contract;
- tool descriptor;
- security event;
- scenario.

### 26.3 Round-trip tests

```text
YAML
 ↓
model
 ↓
JSON
 ↓
model
```

Must preserve semantics.

### 26.4 Property-based tests

Use Hypothesis only for areas where it materially improves confidence.

Good candidates:

- canonical map ordering;
- set ordering;
- hash stability;
- bounded identifiers;
- timestamp ordering.

Do not use property tests merely for coverage numbers.

### 26.5 Negative tests

Especially important.

Test:

- unknown field typo;
- invalid schema version;
- duplicate rule IDs;
- negative budget;
- contradictory duplicate capability rule;
- invalid enum;
- malformed JSON Schema object;
- invalid event payload for event type;
- decreasing event sequence;
- invalid approval expiry;
- unsafe YAML constructor attempt.

### 26.6 Network isolation

Default tests should fail if they accidentally attempt external network access, if practical in the chosen test setup.

At minimum, no test should require network.

---

## 27. Workstream 0U — Static Quality and Security Checks

Add CI checks appropriate to the scaffold:

```text
format/lint
type check
unit tests
schema regeneration check
example validation
package build
```

Optional:

- dependency vulnerability scanner;
- secret scanner;
- license check.

Do not let tooling expansion overwhelm Phase 0.

### Type quality

Public domain models and ports should be fully typed.

Avoid pervasive `Any`.

### Error handling

No bare `except Exception: pass`.

Security parsing errors must be explicit.

---

## 28. Suggested Implementation Order

The implementation should proceed in this order because later tasks depend on earlier semantic decisions.

### Step 1 — terminology + taxonomies

Implement:

- `taxonomy.py`;
- `docs/taxonomy.md`.

Freeze names before schemas spread them.

### Step 2 — base domain primitives

Implement:

- identifiers/base utilities;
- principal;
- agent identity;
- delegation;
- tool/capability;
- provenance primitives.

### Step 3 — policy + approval models

Implement:

- policy request;
- policy decision;
- reason codes;
- approval binding;
- policy port.

### Step 4 — contract schema

Implement:

- v0.1 models;
- YAML/JSON loader;
- semantic validation.

### Step 5 — canonicalization/hashing

Implement before examples proliferate.

### Step 6 — event model + evidence doc

Ensure event semantics can represent both Phase 1 and Phase 2.

### Step 7 — scenario + finding schemas

Create the evaluation-side artifacts using the already-defined domain language.

### Step 8 — CLI/schema export

Expose completed functionality.

### Step 9 — fixtures and broad negative tests

Use examples to pressure-test the design.

### Step 10 — threat model/docs cleanup

The threat model begins earlier but should be reconciled against the final v0.1 schemas.

### Step 11 — implementation report

Document:

- deviations;
- unresolved questions;
- schema decisions;
- follow-up work for Phase 1.

---

## 29. Detailed Acceptance Test Matrix

| Area | Valid case | Invalid case | Required outcome |
|---|---|---|---|
| Contract | read-only agent | unknown top-level key | reject with `UNKNOWN_FIELD` |
| Contract | approval rule | duplicate rule ID | reject |
| Budget | positive tool limit | negative limit | reject |
| Tool | JSON schema | non-serializable schema | reject |
| Tool hash | reordered keys | changed schema type | same / different hash respectively |
| Delegation | expiry > issued | expiry <= issued | reject invalid |
| Policy decision | deny with reason | unknown outcome | reject |
| Approval | digest bound | modified action | digest differs |
| Event | typed payload | wrong payload for type | reject |
| Event stream | monotonic sequence | decreasing/duplicate | reject |
| Scenario | known assertion | unknown assertion | reject |
| YAML | normal safe doc | object constructor tag | reject safely |
| Version | 0.1 | unsupported major | explicit unsupported error |
| Canonicalization | reordered sets/maps | security value change | stable / changed hash |

---

## 30. Security-Specific Negative Design Tests

These tests verify the architecture does not accidentally encode unsafe assumptions.

### 30.1 Prompt text cannot become policy

There should be no API like:

```python
PolicyEngine.decide(prompt: str)
```

The policy engine accepts structured `PolicyRequest`.

### 30.2 Tool description is not tool identity

Changing tool description does not create a new `tool_id`, but changes security-relevant metadata hash.

### 30.3 User request does not implicitly grant global authority

`TaskScope` and `Delegation` exist separately from `Principal`.

### 30.4 Approval is not authorization for arbitrary future calls

Approval binds to action digest and request.

### 30.5 Allowed does not imply executed

Event types make this impossible to conflate structurally.

### 30.6 Event storage does not require raw secrets

All baseline fixtures prove evidence can reference hashes/artifacts instead.

---

## 31. Decisions Phase 0 Should Make

Phase 0 should finish with explicit answers to:

1. Exact canonical identifier syntax.
2. Whether models are immutable/frozen by default.
3. YAML library.
4. CLI library.
5. Type checker.
6. Schema version representation.
7. Document hash vs effective policy hash semantics.
8. Event payload discriminated-union representation.
9. Sync vs async interface for `EventSink`.
10. Where semantic validation lives relative to Pydantic model validators.

Capture meaningful choices in ADRs only if the scaffold includes an ADR process.

---

## 32. Decisions Phase 0 Should NOT Make Yet

Defer:

1. Cedar vs OPA final choice.
2. MCP transport implementation.
3. Human approval UX.
4. SQL schema.
5. hosted tenancy model;
6. multi-agent wire protocol;
7. formal taint lattice;
8. replay storage format;
9. policy UI;
10. LLM attack generator;
11. model-evaluator provider;
12. enterprise SIEM integration.

Any Phase 0 implementation that forces these choices should be treated skeptically.

---

## 33. Implementation Guardrails

### No speculative microservices

Everything is an importable Python package/CLI in Phase 0.

### No generic “utils.py” dumping ground

Put helpers with the domain they serve.

### No unstructured `dict[str, Any]` as the main model

Use typed models; allow bounded JSON values only where extensibility requires it.

### No silent coercion for security-sensitive values

Prefer strict integer/bool/enum validation.

Example:

```text
"false"
```

should not silently become boolean false in security policy unless explicitly intended.

### No hidden network calls

Contract/scenario validation is pure/local.

### No model dependency

Phase 0 must run without model API keys.

### No policy execution masquerading as validation

Semantic validation can detect structural contradictions, but it should not pretend to prove runtime security.

---

## 34. Phase 0 Implementation Report Template

At completion create:

`docs/reports/phase-0-implementation-report.md`

Required sections:

```text
# Phase 0 Implementation Report

## Summary
## Commit / branch
## Implemented deliverables
## Repository structure
## Domain model decisions
## Contract v0.1 decisions
## Scenario v0.1 decisions
## Event/evidence model decisions
## Validation and canonicalization
## CLI commands
## Tests and results
## Deviations from plan
## Security assumptions
## Known limitations
## Open questions
## Recommended Phase 1 changes
```

The report should distinguish:

- plan completed as designed;
- intentional deviation;
- deferred item;
- newly discovered risk.

---

## 35. Definition of Done Checklist

### Domain

- [ ] taxonomy enums implemented
- [ ] principal/agent/delegation implemented
- [ ] tool/capability implemented
- [ ] provenance primitive implemented
- [ ] policy request/decision implemented
- [ ] approval models implemented
- [ ] event model implemented
- [ ] scenario model implemented
- [ ] finding model implemented

### Contracts

- [ ] contract v0.1 implemented
- [ ] YAML loader implemented safely
- [ ] JSON loader implemented
- [ ] strict unknown-field behavior
- [ ] semantic validation
- [ ] canonical representation
- [ ] deterministic hash
- [ ] JSON Schema generation

### CLI

- [ ] version
- [ ] contract validate
- [ ] scenario validate
- [ ] schema export
- [ ] examples validate

### Fixtures

- [ ] 3 valid contracts
- [ ] 3 valid scenarios
- [ ] representative event stream
- [ ] invalid contract fixture set
- [ ] invalid scenario fixture set
- [ ] unsafe YAML fixture
- [ ] golden canonical forms

### Documentation

- [ ] architecture
- [ ] threat model
- [ ] evidence model
- [ ] security contract format
- [ ] scenario format
- [ ] taxonomy
- [ ] implementation report

### Quality

- [ ] unit tests pass
- [ ] type checker passes
- [ ] lint/format passes
- [ ] examples validate in CI
- [ ] generated schemas are current
- [ ] no test requires network/API keys
- [ ] no Phase 1/2 feature is falsely exposed as complete

---

## 36. Phase 1 Readiness Gate

Do not begin Phase 1 simply because the checklist is mechanically complete.

Before moving on, review these questions:

### Contract quality

Can a developer express the intended permissions of the example agents without awkward workarounds?

### Event quality

Can the event schema represent:

```text
requested → denied
requested → approval → dispatched → returned
```

without ambiguity?

### Scenario quality

Can a deterministic test express:

```text
malicious external content must not lead to email.send
```

without framework-specific fields?

### Extensibility

Could an MCP adapter and a Python-function adapter both produce the same `PolicyRequest`?

### Evidence discipline

Can a finding point to exact event evidence without storing raw sensitive content?

### Policy/eval convergence

Can the same capability IDs and tool descriptors appear naturally in both the contract and scenario?

If any answer is no, fix the Phase 0 domain model before building the evaluation engine.

---

## 37. Expected Phase 1 Handoff

Phase 0 should hand Phase 1:

```text
Canonical domain types
        +
Security Contract v0.1
        +
Scenario v0.1
        +
Evidence Event v0.1
        +
Validation / canonicalization
        +
Example vulnerable environments expressed as fixtures
```

Phase 1 can then focus narrowly on execution:

```text
load scenario
→ construct test environment
→ run target
→ capture events
→ execute assertions
→ produce findings/report
```

It should not need to redesign what an event, capability, finding, tool, or contract means.

---

## 38. Summary

Phase 0 is deliberately foundation-heavy because this project's long-term differentiation depends on semantic unification.

The biggest architectural failure would be to independently build:

```text
an eval DSL
an MCP policy file
an observability schema
an incident format
```

and discover later that they describe security in incompatible ways.

Phase 0 prevents that by establishing one shared language for:

- identity;
- authority;
- tools;
- tasks;
- data;
- policy;
- evidence;
- attacks;
- findings.

The phase should remain small in runtime capability but unusually rigorous in semantics.

When complete, the project will not yet “secure an agent.”

It will have something more important for the next stages:

> **a coherent, validated, testable definition of what securing an agent means.**
