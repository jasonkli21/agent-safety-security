# Agent Safety & Security Platform — Architecture

**Document:** `docs/architecture.md`  
**Status:** Phased architecture baseline
**Scope:** Long-term architecture with implementation guidance through Phase 7; last reviewed 2026-10-16
**Primary implementation language:** Python 3.12+ initially  
**Primary deployment model:** Local-first / self-hosted; optional managed control plane later  
**Initial runtime integration:** MCP  
**Architecture style:** Modular monolith / library-first core with explicit ports and adapters

---

## 1. Purpose

This document translates the Agent Safety & Security Platform PRD into a durable technical architecture.

The architecture must support a narrow near-term implementation without constraining the broader product vision. In particular, it must enable a single security model to power:

1. pre-deployment adversarial evaluation;
2. runtime authorization and enforcement;
3. identity and delegated authority;
4. data-flow and provenance controls;
5. evidence, replay, and incident reconstruction;
6. continuous regression testing;
7. multi-agent security and hosted fleet management later.

The central architectural requirement is:

> **Evaluation and runtime enforcement must consume the same canonical security contract, policy semantics, evidence model, and domain types.**

The platform should not evolve into separate “eval” and “gateway” products with duplicated policy logic.

The architecture also assumes that basic least-privilege authorization, approvals, audit, identity, and isolation already exist in adjacent open-source projects. Project B should not couple its long-term value to reimplementing those primitives. Its architectural moat is the **shared lifecycle**: contracts that feed evaluation and runtime, attack derivation from authority/data topology, evidence/provenance, incident-to-regression, and delegated multi-agent authority.

---

## 2. Architectural Thesis

The platform is built around five distinct responsibilities:

```text
DEFINE       what authority and invariants should hold
COMPILE      those definitions into executable policy and test obligations
ENFORCE      decisions at trusted action boundaries
OBSERVE      what was requested, decided, executed, and returned
VERIFY       behavior through evaluation, replay, and regression
```

The long-term closed loop is:

```text
┌─────────────────────────────┐
│ Agent Security Contract     │
│ identity + authority + data │
│ invariants + budgets        │
└──────────────┬──────────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
  Eval Compiler   Policy Compiler
        │             │
        ▼             ▼
   Scenarios       Decisions
        │             │
        ▼             ▼
     Agent ─────► Enforcement Boundary
        │             │
        └──────┬──────┘
               ▼
      Evidence + Provenance
               │
               ▼
       Incident / Analysis
          ┌────┴────┐
          ▼         ▼
      Policy      Regression
      change        case
          └────┬────┘
               ▼
      Continuous verification
```

This loop is the product architecture, not merely a workflow.

---

## 3. Design Principles

### 3.1 The model proposes; the security boundary decides

Prompts, system messages, model refusals, and behavioral guardrails are not authorization boundaries.

A model may request:

```text
email.send(...)
```

but a deterministic or independently controlled policy decision point determines whether the request may execute.

### 3.2 Security policy lives outside protected agent context

The protected agent must not be able to rewrite:

- its own permissions;
- approval requirements;
- trusted tool identities;
- policy code;
- security contract;
- trust labels.

The agent may produce recommendations, but recommendations are untrusted input until explicitly accepted.

### 3.3 One canonical domain model

The same types should be used by:

- CLI validation;
- evaluation;
- runtime gateway;
- replay;
- reporting;
- hosted control plane.

Avoid separate policy schemas for evaluation and runtime.

### 3.4 Deterministic controls before probabilistic controls

Priority order:

1. exact policy;
2. schemas;
3. resource scopes;
4. argument validation;
5. data labels / provenance;
6. static detectors;
7. heuristic classifiers;
8. LLM judgment.

Probabilistic detectors add signal. They do not silently grant authority.

### 3.5 Evidence must distinguish intent from effect

The platform must not collapse:

```text
requested
allowed
approved
dispatched
returned
effect observed
```

into a generic “tool call.”

### 3.6 Protocol independence

MCP is the first runtime adapter, not the architectural center.

The protected boundary is:

> **untrusted or probabilistic intent → privileged side effect**

### 3.7 Local-first by default

A useful installation should work with:

- Python;
- SQLite;
- local files;
- optional Docker;
- zero paid APIs.

Managed services may be layered on later.

### 3.8 Fail closed when enforcement is promised

If the platform is operating as an active enforcement point and cannot produce a trustworthy authorization decision, the default outcome is deny.

Shadow/audit modes may explicitly behave differently.

### 3.9 Version all security-relevant inputs

At minimum:

- contract schema version;
- contract instance version;
- tool schema hash;
- tool description hash;
- scenario schema version;
- event schema version;
- evaluator version;
- adapter version;
- model/provider/version where relevant.

### 3.10 Prefer composition over reimplementation

Integrate established components where they fit:

- OpenTelemetry for telemetry;
- Cedar or OPA later for policy backends;
- existing sandbox runtimes;
- existing red-team/eval frameworks;
- OAuth/OIDC/workload identity.

The platform’s value is in the shared security lifecycle and domain model.

---

## 4. System Context

### 4.1 Actors

#### Developer
Defines contracts, runs local evaluation, configures runtime protection, and reviews findings.

#### Security engineer
Reviews policies, incidents, attack coverage, exceptions, and posture.

#### End user
Delegates a task to an agent and may approve sensitive actions.

#### Agent
Produces intents and invokes tools. Treated as potentially incorrect, manipulated, or compromised.

#### Tool / MCP server / API
Executes privileged actions or provides data. May be trusted, untrusted, buggy, or compromised.

#### Identity provider
Optional external authority for users/services/workloads.

#### CI system
Runs deterministic policy and security regressions.

#### Managed control plane
Future centralized management plane; never required for core local enforcement.

---

## 5. Trust Boundaries

The system must make trust explicit.

```text
┌──────────────── User / Developer Trust Domain ────────────────┐
│ Contract authoring                                             │
│ Policy review                                                  │
└──────────────────────────┬─────────────────────────────────────┘
                           │ trusted configuration
                           ▼
┌──────────────── Security Platform Trust Domain ────────────────┐
│ Contract parser / compiler                                     │
│ Policy decision point                                          │
│ Approval broker                                                │
│ Evidence recorder                                              │
└───────────────┬────────────────────────────┬────────────────────┘
                │                            │
        privileged request              evidence
                │                            │
                ▼                            ▼
┌──────── Agent / Model ────────┐      ┌──────── Storage ────────┐
│ probabilistic / untrusted     │      │ security-sensitive      │
└───────────────┬───────────────┘      └──────────────────────────┘
                │ tool intent
                ▼
┌──────── External Tools / Content / MCP ────────────────────────┐
│ may be compromised, adversarial, mutable, or malicious         │
└────────────────────────────────────────────────────────────────┘
```

Important assumptions:

- agent output is untrusted;
- external content is untrusted unless explicitly classified otherwise;
- tool descriptions can change;
- tool responses can contain instruction-like malicious content;
- protected security state is not writable by the agent;
- local developer ownership does not imply all local MCP servers are trusted.

---

## 6. Core Domain Model

The core domain package should be dependency-light and reusable everywhere.

### 6.1 Principal

Represents an identity capable of requesting or delegating authority.

```text
Principal
- principal_id
- principal_type: user | agent | service
- attributes
- authentication_context?   # later
```

A principal is identity, not permission.

### 6.2 AgentIdentity

Describes the protected agent instance or logical agent.

```text
AgentIdentity
- agent_id
- name
- framework?
- model_provider?
- model_name?
- owner_principal?
- environment
- trust_level
```

Runtime model/provider fields are contextual and should not define authorization by themselves.

### 6.3 Delegation

Represents authority transferred from one principal to another.

```text
Delegation
- delegation_id
- delegator
- delegate
- task_scope
- capability_scope
- issued_at
- expires_at?
- parent_delegation_id?
```

Long-term invariant:

```text
effective child authority ⊆ parent delegated authority
```

The contract model defines these relationships. Current runtime enforcement is limited to the
direct Phase 6 authority semantics described below; broader delegation graphs remain future scope.

### 6.4 ToolDescriptor

Canonical tool metadata.

```text
ToolDescriptor
- tool_id
- namespace
- name
- protocol
- server_id?
- input_schema
- output_schema?
- description
- description_hash
- schema_hash
- side_effect_class
- risk_class
- data_access_classes[]
- idempotency
- destructive
- version?
```

The descriptor must distinguish identity from mutable metadata.

### 6.5 Capability

Represents an action an agent may request.

Examples:

```text
calendar.read
calendar.create
email.send
filesystem.read
shell.execute
```

Capabilities should support:

- exact match;
- namespacing;
- resource constraints;
- argument constraints later.

### 6.6 TaskScope

Represents what the user actually delegated for the current task.

Example:

```text
goal: summarize travel itinerary
allowed resources:
- travel email label
- read-only calendar range

forbidden outcomes:
- sending messages
- modifying bookings
```

Phase 0 defines a minimal representation. Dynamic task-scope inference is explicitly deferred.

### 6.7 DataLabel

Security labels attached to data artifacts.

Initial labels should be simple and explicit:

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

Do not encode an overly elaborate lattice in Phase 0.

### 6.8 DataArtifact

Represents data with provenance and labels.

```text
DataArtifact
- artifact_id
- origin
- labels[]
- content_hash?
- parent_artifact_ids[]
- created_at
```

Raw content does not need to be stored in every event.

### 6.9 AgentSecurityContract

The canonical policy intent.

Major sections:

```text
metadata
agent
identity
task_scope
tools
data
budgets
approvals
invariants
environment
```

The contract is declarative and versioned.

It should state intent, not framework-specific runtime mechanics.

### 6.10 PolicyRequest

Input to authorization.

Long-term shape:

```text
PolicyRequest
- principal
- agent
- delegation
- task
- action
- resource
- arguments_summary
- data_labels
- provenance
- trajectory_context
- environment
```

Not every field is populated in Phase 0.

### 6.11 PolicyDecision

Canonical output:

```text
PolicyDecision
- decision_id
- request_id
- outcome:
    allow | deny | require_approval | error
- matched_rules[]
- reason_codes[]
- human_readable_reason
- contract_version
- decided_at
```

A decision must always be explainable from deterministic reason codes where possible.

### 6.12 ApprovalRequest / ApprovalDecision

Approval is modeled explicitly rather than as a boolean on a policy decision.

```text
ApprovalRequest
- approval_id
- policy_request
- immutable_action_summary
- reason
- expires_at?

ApprovalDecision
- approval_id
- approver
- decision: approve | deny
- decided_at
- scope
```

### 6.13 SecurityEvent

Append-only factual record of security-relevant activity.

Examples:

```text
RUN_STARTED
MODEL_INVOCATION
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

Events record facts, not mutable aggregate state.

### 6.14 Scenario

A reproducible security test specification.

```text
Scenario
- scenario_id
- title
- attack_family
- setup
- task
- injected_inputs
- expected_assertions
- scorers
- required_capabilities
- tags
```

### 6.15 Finding

An evaluation or runtime security observation.

```text
Finding
- finding_id
- severity
- category
- evidence_refs[]
- expected
- observed
- remediation_hint?
```

### 6.16 Incident

A security investigation object derived from events/findings.

No Incident type is defined in Phase 0. Define it in a later phase when incident-response
workflows and their required evidence relationships are designed.

### 6.17 ReplayBundle

Long-term portable bundle containing enough information to reproduce a trace.

No ReplayBundle type is defined in Phase 0. Design the bundle alongside a later replay
implementation, after its evidence and reproducibility requirements are established.

---

## 7. Canonical Risk Taxonomy

Risk classifications should be shared by eval and runtime.

### 7.1 Action side-effect class

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

### 7.2 Trust class

```text
TRUSTED_CONFIG
USER_INPUT
UNTRUSTED_EXTERNAL
TOOL_OUTPUT
MODEL_OUTPUT
GENERATED_POLICY_SUGGESTION
```

### 7.3 Security finding families

Initial canonical categories:

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

Taxonomies must be enums or stable identifiers, not free-form strings sprinkled through the codebase.

---

## 8. Architectural Layers

The initial codebase should be structured around dependency direction.

```text
           ┌──────────────────────┐
           │ CLI / API / Adapters │
           └──────────┬───────────┘
                      ▼
           ┌──────────────────────┐
           │ Application Services │
           └──────────┬───────────┘
                      ▼
        ┌────────────────────────────┐
        │ Core Domain + Contracts    │
        │ Events + Policy Semantics  │
        └─────────────┬──────────────┘
                      ▼
           ┌──────────────────────┐
           │ Ports / Interfaces   │
           └──────────┬───────────┘
                      ▼
      ┌────────────────────────────────┐
      │ SQLite / files / MCP / OTel    │
      │ model providers / policy backends
      └────────────────────────────────┘
```

Dependency rule:

> Core domain modules must not import framework, database, MCP, HTTP, or model-provider code.

---

## 9. Major Components

### 9.1 Contract Loader

Responsibilities:

- parse YAML/JSON;
- schema validation;
- semantic validation;
- normalization;
- version checks;
- canonical serialization;
- document/effective-policy hashing.

Phase 0: implement.

### 9.2 Contract Compiler

Long-term responsibilities:

- compile declarative contract into policy rules;
- derive test obligations;
- create normalized effective policy.

Phase 0: no separate compiler interface; loading and normalization use the contract validator.

Phase 3: substantial implementation.

### 9.3 Policy Decision Point (PDP)

Responsibilities:

- accept `PolicyRequest`;
- evaluate deterministic rules;
- return `PolicyDecision`;
- never execute tools.

Phase 0: define port and stub test implementation.

Phase 2: implement initial runtime rules.

### 9.4 Policy Enforcement Point (PEP)

Responsibilities:

- intercept privileged action;
- build `PolicyRequest`;
- consult PDP;
- request approval when required;
- dispatch only after authorization;
- record evidence.

Adapters implement PEP behavior for MCP/functions/etc.

Phase 2 onward.

### 9.5 Evaluation Engine

Responsibilities:

- load scenarios;
- prepare fixtures;
- invoke target agent;
- observe trajectory;
- evaluate assertions;
- generate findings and metrics.

Phase 1.

### 9.6 Scenario Compiler / Generator

Responsibilities:

- compile scenario DSL;
- derive security tests from contracts;
- generate attack hypotheses from capability/data topology.

Manual scenario execution begins in Phase 1.

Contract-derived generation becomes central in Phase 3+.

### 9.7 Tool Registry

Responsibilities:

- tool identity;
- schema/version hashes;
- risk metadata;
- trust state;
- later supply-chain changes.

Phase 0: domain model + in-memory/file fixtures.

Phase 2: discovery from MCP.

### 9.8 Approval Broker

Responsibilities:

- present immutable action summary;
- collect approval;
- bind approval to exact request/scope;
- enforce expiry.

Phase 2 local terminal implementation.

Future: UI/team approval integrations.

### 9.9 Provenance Engine

Responsibilities:

- create data artifacts;
- propagate labels;
- maintain parent-child relationships;
- answer source/sink questions.

Phase 4.

Phase 0 only defines minimal data types.

### 9.10 Evidence Recorder

Responsibilities:

- assign trace/run IDs;
- append structured events;
- maintain event ordering;
- redact sensitive payloads according to configuration;
- persist evidence.

Phase 0: interfaces + JSONL writer may be included if useful for schema tests.

Phase 1: required.

### 9.11 Replay Engine

Responsibilities:

- package trace dependencies;
- substitute deterministic/mock tools;
- re-execute scenario;
- compare behavior;
- promote incident to regression.

Phase 5.

### 9.12 Observability Exporter

Responsibilities:

- map canonical events to OpenTelemetry spans/events;
- preserve internal event semantics;
- avoid making OTel the domain model itself.

Phase 1+.

### 9.13 CLI

Long-term:

```bash
agentsec init
agentsec contract validate
agentsec schema export
agentsec eval
agentsec protect
agentsec replay
agentsec incident promote
agentsec policy test
```

Phase 0 should expose only commands backed by actual functionality.

Recommended Phase 0 subset:

```bash
agentsec version
agentsec contract validate <path>
agentsec scenario validate <path>
agentsec schema export
agentsec examples validate
```

---

## 10. Policy Architecture

### 10.1 Policy semantics

The long-term decision must evaluate more than tool name.

Conceptually:

```text
decision = f(
    principal,
    delegated_authority,
    task_scope,
    action,
    resource,
    arguments,
    data_labels,
    provenance,
    trajectory,
    environment,
    budgets
)
```

### 10.2 Decision precedence

Initial semantic rule:

```text
explicit deny
    >
required approval
    >
explicit allow
    >
default deny
```

Any future backend must preserve equivalent externally observable semantics.

### 10.3 Default deny

Unknown tools/capabilities are denied in enforcement mode unless a contract explicitly opts into a different policy.

### 10.4 Policy backend abstraction

Define a port such as:

```python
class PolicyEngine(Protocol):
    def decide(self, request: PolicyRequest, contract: CompiledSecurityPlan) -> PolicyDecision: ...
```

Initial implementation may be native Python predicates.

The native engine consumes the immutable compiled representation in Phase 3. A raw-contract
compatibility helper compiles before evaluation. Later backends may target Cedar or OPA/Rego.

The domain model must not expose backend-specific ASTs.

### 10.5 LLM-assisted policy

Allowed:

- suggest policy;
- explain finding;
- classify ambiguous content;
- propose tighter least privilege.

Forbidden as sole authority:

- granting destructive access;
- widening production permissions;
- bypassing explicit deny;
- overriding approval requirement.

---

## 11. Contract Architecture

### 11.1 Authoring format

YAML should be the primary human-authored format; JSON should be supported through the same schema.

### 11.2 Schema authority

Pydantic domain models are the implementation source of truth in the Python phase.

Export JSON Schema for:

- documentation;
- IDE validation;
- compatibility tests.

### 11.3 Versioning

Every top-level serialized artifact contains:

```yaml
schema_version: "0.1"
```

Use semantic rules:

- patch: clarification compatible with existing documents;
- minor: additive backward-compatible fields;
- major: incompatible representation or semantics.

Before 1.0, compatibility is best-effort but migrations should be explicit.

### 11.4 Unknown fields

Security-sensitive config should default to rejecting unknown fields.

Silent typo acceptance is dangerous.

#### 11.5 Canonicalization and identity

Contracts should have a deterministic normalized representation for hashing/diffing. Phase 0 should distinguish two concepts rather than overloading a generic “contract hash”:

- **document hash** — identity of the complete normalized authored document, including descriptive metadata that is intentionally part of the document;
- **effective policy hash** — identity of the normalized security-relevant semantics used by evaluation/runtime, excluding cosmetic metadata.

Neither hash should contain unstable generated fields such as load timestamps. Callers must name which hash they store or compare.

---

## 12. Evaluation Architecture

Phase 1 implements a local synchronous evaluation engine over the Phase 0 domain.
See [evaluation](evaluation.md) for the concrete target, coverage, causality and assertion semantics.

### 12.1 Evaluation run

```text
Scenario
  ↓
Fixture setup
  ↓
Target agent
  ↓
Observed events/actions
  ↓
Assertions
  ↓
Findings + utility result
```

### 12.2 Deterministic assertions first

Examples:

```text
tool_not_called
tool_called
argument_matches
destination_allowed
canary_not_leaked
approval_required
run_terminated_reason
max_tool_calls
artifact_not_written
```

LLM-as-judge should be optional.

### 12.3 Security and utility paired

Every defense evaluation should eventually record:

- security outcome;
- legitimate task outcome.

This avoids rewarding systems that simply block everything.

### 12.4 Target abstraction

The eval engine should target an interface, not one framework.

```python
class AgentTarget(Protocol):
    def run(
        self, *, contract: AgentSecurityContract, scenario: Scenario, context: EvaluationContext
    ) -> EvaluationObservation: ...
```

Phase 1 uses a deterministic scripted fixture target and no production PolicyEngine.
The context injects clocks/IDs and an in-memory event recorder. Reports combine separate
security and utility statuses using ERROR > FAIL > INCONCLUSIVE > PASS. Missing capture is
explicit; evaluation-specific causality validation does not expand the Phase 0 sequence validator.
Complete tool arguments and text surfaces remain ephemeral; JSONL stores canonical events.

---

## 13. Runtime Enforcement Architecture

Phase 2 implements this boundary. See [runtime MCP](runtime-mcp.md) for exact supported
semantics, coverage refusal, discovery snapshots, approval/budget state ownership, response
validation, modes and failure behavior. The SDK remains confined to `adapters/mcp`; policy and
runtime use canonical domain models. Dispatch evidence includes an explicit enforcement mode
so shadow forwarding retains its true decision. Phase 1 evaluation rejects non-enforcing
trajectories; it does not infer authorization from shadow dispatch.


### 13.1 Request flow

```text
Agent
  ↓ intent
Adapter / PEP
  ↓
Normalize ToolRequest
  ↓
Build PolicyRequest
  ↓
Policy Decision Point
  ↓
allow / deny / approval / error
  ↓
Approval Broker if required
  ↓
Dispatch
  ↓
Tool Response
  ↓
Response Guard
  ↓
Agent
```

All transitions emit canonical events.

### 13.2 MCP adapter

Initial runtime target because MCP provides:

- tool discovery;
- structured schemas;
- clear interception point;
- real ecosystem utility.

The adapter must translate MCP-native messages into canonical domain types and back.

MCP-specific fields should not leak into the policy core.

### 13.3 Enforcement modes

```text
ENFORCE
SHADOW
DISABLED
```

`ENFORCE` denies on policy-system failure.

`SHADOW` records the decision that would have occurred but does not block.

`DISABLED` is explicit and should never masquerade as protection.

---

## 14. Evidence Architecture

### 14.1 Canonical event envelope

Every event should include:

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
security_labels?
```

### 14.2 Payload discipline

Avoid unbounded arbitrary dictionaries for all domain events.

Prefer typed payloads for stable event types.

### 14.3 Sensitive data

Event payloads should support:

- hash only;
- metadata only;
- redacted value;
- encrypted full value later;
- local-only full content.

Default early behavior should minimize raw sensitive content.

### 14.4 Storage

Phase 0/1:

- JSONL for append-only raw event streams;
- SQLite for indexed metadata if needed;
- fixtures in repository for tests.

Later:

- PostgreSQL;
- object storage / Parquet;
- external OTel backends.

### 14.5 OpenTelemetry mapping

OpenTelemetry is an export format/integration, not the canonical internal schema.

Maintain a mapping layer:

```text
SecurityEvent → OTel span/event attributes
```

This prevents external semantic-convention churn from destabilizing core domain types.

---

## 15. Persistence Architecture

### 15.1 Repository pattern only where necessary

Avoid abstracting every data access operation prematurely.

Create explicit ports for durable concepts:

- contract repository;
- event sink;
- tool registry;
- incident repository later.

### 15.2 Phase 0 persistence

Required:

- filesystem contract/scenario loading;
- JSON Schema export;
- test fixtures.

Optional but reasonable:

- JSONL event sink for round-trip validation.

SQLite should not be added merely because it appears in the long-term PRD unless Phase 0 needs it.

### 15.3 Managed architecture later

```text
Customer / local data plane
       │
       ├── local PDP / PEP
       ├── local sensitive traces
       │
       └── optional metadata sync
                    │
                    ▼
         Managed control plane
```

The hosted plane should not become a mandatory synchronous dependency for local authorization.

---

## 16. Deployment Architecture

### 16.1 Local developer mode

```text
Laptop
├── CLI
├── contracts
├── eval engine
├── MCP gateway
├── JSONL / SQLite
└── optional local OTel collector
```

Zero cloud required.

### 16.2 CI mode

```text
GitHub Actions / other CI
├── contract validation
├── scenario validation
├── security regression suite
├── policy tests
└── artifacts / machine-readable report
```

### 16.3 Self-hosted production mode

Later:

```text
Agent workload
   ↓
local/sidecar enforcement adapter
   ↓
tools

Policy bundle + local decision engine
Evidence → customer-controlled storage / SIEM
```

### 16.4 Managed mode

Future control-plane responsibilities:

- orgs;
- central policies;
- policy review;
- agent registry;
- posture;
- alerts;
- fleet analytics;
- retention;
- SSO.

Runtime enforcement should remain deployable customer-side.

---

## 17. Security Architecture of the Platform Itself

### 17.1 Protected state

Contracts, policy bundles, trust roots, and approval records are security-critical.

The agent must not have ordinary write permissions to them.

### 17.2 Integrity

Long-term:

- signed contract bundles;
- signed tool metadata;
- append-only/tamper-evident audit chains;
- content hashes.

Phase 0:

- deterministic hashes;
- immutable Pydantic models where practical;
- strict parsing.

### 17.3 Injection containment

Never concatenate untrusted tool content into policy expressions.

Policy evaluation operates on structured fields.

### 17.4 Parser hardening

- bounded input sizes;
- safe YAML loading;
- reject unknown fields;
- clear schema versions;
- no arbitrary object deserialization.

### 17.5 Secrets

Core tests must use canaries, not real credentials.

Do not require secrets for default test suite.

### 17.6 Failure behavior

Define explicit errors:

```text
INVALID_CONTRACT
UNKNOWN_SCHEMA_VERSION
POLICY_ENGINE_FAILURE
APPROVAL_TIMEOUT
TOOL_SCHEMA_MISMATCH
EVIDENCE_WRITE_FAILURE
```

Security-relevant failure modes should not collapse into generic exceptions.

---

## 18. Reliability and Performance

### 18.1 Runtime latency goal

No hard SLA is required in Phase 0.

Long-term inline authorization should be designed for a deterministic fast path that is small compared with model inference latency.

Avoid network calls for simple policy checks.

### 18.2 Backpressure

Evidence logging must not silently drop critical authorization events.

Future runtime modes should explicitly choose among:

- synchronous durable security events;
- bounded buffered export;
- fail-closed on critical evidence failure;
- best-effort observability for noncritical details.

### 18.3 Availability

Hosted control plane outages must not remove the ability to evaluate cached/local policy.

### 18.4 Determinism

Given:

```text
same contract version
same policy request
same deterministic backend version
```

the policy decision should be reproducible.

---

## 19. Extensibility

### 19.1 Ports and adapters

Create stable interfaces for:

- policy engine;
- event sink;
- agent target;
- tool dispatcher;
- approval provider;
- detector;
- model client;
- identity provider later.

### 19.2 Plugin discipline

Do not build a dynamic third-party plugin framework in Phase 0.

Internal adapter registration is enough.

A public plugin API should come only after extension points are proven.

### 19.3 Detector architecture

Detectors should return signals:

```text
SecuritySignal
- signal_type
- confidence?
- severity
- evidence
```

A detector does not itself decide authority unless a contract explicitly maps the signal to policy.

---

## 20. Proposed Package Boundaries

Recommended initial Python layout:

```text
src/agentsec/
├── __init__.py
├── cli/
│   └── main.py
├── contracts/
│   ├── models.py
│   ├── loader.py
│   ├── validation.py
│   ├── canonical.py
│   └── schema_export.py
├── domain/
│   ├── identity.py
│   ├── tools.py
│   ├── policy.py
│   ├── events.py
│   ├── scenarios.py
│   ├── findings.py
│   ├── provenance.py
│   └── taxonomy.py
├── policy/
│   ├── ports.py
│   └── native.py        # later phase
├── eval/
│   ├── ports.py
│   └── engine.py        # Phase 1
├── runtime/
│   ├── ports.py
│   └── gateway.py       # Phase 2
├── evidence/
│   ├── ports.py
│   └── jsonl.py
└── adapters/
    └── mcp/             # Phase 2
```

Tests mirror package boundaries.

Avoid creating empty directories for every future phase unless they communicate a real interface already required by Phase 0.

---

## 21. Technology Choices

### Python

Use Python initially for:

- ecosystem reach;
- fast schema iteration;
- Pydantic;
- async support;
- MCP/eval/provider integrations.

Do not rewrite in Rust/Go preemptively.

Candidate future high-performance components:

- inline proxy;
- content scanners;
- high-volume evidence processing.

### Pydantic

Use for:

- strict domain/config models;
- validation;
- JSON Schema export;
- serialization.

Use strict configuration and reject unknown fields in security-sensitive artifacts.

### Typer or Click

Either is acceptable for the CLI.

Prefer the smaller dependency/complexity choice once scaffolding is created.

### YAML

Use a safe parser.

Canonical in-memory types remain independent of YAML.

### Testing

Recommended:

- `pytest`;
- property-based testing with Hypothesis for schema invariants if justified;
- golden fixtures for canonical serialization;
- static typing via mypy or pyright;
- Ruff for lint/format.

---

## 22. Phase Mapping

### Phase 0
Implement:

- canonical domain types;
- contract schema;
- scenario schema;
- event schema;
- taxonomies;
- validation;
- canonicalization/hashing;
- CLI validation;
- fixtures;
- architecture/threat/evidence docs.

Do not implement:

- real agent evaluation;
- MCP gateway;
- production policy engine;
- provenance propagation;
- identity federation.

### Phase 1
Add:

- local eval engine;
- deterministic target/tool fixtures;
- assertions;
- attack scenarios;
- JSONL evidence;
- reports;
- CI exit codes.

### Phase 2
Add:

- MCP adapter;
- native policy engine v1;
- enforcement modes;
- approvals;
- budgets;
- audit.

### Phase 3
Add:

- actual contract compiler;
- policy-derived tests;
- policy coverage;
- test/runtime semantic equivalence checks.

### Phase 4+
Add:

- data flow;
- replay;
- delegated identity;
- more adapters;
- supply-chain security;
- multi-agent support;
- managed control plane.

---

## 23. Architecture Invariants

These should become explicit tests where possible.

1. **Core domain imports no MCP/provider/database framework.**
2. **Unknown contract fields are rejected.**
3. **Unknown schema versions are rejected explicitly.**
4. **Canonical serialization is deterministic.**
5. **Equivalent normalized contracts produce the same document/effective-policy hashes according to their documented semantics.**
6. **Policy decisions contain machine-readable reason codes.**
7. **Runtime authorization cannot be delegated to an LLM-only decision.**
8. **Agent code cannot mutate protected policy state through normal interfaces.**
9. **Tool identity is distinct from mutable description/schema metadata.**
10. **Security events distinguish requested, allowed, dispatched, and completed states.**
11. **Scenario assertions do not require LLM grading when deterministic evidence exists.**
12. **MCP-specific types never become canonical policy types.**
13. **All serialized security artifacts carry a schema version.**
14. **Sensitive raw content is not required in canonical event metadata.**
15. **Future child-agent authority cannot exceed delegated parent authority.**

---

## 24. Architecture Decision Records to Create Later

Recommended ADRs as implementation choices become concrete:

- ADR-001: Python as initial implementation language
- ADR-002: Pydantic as schema source of truth
- ADR-003: Native policy engine first vs Cedar/OPA immediately
- ADR-004: Canonical event model vs direct OTel domain model
- ADR-005: YAML authoring + JSON Schema
- ADR-006: Event storage format for Phase 1
- ADR-007: MCP proxy topology
- ADR-008: Approval binding semantics
- ADR-009: Document hash vs effective policy hash semantics
- ADR-010: Hosted control plane boundary

Phase 0 should create ADRs only for decisions actually made, not speculative placeholders.

---

## 25. Open Questions

The architecture intentionally leaves the following unresolved:

1. Native policy engine vs Cedar vs OPA as the first production backend.
2. Exact task-scope language.
3. Fine-grained resource selectors.
4. Formal data-label lattice.
5. How provenance propagates through free-form model generation.
6. Replay fidelity requirements.
7. How approval grants can safely cover multiple related actions.
8. Whether contract-derived attack generation is rule-based, graph-based, or hybrid.
9. Which event payloads map cleanly to OTel GenAI conventions.
10. How to represent remote multi-agent delegation cryptographically.

These should be answered through phases rather than baked prematurely into Phase 0.

---

## 26. Quality Bar

This platform sits on a security boundary. Its engineering process should reflect that.

Required from the beginning:

- strict typing where practical;
- deterministic tests;
- explicit error types;
- no broad silent exception handling;
- documented trust assumptions;
- negative tests for malformed security configuration;
- dependency minimization;
- secure defaults;
- reviewable fixtures;
- reproducible validation;
- no hidden network requirement in core tests.

The platform should prefer a smaller number of well-specified primitives over a broad but ambiguous feature set.

---

## 27. Near-Term Architectural Milestone

The architecture is successful through Phase 0 when the repository can answer, without executing a real agent:

1. What is an agent?
2. What is a principal?
3. What is a tool?
4. What is a capability?
5. What authority was delegated?
6. What is the security contract?
7. What is a policy request?
8. What outcomes can a policy decision produce?
9. What is a security event?
10. How is a test scenario represented?
11. How are security findings classified?
12. How are all of those artifacts versioned and validated?

If those answers are coherent, Phase 1 can build evaluation and Phase 2 can build runtime enforcement on the same foundation.

If they are ambiguous, implementation should not proceed simply to create more code.

---

## 28. Summary

The architecture is intentionally centered on a **shared security domain model** rather than on MCP, a model provider, or a particular agent framework.

The long-term platform consists of four interlocking planes:

```text
Definition Plane
    contracts / identity / tools / policy intent

Verification Plane
    scenarios / attacks / eval / replay / regressions

Enforcement Plane
    PDP / PEP / approvals / runtime adapters

Evidence Plane
    events / provenance / findings / incidents / telemetry
```

Phase 0 establishes the language those planes share.

Phases 1–3 prove the central thesis:

> **The same explicit security contract can define expected behavior, generate tests, and constrain real agent actions.**

That thesis should remain the architectural anchor as the project expands.

## Phase 3 executable contract path

`compiler.compile_contract` freezes the supported exact-match intent and records unsupported
semantic atoms with source paths and digests. Native policy consumes this representation;
MCP startup compiles once and reuses it for decisions and adapter coverage. A supplied startup
plan must equal a fresh compilation of the protected contract, including identity and policy hash.
The compiled scope uses tuples/frozen sets, never a mutable resource map. Runtime counters and
approval redemption remain separate. No MCP types enter the compiler.

Generated obligations use a small independent declarative precedence oracle, then execute the
native evaluator. A conformance target reuses Phase 1 canonical evidence emission with decisions
from that evaluator, and existing trajectory/assertion checks remain authoritative. Finite policy
diff uses the shared evaluator over the union of exact capability/resource partitions. This is
bounded comparison, not general formal equivalence. See [contract conformance](contract-conformance.md).

Compiled executable identity excludes agent display/model metadata and task prose, matching the
effective-policy projection. Runtime protected requests/actions derive from that plan. Executed
conformance/coverage and adapter proof bind to exact compiler/plan content identity, distinct from
the authored effective policy hash; discovery proof also binds to its metadata/binding snapshot.
Generated conformance checks exact reasons and matching-rule provenance. Grouped identity/scope
atoms remain NOT_RUN without discriminating generated obligations; semantic diff includes
explanation changes independently of authority rank.


## Phase 4 tracked provenance boundary

The immutable `phase4-v1` plan includes exact data rules. Native policy applies them only after
ordinary ALLOW/REQUIRE_APPROVAL, preserving every ordinary deny/error. Protocol-independent
provenance state holds content-free immutable nodes and a concurrency-safe exposure frontier.
Requests snapshot the frontier; response artifacts inherit that snapshot's labels monotonically.
TOOL_RETURNED is distinct from DATA_EXPOSED: guarded release records critical exposure evidence
before atomically committing the frontier and returning. Rejected responses never taint context.
MCP bindings explicitly classify output labels and static opaque sink destinations; their exact
configuration remains bound by discovery proof. Approvals bind destination and canonical artifact
context. No semantic byte matching, label lattice, declassification, initial user/model context
tracking or model-internal provenance is claimed. See [provenance/data flow](provenance-data-flow.md)
for normative composition, concurrency, exposure and coverage limits. Replay/incident workflows
are described in the Phase 5 section below; no persistence or new protocol dependency enters the provenance core.

## Phase 5 offline security lifecycle

Replay validates a canonical JSON bundle and reuses native compiled policy, runtime approval/
budget ledgers, and protocol-independent provenance over an ordered content-free event program.
It has no live dispatch port. Source/current plan identities, replay identity, fidelity/blockers
and source-versus-replay semantic facts remain distinct. Runtime start evidence additively binds
its exact plan; older producers stay explicitly legacy and expose no recorded source identity.
Historical approval reuse requires exact source-plan binding. Promotion preserves original commitments
and explicit safe assertions in minimized derived regression material, optionally capturing a
separately supplied candidate plan. It never modifies policy. See [replay/incidents](replay-incidents.md).


## Phase 6 restrictive identity authority

Current `phase6-v1` compilation makes OBO executable; historical `phase4-v1` plans retain
original serialization, identity and semantics. A protocol-independent provider port returns
minimized VerifiedCredential facts. Protected static configuration is explicit local trust;
the optional PyJWT adapter verifies pinned asymmetric proofs and explicit subject/scope mappings.
AuthorityContext freezes the direct grant and credential ceiling independently of authored policy.
The shared pure authority layer intersects task/resource restrictions and checks activation,
identity and freshness; native policy, conformance and offline replay reuse it. Runtime owns an
immutable authority snapshot and rechecks expiry immediately before dispatch after approval.
Normalized actions and policy-input evidence bind its computed digest. Resource-bearing grant
facts are explicitly redacted; replay needs trusted matching context or remains incomplete.
No bearer credential, identity federation service or transitive graph belongs in the domain.
See [identity and delegation](identity-delegation.md).


## Phase 7 protected adapter routes and isolation composition

`ProtectedCall` snapshots typed tool metadata, exact extraction/display and data classifications,
checks shared compiled-plan coverage, and enters RuntimeGateway before private adapter dispatch.
Native Python, strict provider JSON shapes, optional LangChain StructuredTool, fixed-endpoint HTTP
and structured process execution share policy/identity/approval/budget/provenance/evidence behavior.
MCP reuses generic schema/argument/coverage checks while retaining discovery/transport/proof logic.
ExecutionBinding is operational identity, never an authored grant: additive normalized-action and
dispatch fields bind adapter route, protected configuration and isolation to exact approvals.
Absent fields preserve historical serialization/digests; compiler and authored policy hashes stay
unchanged. Offline replay substitutes safe route facts without importing/executing adapters.

For resource-scoped Phase 7 HTTP/process routes, an extracted argument value alone does not prove
the physical effect target. ENFORCE coverage requires a protected fixed `trusted_effect_resource`;
an extracted value, when configured, must equal it before the gateway. This remains a reviewed
operator assertion about the downstream service or executable, not semantic attestation. Candidate
route fidelity is a separate replay result from policy/evidence trace diff and is `UNKNOWN` without
a protected candidate route manifest. Adapter-level pure validation runs before approval, budget
commitment and dispatch evidence. Approval presentation redacts resources unless explicitly opted
in. LangChain callbacks and tracing remain external effects and require their own egress controls.

Process isolation is a separate protected port. Explicit host execution or a concrete Docker backend
with secure defaults is selected by trusted wiring. Docker runtime selection composes with runsc;
no sandbox runtime is implemented, and containment failure never falls back to host in any mode.
Cancellation after dispatcher entry remains potentially effectful/unknown. This extends operational
surfaces only: direct Phase 6 authority and Phase 0–6 semantics remain protected. See
[adapters/isolation](adapters-isolation.md). Phase 8 now adds restrictive supply-chain admission as described below; Phase 9 graphs remain deferred.

## Phase 8 restrictive supply-chain admission

Operator-owned TrustLock pins and independently provisioned Ed25519 public keys restrict
candidate implementations without changing authored contract semantics or `phase6-v1`. Immutable,
content-free qualified inventories bind exact observed metadata, routes and classifications, with
explicit missing artifact/dependency proof. RuntimeGateway checks admission before approval and
rechecks the action-bound lock/epoch/signature/local-byte snapshot synchronously at the final
budget/dispatch boundary. Protected registration and MCP visibility also check admission.
Provider/framework rebinding needs an independently pinned route; it cannot remove the guard.

Local file hashing proves inspected bytes only. Remote code, loaded Python functions, executable
hash-and-exec, Docker tags/images/daemon and actual sandbox behavior are unproven; runtime
attestation requirements reject as unsupported. Declared dependency manifests are not complete
resolved SBOMs. Trust root protection remains an operator deployment responsibility, as with
contracts. ENFORCE restricts, SHADOW reports and DISABLED skips trust while retaining transport/
isolation safety. Same-event-loop ownership prevents cross-thread lock replacement races; it
cannot constrain malicious trusted application code or privileged filesystem replacement.

Optional request/dispatch assessment and snapshot fields are omitted on legacy paths. Approvals
bind exact trust generation, and offline replay compares candidate observations separately from
route fidelity without re-verifying signatures or accessing files/tools. Historical hashes and
serialized omissions remain intact. See [supply-chain trust](supply-chain-trust.md). Independent
Phase 7 acceptance remains unconfirmed, and Phase 8 needs independent review before release.

For MCP, process/endpoint contact and initialization precede tool discovery. Trust-enabled
ENFORCE stdio therefore requires an explicit operator-managed launch boundary before the SDK can
spawn the executable. This is a deployment prerequisite, not an agentsec executable attestation;
without an external OS control the operator must not launch an untrusted server. Required tool
presence is a separate optional lock assertion and does not broaden the pin set. Live trust
discovery is cumulatively bounded, subject to the SDK decoding one page before agentsec can count
its size. See [MCP runtime](runtime-mcp.md) and [supply-chain trust](supply-chain-trust.md).


## Phase 9 protected local graph sessions

`phase9-v1` is an opt-in compiler identity; default `phase6-v1` and historical `phase4-v1`
remain unchanged. Immutable canonical graph commitments bind exact independent participant
plans and verified credentials. `MultiAgentSession` owns enrollment, permanent retirement,
monotonic replacement generations and one hierarchical budget coordinator. Every enrolled
RuntimeGateway call intersects all path grants, credentials and compiled tool/task/data
ceilings through a common pure evaluator, and combines approvals into one exact-action broker
step. No standalone policy request can authenticate a graph by supplying its digest.

One thread/event loop owns the session; complete-path reservation/commit and final epoch/
freshness checks are synchronous. Unique receipts compensate only pre-entry failures. The
gateway checks again after critical dispatch evidence to catch reentrant graph revocation.
Fixed adjacent message routes enter the sender gateway and import labels monotonically only
after critical receiver evidence, before releasing text. Foreign lineage is referenced, never
registered as locally verified ancestry. Protected Python wiring is not an in-process sandbox.

Minimal GRAPH_EVENT lifecycle/message facts extend canonical evidence without content/grants.
Offline graph replay reuses pure policy/ledger/provenance over one recorded epoch with explicit
missing-material blockers and separate candidate graph comparison. Replay enforces one run per
participant, permanent retirement, live ancestry at message release, per-run monotonic event time,
and request/approval/dispatch/return causality. Runtime revocation and generation replacement
release pending receipts on paths invalidated by the change while preserving committed effects.
Participant event wrappers bind to unique, stable run/trace identities; sinks may still be shared.
Historical incident promotion
keeps graph cases DRAFT; it does not export protected graph authority automatically. ENFORCE is
the only supported graph mode; unimplemented mode semantics fail setup. Phase 7 isolation and
Phase 8 trust remain restrictive and unchanged. New peer/plan enrollment, remote A2A, hosted
services and model/cost quotas are unsupported. See [multi-agent security](multi-agent-security.md).


## Phase 10 decision: optional team governance is outside runtime authority

`control_plane` owns a separate team-v1 identity, RBAC, revision and minimized-report namespace.
Only explicit operator bootstrap/configuration pins external Ed25519 issuer keys and provisions
subjects. Team principals never become Phase 6 credentials, delegation grants, trust pins or
Phase 9 session participants. SQLite governance transactions and HTTP ingress are isolated from
core domain/runtime code. Publication is immutable configuration history with independent review
and compare-and-set; it never changes a running gateway or graph. Existing startup compilation,
approvals, restrictive trust and graph ownership remain authoritative with zero team availability.
Central metadata is a new allowlist projection, never a full SecurityEvent upload, and remains
REPORTED_UNVERIFIED. See [managed control-plane design](managed-control-plane.md) for finite role,
state, API, storage, outage and minimization contracts. This loopback single-instance reference
adds no hosted SaaS, public proxy/TLS deployment or independent Phase 7–10 acceptance.

Expensive governance assessment uses an authenticated immutable snapshot outside SQLite's shared
write transaction, then rechecks source, workflow version, actor permissions and publication
generation before compare-and-set commit. Restored databases and existing WAL/SHM sidecars are
admitted only after POSIX owner, regular-file and private-mode checks. Advisory posture separately
reports policy alignment and effect-evidence dimensions; reporter declarations never attest loaded
policy or verified effects.


## Phase 11 decision: offline enterprise observations do not become authority

The optional enterprise package composes existing team authorization and scoped SQLite records
without changing the schema version or core domain types. Offline domain-separated Ed25519
signatures bind independently pinned peer/purpose/scope. Federation verifies and recompiles before
recipient-owned immutable DRAFT import; replay high water survives key rotation. Recipient review
and publication remain separate, with no activation path into RuntimeGateway. Case/risk CAS
transitions are metadata-only governance, and risk dispositions never alter policy/CI/posture.
Finite fleet simulation snapshots publication/inventory, assesses outside the global write lock
and rechecks authorization and snapshot. UNKNOWN/UNCLASSIFIED states preserve missing evidence.
Tenant audit projections produce bounded offline SIEM pages; signatures bind exact output bytes,
while reporter claims retain REPORTED_UNVERIFIED assurance. Private signing keys never enter
SQLite/HTTP. See [enterprise security](enterprise-security.md). This is a single-node loopback/offline
reference, not public hosting, runtime attestation, remote authority, HA or a commercial SLA.
