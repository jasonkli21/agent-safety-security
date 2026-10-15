# Agent Safety & Security Platform — Product Requirements Document

**Status:** Long-term product vision and phased roadmap  
**Last reviewed:** 2026-10-15  
**Working repository name:** `agent-safety-security`  
**Working Python package / CLI namespace:** `agentsec`  
**Primary deployment model:** Local-first / self-hosted, with an optional managed control plane later  
**Initial runtime integration:** MCP, without making MCP the platform boundary

---

## 1. Executive Summary

AI agents are moving from generating text to taking privileged actions: reading private data, invoking APIs, executing code, sending messages, modifying infrastructure, persisting memory, and delegating work to other agents. The security problem is therefore larger than “is the model safe?” It increasingly becomes:

- What authority does this agent actually have?
- What authority was delegated for this specific task?
- What data may it read, transform, persist, or transmit?
- What happens when untrusted content tries to manipulate it?
- Can high-risk actions be stopped independently of model compliance?
- Can we prove what was requested, allowed, approved, dispatched, returned, and actually observed?
- Can a real incident automatically become a future regression test?
- Can evaluation, runtime enforcement, identity, provenance, and incident response share one security model instead of drifting apart?

Project B is a **local-first, harness-agnostic security lifecycle for AI agents**. Its long-term scope combines:

1. pre-deployment adversarial evaluation and red teaming;
2. runtime action authorization and policy enforcement;
3. agent identity, task-scoped authority, and delegation;
4. data-flow, sensitivity, and exfiltration controls;
5. human approval for high-risk actions;
6. structured evidence, provenance, and incident reconstruction;
7. replay and regression testing from real traces;
8. CI/CD security gates and posture measurement;
9. supply-chain inspection for tools, MCP servers, skills, and agent dependencies;
10. multi-agent trust and delegation controls;
11. an optional managed team/enterprise control plane.

The project is **not** differentiated by claiming that prompt-injection testing, tool authorization, MCP gateways, agent identity, or audit are individually new. Current open-source projects already implement meaningful parts of those areas. The product thesis is instead the closed security loop:

> **Specify intended authority and invariants once → derive tests and attack hypotheses from that specification → enforce the same semantics at runtime → capture evidence → replay failures → promote incidents to regressions → continuously tighten security without silently expanding authority.**

The bold end state is an **agent security operating layer** rather than another guardrail library or MCP proxy.

---

## 2. Product Thesis

### 2.1 The model proposes; the security boundary decides

Prompts are not authorization. Model refusals are not authorization. A model can request an action, but a separately controlled security boundary must determine whether the action is permissible.

At the same time, authorization alone is insufficient. A system can have apparently reasonable policies and still behave unsafely because of indirect prompt injection, tool chains, data exfiltration, mutable tool metadata, memory poisoning, excessive agency, or delegation mistakes.

The platform therefore separates:

- **intent generation** — models and agents;
- **security specification** — contracts controlled outside agent context;
- **runtime enforcement** — trusted action boundaries;
- **evaluation** — deliberate adversarial testing;
- **evidence** — structured records of decisions and outcomes;
- **learning** — converting observed failures into tests and policy improvements.

### 2.2 Positioning

Short form:

> **Test agents before deployment, constrain them while they run, and learn from every trace afterward.**

Technical form:

> **A protocol-independent policy, verification, and evidence plane for agent actions and data flows.**

### 2.3 Why now

The 2026 ecosystem increasingly treats agent security as infrastructure rather than prompt hygiene:

- OWASP’s Top 10 for Agentic Applications covers goal hijacking, tool misuse, identity/privilege abuse, supply-chain issues, memory/context poisoning, cascading failures, and human-agent trust risks.
- NIST/NCCoE is actively exploring software and AI agent identity and authorization, including identification, authorization, auditing, non-repudiation, and prompt-injection mitigation.
- OpenTelemetry is standardizing GenAI/agent/tool telemetry.
- Open-source projects are independently converging on agent evaluation, MCP scanning, runtime authorization, identity, approvals, isolation, and audit.

This convergence validates the category while making broad integration—not a single detector—the more compelling opportunity.

---

## 3. Problem Definition

### 3.1 Agent security is fragmented across lifecycle stages

A typical stack may use one tool for red teaming, another for MCP scanning, a custom policy file for runtime, a generic tracing product for observability, and manual incident review afterward.

```text
Security intent
    ↓
red-team configuration      runtime policy      trace schema
    ↓                            ↓                   ↓
separate system              separate system      separate system
    \___________________________|___________________/
                                ↓
                         manual reconciliation
```

This creates predictable drift:

- red-team cases stop matching runtime policy;
- tool permissions become broader than task authority;
- docs describe rules the runtime does not enforce;
- exceptions silently outlive their purpose;
- incidents are not preserved as regression tests;
- tool identity is confused with mutable descriptions/schemas;
- agent identity inherits human credentials rather than delegated authority;
- data-flow policy is disconnected from action authorization.

### 3.2 Agent security is behavioral and sequential

Unsafe behavior often depends on trajectory, not one prompt or one call:

- a read-only agent follows an indirect injection and asks for an unrelated network tool;
- two individually permitted tools form an exfiltration path;
- untrusted content is persisted into durable memory;
- a tool changes its description after approval;
- a child agent receives more authority than intended;
- retry loops create cost or denial-of-service effects;
- a permitted external write becomes unsafe because secret-bearing data is present.

The platform must therefore reason about **identity, authority, task scope, sequences, provenance, data labels, mutable dependencies, and outcomes**.

---

## 4. Goals

### 4.1 Primary goals

The platform should eventually:

1. provide a single declarative security contract for agents, tools, data, approvals, budgets, and invariants;
2. evaluate agent systems adversarially before deployment;
3. enforce least privilege at runtime;
4. gate high-risk side effects independently of model compliance;
5. track provenance and sensitivity through agent trajectories;
6. establish meaningful agent identity and delegated authority;
7. record evidence sufficient for audit and incident reconstruction;
8. replay prior executions deterministically where practical;
9. convert incidents and suspicious traces into CI regressions;
10. derive attack hypotheses from the actual authority/data topology;
11. integrate with CI/CD and deployment gates;
12. remain useful across models, providers, frameworks, and protocols;
13. run meaningfully on a laptop and near-free cloud infrastructure;
14. preserve an open-source/local core while supporting a future profitable managed product.

### 4.2 Secondary goals

- make security decisions explainable to developers;
- provide safe defaults without requiring a security specialist for basic use;
- map evidence to OWASP/NIST/other standards where useful;
- support reproducible research on agent defenses;
- compare model/framework/security configurations under identical scenarios;
- quantify the marginal value and utility cost of defenses.

---

## 5. Non-Goals

Initially, the project is not intended to become:

- a foundation-model alignment or mechanistic-interpretability platform;
- a replacement for EDR, container isolation, or mature malware sandboxes;
- a full cloud IAM provider;
- a SIEM;
- a general API gateway;
- a secrets manager;
- a complete agent framework;
- a general-purpose LLM observability product;
- a bespoke implementation of every red-team, policy, telemetry, identity, or sandbox primitive.

Integration is preferred where mature components already exist.

---

## 6. Target Users

### 6.1 Initial users

**AI application developer** — wants local, understandable agent security without building a custom authorization/eval stack.

**MCP/tool developer** — wants to validate tool risk, permissions, and adversarial behavior before release.

**Security-minded indie/open-source developer** — wants strong defaults, CI integration, and zero mandatory hosted infrastructure.

### 6.2 Later users

**Application security engineer** — centralized policy, attack suites, deployment gates, incidents, and evidence.

**AI platform team** — multiple agents, shared security contracts, delegated identity, environment separation, fleet posture.

**Compliance/governance team** — reviewable policy history, approvals, evidence, retention, and control mappings.

**Security researcher** — reproducible environments, defense comparison, attack corpora, and trajectory analysis.

---

## 7. Core Abstraction: Agent Security Contract

The central artifact is an **Agent Security Contract**: a versioned declarative description of what an agent is expected and permitted to do.

Conceptually:

```yaml
agent: travel-assistant

identity:
  principal: agent:travel-assistant
  acts_on_behalf_of: user:local

tools:
  calendar.read: allow
  calendar.create: require_approval
  email.send: deny

data:
  credentials:
    external_destination: deny

budgets:
  max_tool_calls: 30
  max_external_writes: 3

invariants:
  - untrusted content must never grant authority
  - credentials must never reach an external sink
```

The exact syntax may evolve. The architectural requirement is that one contract can feed:

1. runtime authorization;
2. generated attack hypotheses;
3. generated negative tests;
4. approval tests;
5. trace interpretation;
6. incident classification;
7. posture/coverage reporting;
8. deployment gating.

The contract must describe security intent, not framework-specific mechanics.

---

## 8. Closed-Loop Security Lifecycle

```text
┌──────────────────────────────┐
│ Agent Security Contract      │
│ authority + data + invariants│
└──────────────┬───────────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
  Eval Compiler   Policy Compiler
        │             │
        ▼             ▼
   Adversarial      Runtime
     Tests         Enforcement
        │             │
        └──────┬──────┘
               ▼
      Evidence + Provenance
               │
               ▼
       Incident Analysis
          ┌────┴────┐
          ▼         ▼
  policy suggestion  regression case
          └────┬────┘
               ▼
      Continuous Verification
```

The feedback loop is the defining product feature.

---

## 9. Threat Model

### 9.1 Adversaries and failure sources

- malicious end user;
- malicious content author;
- compromised website/document/email;
- compromised MCP/tool server;
- malicious skill/plugin/dependency;
- compromised agent;
- over-permissioned benign agent;
- another agent in a multi-agent workflow;
- insider with security-state access;
- accidental operator misconfiguration.

### 9.2 Threat families

**Goal manipulation** — direct/indirect prompt injection, goal hijacking, instruction hierarchy confusion.

**Tool misuse** — unauthorized calls, dangerous arguments, confused deputy behavior, unsafe call sequences.

**Identity and privilege** — inherited human credentials, privilege escalation, impersonation, stale authority, delegation ambiguity.

**Data exfiltration** — secrets, PII, cross-tenant data, covert transfer through allowed fields, unsafe destinations.

**Context/memory poisoning** — untrusted content persisted as trusted memory, retrieval poisoning, policy-like content injection.

**Supply chain** — malicious MCP server, tool-description/schema change, skill/package compromise.

**Resource abuse** — infinite loops, retry storms, token/API cost runaway, recursive delegation.

**Unsafe side effects** — destructive writes, messages, financial actions, infrastructure changes, production deployments.

**Multi-agent trust failure** — authority laundering, transitive over-delegation, untrusted agent output treated as trusted instructions.

---

## 10. Open-Source Landscape and Positioning

**Landscape last reviewed:** 2026-10-15.

The project should explicitly learn from and integrate with existing work. It should not claim novelty for functionality already available elsewhere.

### 10.1 Evaluation / red-team projects

| Project | Strong overlap | What Project B must add beyond it |
|---|---|---|
| AgentDojo | prompt-injection attacks/defenses in tool-using agent environments | persistent runtime policy, identity, provenance, incident loop |
| Microsoft PyRIT | extensible GenAI red teaming and attack orchestration | production action-boundary enforcement and shared contract semantics |
| NVIDIA garak | broad model/system vulnerability probing | task-scoped action security and runtime evidence |
| Promptfoo | developer-friendly eval/red-team workflows and CI | shared runtime policy/identity/provenance model |
| Inspect AI | sophisticated evaluation framework with tool use | inline enforcement and incident/regression lifecycle |
| Agentic Security | offensive scanning/fuzzing | unified runtime, identity, evidence, and policy-derived test loop |

References:

- https://github.com/sequrity-ai/agentdojo
- https://github.com/microsoft/pyrit
- https://github.com/NVIDIA/garak
- https://github.com/promptfoo/promptfoo
- https://github.com/UKGovernmentBEIS/inspect_ai
- https://github.com/msoedov/agentic_security

### 10.2 Runtime / authorization / MCP projects

| Project | Strong overlap | Important distinction for Project B |
|---|---|---|
| Agent Guard | least-privilege authorization, human approval, audit, agent identity, optional isolation; harness-agnostic | Project B must not treat these as its novelty; differentiation centers on shared eval/runtime contract, attack derivation, provenance, incident-to-regression, and multi-agent authority |
| mcp-firewall | MCP/runtime policy enforcement, threat detection, audit | broader verification lifecycle and protocol-independent contract |
| MCP-Scan / Invariant lineage | MCP/tool scanning, poisoning/data-flow concepts | one lifecycle spanning specification, testing, enforcement, replay, identity |
| Secure MCP Gateway | auth/RBAC/tool filtering/audit/multi-tenancy | adversarial verification, data provenance, incident regression, cross-protocol model |
| MCP Agent Security Gateway | default-deny inspection, capability checks, audit, exfiltration controls | contract-derived verification and broader identity/delegation lifecycle |
| mcpwn | pre-deployment MCP vulnerability scanning | persistent runtime and continuous verification |

References:

- https://github.com/agent-rails/agent-guard
- https://github.com/ressl/mcp-firewall
- https://github.com/invariantlabs-ai/docs/blob/main/docs/mcp-scan/index.md
- https://github.com/datacline/secure-mcp-gateway
- https://github.com/poojakira/mcp-agent-security-gateway
- https://github.com/ressl/mcpwn

### 10.3 Guardrail / filtering projects

**NVIDIA NeMo Guardrails** and similar filtering frameworks overlap around input/output policy, dialog constraints, prompt-injection/PII/secret signals, and programmable guardrails.

Project B’s authorization philosophy is different:

> A classifier may signal “this looks like prompt injection,” but an agent should still be unable to execute an out-of-scope action even when the classifier misses it.

Detectors are signals; explicit authority remains the boundary.

References:

- https://github.com/NVIDIA-NeMo/Guardrails
- https://github.com/protectai/llm-guard (archived in 2026; useful architectural reference)

### 10.4 Standards / ecosystem references

- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- NIST/NCCoE Software and AI Agent Identity and Authorization: https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization
- NIST AI Agent Standards Initiative: https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative
- OpenTelemetry GenAI observability: https://opentelemetry.io/blog/2026/genai-observability/
- Cedar: https://cedarpolicy.com/

---

## 11. Differentiation

Project B should be judged against the strongest current projects, not a straw-man “simple MCP firewall.” Its durable differentiation should come from the following system-level capabilities.

### 11.1 One contract across evaluation and runtime

A rule such as:

```text
email.send = require approval
```

should become both:

- a runtime authorization rule;
- a generated test that attempts an unapproved send and expects a block.

The product should continuously verify that the **specification and enforcement agree**.

### 11.2 Policy-to-attack generation

Given tools, capabilities, resources, and data labels, derive plausible abuse paths.

```text
secret.read + email.send(external)
        ↓
possible exfiltration path
        ↓
generated adversarial scenario
```

Over time this can become graph-based attack-path analysis rather than a fixed prompt library.

### 11.3 Attack-to-policy feedback

When an attack succeeds, produce actionable policy options:

- narrower task scope;
- tighter tool/resource selector;
- data-flow rule;
- approval requirement;
- isolation requirement;
- trust downgrade.

Recommendations may use models. Production authority must never be silently expanded by an LLM.

### 11.4 Incident-to-regression

A real suspicious execution should be exportable into a reproducible security case and checked into CI.

```text
production trace
    ↓
replay bundle
    ↓
security/regressions/incident-123.yaml
    ↓
future deployment gate
```

This turns security operations into software regression engineering.

### 11.5 Data-flow-aware authorization

Long term, decisions should depend on:

```text
principal + delegation + task + action + resource + arguments
+ data labels + provenance + trajectory + environment
```

not just `tool_name`.

### 11.6 Task-scoped authority

The platform should distinguish:

> “This agent may ever call `calendar.write`”

from:

> “This user delegated only itinerary summarization for this task, therefore `calendar.write` is not in effective authority now.”

### 11.7 Multi-agent delegated authority

Long-term invariant:

```text
child effective authority
    ⊆ parent delegated authority
    ⊆ user grant
```

No agent can expand its own authority by delegating through another agent.

### 11.8 Protocol independence

MCP is the first adapter. The conceptual enforcement boundary is **agent intent → privileged action**.

Later adapters may include native function calling, Python dispatch, LangGraph/LangChain, HTTP, shell/coding-agent operations, and agent-to-agent calls.

### 11.9 Evidence-first security

The platform must distinguish:

```text
requested ≠ allowed ≠ approved ≠ dispatched ≠ returned ≠ effect verified
```

That distinction underpins audit, replay, incident response, and truthful security claims.

---

## 12. Product Pillars

### Pillar A — Security Specification

- agent registry;
- tool registry;
- capabilities/resources;
- security contracts;
- task scopes;
- data classes;
- approval rules;
- budgets;
- environment rules;
- sequence constraints.

### Pillar B — Evaluation & Red Teaming

- scenario DSL;
- deterministic attacks;
- mutation/fuzzing;
- model-generated attacks;
- attack chains;
- benchmark suites;
- scoring;
- defense comparison;
- reproducible manifests.

### Pillar C — Runtime Enforcement

- policy decision point;
- policy enforcement adapters;
- MCP gateway;
- native dispatch SDK;
- approvals;
- budgets/rate limits;
- egress controls;
- argument validation;
- response inspection;
- sequence-aware enforcement.

### Pillar D — Identity & Delegation

- agent principals;
- user-on-behalf-of relationship;
- task-scoped authority;
- short-lived credentials;
- capability tokens;
- delegated scopes;
- workload identity integration;
- trust tiers.

### Pillar E — Data Security & Provenance

- data labels;
- origin tracking;
- taint/provenance propagation;
- destination constraints;
- redaction;
- secret/PII detection;
- untrusted-content labeling;
- memory-write controls.

### Pillar F — Evidence, Forensics & Replay

- append-only event model;
- OpenTelemetry export;
- trace graph;
- policy decision record;
- approval record;
- replay bundle;
- deterministic mock tools;
- incident-to-regression workflow.

### Pillar G — Continuous Security

- CI integration;
- regression thresholds;
- policy diff tests;
- attack coverage;
- posture trends;
- deployment gates;
- scheduled red-team runs.

---

## 13. Functional Requirements

### 13.1 Security contracts

Contracts must be versioned, reviewable, diffable, testable, and reproducible. They should eventually express:

- identity;
- delegated task scope;
- capabilities/resources;
- allow/deny/approval;
- argument constraints;
- data-flow constraints;
- budgets;
- sequence rules;
- egress destinations;
- environment/trust requirements.

### 13.2 Tool registry

Each tool should eventually record:

```text
stable identity
provider/server
schema + schema hash
description + description hash
side-effect class
risk class
data access class
credential scope
destructiveness
idempotency
```

Tool identity must remain distinct from mutable metadata so “rug pull” changes can be detected.

### 13.3 Approval engine

Approval is a real execution branch. It must bind to an immutable normalized action, have explicit scope and expiry, and fail closed when required but unavailable.

### 13.4 Budgets

Per run/task/agent budgets may cover model calls, tool calls, destructive actions, external writes, runtime, cost, and delegated agents.

### 13.5 Request and response inspection

Requests may be checked for schema violations, unsafe arguments, destinations, sensitive data, security signals, budgets, and sequence violations.

Tool responses may be classified as trusted structured data, untrusted external content, secret-bearing data, or instruction-like content before re-entering model context.

### 13.6 Scenario DSL

Scenarios should support setup, injected content, task, deterministic assertions, utility assertions, and optional probabilistic scorers.

### 13.7 Generated scenarios

Contracts should eventually derive tests for denied tools, approval-required tools, sensitive source/sink pairs, destructive actions, scope escalation, resource exhaustion, and memory poisoning.

### 13.8 Scoring

Security metrics must be paired with legitimate-task utility. Key metrics include attack success, authorization bypass, secret exfiltration, approval bypass, excessive agency, false-positive blocking, task completion, policy coverage, and trace completeness.

---

## 14. High-Level Architecture

```text
                           ┌──────────────────────┐
                           │ Security Contracts   │
                           └──────────┬───────────┘
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
              Eval Compiler                     Policy Compiler
                     │                                 │
                     ▼                                 ▼
             Attack / Scenario                 Policy Decision Point
                  Engine                              │
                     │                                │
                     ▼                                ▼
               Agent Target ───────────────► Enforcement Adapter
                                                  │
                               ┌──────────────────┼──────────────────┐
                               ▼                  ▼                  ▼
                              MCP              Functions            HTTP
                               │                  │                  │
                               └──────────────────┼──────────────────┘
                                                  ▼
                                              Tools/APIs
                                                  │
                                                  ▼
                                           Response Guard

Every stage emits canonical evidence events and provenance references.
```

The detailed technical design lives in `docs/architecture.md`.

---

## 15. Local-First / Cost Strategy

Core security should not require expensive inference.

Preferred order:

1. deterministic policy;
2. schemas and static validation;
3. explicit resource/data labels;
4. rules and local signals;
5. lightweight local classifiers;
6. cached model decisions;
7. free/BYO API quotas;
8. paid frontier models only when they materially improve attack generation or semantic analysis.

A useful local installation should require only Python, local storage, and optional Docker. Cloud components should scale to zero where practical. If commercial usage creates meaningful event volume, profitability and positive unit economics become more important than maintaining a zero-dollar bill.

---

## 16. Phased Roadmap

### Phase 0 — Foundation, threat model, and canonical schemas

Define the shared security language before implementing runtime behavior:

- threat model;
- canonical taxonomies;
- Agent Security Contract v0.1;
- scenario schema v0.1;
- policy request/decision schema;
- approval model;
- event/evidence model;
- tool/capability model;
- provenance primitives;
- deterministic canonicalization/hashing;
- local validation CLI.

**Exit:** Phase 1 evaluation and Phase 2 enforcement can share the same domain model without redesign.

### Phase 1 — Local Agent Security Evaluation Lab

- scenario execution;
- deterministic fixtures/mock tools;
- attack catalog;
- transcript/event capture;
- assertions;
- findings/scoring;
- CI exit codes;
- no mandatory model API.

**Exit:** `agentsec eval` produces reproducible local security reports.

### Phase 2 — MCP Runtime Gateway

- MCP interception;
- tool discovery;
- allow/deny/approval;
- schema/argument checks;
- budgets;
- evidence;
- response inspection;
- fail-closed enforcement and explicit shadow mode.

**Exit:** a real MCP client/server can be protected without rewriting application logic.

### Phase 3 — Unified Contract: Policy → Evaluation → Runtime

This is the first major differentiation milestone.

- compile the contract into runtime policy;
- automatically derive negative tests;
- generate approval tests;
- test policy changes before activation;
- measure contract/test/runtime coverage;
- check semantic equivalence between test and runtime interpretation.

### Phase 4 — Provenance and Data-Flow Security

- data labels;
- source/sink modeling;
- provenance graph;
- taint propagation;
- flow policy;
- memory-write controls;
- secret/PII flow restrictions.

### Phase 5 — Incident Replay & Security Regression

- replay bundles;
- deterministic tool substitution;
- trace diffing;
- incident classification;
- “promote to regression” workflow;
- CI integration.

### Phase 6 — Identity, Delegation & Least Privilege

- agent principals;
- on-behalf-of relationships;
- short-lived credentials;
- capability-scoped tokens;
- task-scoped authority;
- delegated permissions;
- workload identity/OAuth/OIDC integrations.

### Phase 7 — Harness-Agnostic Adapters & Isolation Integration

- Python/native dispatch;
- OpenAI/Anthropic/Gemini-style tools;
- LangGraph/LangChain;
- HTTP;
- shell/coding-agent actions;
- composition with Docker/gVisor/WASM/microVM-style isolation.

### Phase 8 — Supply Chain, Tool Registry & Trust

- tool/server fingerprinting;
- schema/description pinning;
- change detection;
- dependency manifest;
- trust metadata;
- signature verification hooks;
- static tool-risk scanning.

### Phase 9 — Multi-Agent Security

- delegation graph;
- agent-to-agent identity;
- transitive authority limits;
- message provenance;
- recursive budgets;
- authority-laundering detection;
- multi-agent attack scenarios.

### Phase 10 — Managed Team Control Plane

- organizations;
- RBAC/SSO;
- shared policy registry;
- review workflow;
- centralized agent inventory;
- hosted evidence metadata;
- dashboards/alerts;
- CI integrations;
- fleet posture.

Sensitive content should be able to remain customer-side.

### Phase 11 — Enterprise Security Platform

- policy federation;
- SIEM export;
- incident workflows;
- private deployment;
- signed attestations/evidence;
- fleet policy simulation;
- support/SLA;
- risk-acceptance workflow.

### Phase 12 — Adaptive Security Research Layer

Research areas with potential moat:

- automatic attack-path generation;
- adversarial policy testing;
- learned behavioral baselines;
- anomaly detection over trajectories;
- least-privilege suggestions;
- formal authority/policy analysis;
- unsafe-trajectory prediction;
- model-specific vulnerability profiles;
- defense-portfolio optimization.

Adaptive systems may recommend tighter controls. They must not silently expand production authority.

---

## 17. Reference User Journeys

### 17.1 Local developer

```bash
agentsec contract validate security/contract.yaml
agentsec eval security/scenarios/
agentsec protect -- <agent command>
```

The developer receives findings such as unauthorized capability requests, unapproved external writes, mutable tool metadata, or exfiltration paths.

### 17.2 CI gate

```text
authorization bypasses = 0
secret exfiltration = 0
approval bypasses = 0
attack success regression < threshold
legitimate task success regression < threshold
```

### 17.3 Incident review

A trace shows:

```text
untrusted page
    ↓
agent
    ↓
secret read
    ↓
external send
```

The investigator can see the exact policy decision, approval state, data labels, dispatch state, and outcome evidence, then promote the trace into a regression case.

---

## 18. Evidence and Observability Principles

The platform should align with OpenTelemetry where practical but keep a canonical internal event model.

Important distinction:

```text
policy allowed call
≠ call dispatched
≠ tool returned success
≠ intended side effect verified
```

Security telemetry must minimize sensitive content by default and support metadata-only, hashed, redacted, local-only, and later encrypted representations.

---

## 19. Security Principles for the Product Itself

- fail closed where enforcement is promised;
- keep policy outside normal agent write scope;
- use deterministic authorization as the authority ceiling;
- treat LLMs as advisory for security decisions unless policy explicitly clamps them to more restrictive outcomes;
- version all security-relevant artifacts;
- safely parse untrusted YAML/JSON/configuration;
- never require real credentials for default tests;
- distinguish cryptographic signatures from ordinary content hashes;
- avoid claiming protection that cannot be evidenced.

---

## 20. Standards Mapping

Mappings may eventually cover:

- OWASP Top 10 for Agentic Applications 2026;
- NIST AI RMF;
- NIST/NCCoE agent identity and authorization work;
- MITRE ATLAS where relevant;
- conventional authentication, authorization, audit, secrets, and supply-chain controls.

The UI/data model should distinguish:

```text
control exists
control configured
control exercised in test
control observed in runtime
```

These are not equivalent states.

---

## 21. Evaluation Methodology

- always pair security and legitimate-task utility;
- use repeated trials for stochastic/model-dependent cases;
- prefer deterministic assertions when the behavior is objectively observable;
- separate attack generation from scoring when possible;
- report tested threat coverage rather than implying complete safety;
- pin model/provider/evaluator versions when results depend on them.

---

## 22. Integration Strategy

The product should secure existing stacks rather than require a new agent framework.

Priority order:

1. MCP;
2. generic Python dispatch;
3. provider-style function/tool calling;
4. LangGraph/LangChain;
5. HTTP;
6. coding-agent action wrappers;
7. agent-to-agent protocols.

Potential integrations rather than replacements include OpenTelemetry, Inspect AI, PyRIT, garak, Promptfoo, Cedar, OPA, and mature isolation runtimes.

---

## 23. Monetization Strategy

### 23.1 Recommended open-source core

- local CLI;
- security contracts;
- scenario format;
- local evaluation;
- runtime SDK/gateway;
- base policy engine;
- local evidence;
- core adapters.

### 23.2 Commercial / managed layer

- organization/team management;
- centralized policy and review workflow;
- fleet inventory/posture;
- hosted evidence metadata/retention;
- alerting;
- SSO and enterprise identity integrations;
- premium attack intelligence;
- managed red-team runs;
- private enterprise deployment;
- compliance evidence/reporting;
- support/SLA.

This split keeps security-critical enforcement inspectable and customer-controlled while creating recurring value in centralized management.

### 23.3 Pricing principles

Prefer value-aligned dimensions such as protected agents/environments, retained evidence volume, tool-call/event volume, seats, or enterprise contracts rather than pure token markup.

### 23.4 Profitability principle

The project should remain near-free while experimental, but once customers generate material infrastructure cost the goal becomes positive unit economics—not preservation of a zero-dollar cloud bill.

---

## 24. Licensing Direction

Initial recommendation: **Apache-2.0 core** for adoption and enterprise friendliness, with commercial differentiation in hosted/team/enterprise capabilities if real adoption emerges.

Do not prematurely optimize licensing around a hypothetical business. Revisit after meaningful usage and contributor/community feedback.

---

## 25. Success Metrics

### Early product

- reproducible eval rate;
- attack-family coverage;
- policy/test coverage;
- setup time;
- deterministic assertion share;
- false-block rate.

### Runtime

- policy latency and availability;
- unauthorized calls blocked;
- approval reliability;
- trace completeness;
- fail-closed correctness.

### Security

- attack success reduction;
- exfiltration reduction;
- approval/policy bypass rate;
- regression catch rate;
- utility/security frontier.

### Adoption

- active repositories/projects;
- CI runs;
- protected executions;
- contributed scenarios/adapters;
- incidents promoted to regressions.

### Commercial

- protected agents/org;
- paid retention/expansion;
- gross margin;
- hosted control-plane retention.

---

## 26. Key Risks

### Crowded and fast-moving market

Mitigation: compete on lifecycle integration and semantic unification, not a generic “agent firewall” claim.

### Scope explosion

Mitigation: phase rigor; do not build a SIEM, IAM system, custom sandbox, or policy language before existing components prove insufficient.

### False confidence from security scores

Mitigation: show tested coverage, evidence, uncertainty, residual risk, and utility cost.

### Detector evasion

Mitigation: treat classifiers as signals; rely on least privilege, data-flow restrictions, approvals, and isolation for hard boundaries.

### Runtime latency

Mitigation: deterministic local fast path, caching, asynchronous analytics, optional expensive detectors.

### Sensitive telemetry

Mitigation: local-first data plane, content minimization, redaction, encryption, configurable retention.

### Model-dependent evaluation cost

Mitigation: deterministic fixtures, replay, sampling, BYO keys, free providers, local models where sufficient.

### Competitive overlap with Agent Guard / mcp-firewall / similar projects

Mitigation: explicitly avoid making basic action authorization, approvals, identity, or audit the unique thesis. Prove value through shared contract compilation, attack graph generation, provenance/data-flow policy, incident-to-regression, and multi-agent delegation semantics.

---

## 27. Research Opportunities

This project can support meaningful AI-safety/security research without training frontier models:

- compare prompt-only defenses vs hard authorization;
- measure security/utility/friction/latency tradeoffs;
- model-specific vulnerability profiles;
- infer candidate least-privilege policy from safe historical behavior;
- generate attack graphs from capabilities and data flows;
- formally analyze invariants such as “no secret source reaches external sink”;
- compare isolation/approval/data-flow defense combinations;
- predict unsafe trajectories before side effects occur.

---

## 28. Relationship to the Other Projects

### Project A — Context / Drift Manager

Project A asks whether an agent has accurate, bounded, non-conflicting context.

Project B asks what happens when the agent is wrong, manipulated, compromised, or simply overpowered.

Potential future integration:

```text
Context provenance / trust
        ↓
Agent Safety & Security
        ↓
runtime risk and policy
```

They should remain separately useful and separately evolvable.

### Project C — Distributed Systems Failure Lab

Mostly independent, with possible future scenarios around policy-service failure, evidence backpressure, retries, approval outages, and cascading multi-agent failures.

---

## 29. Open Questions

1. Native deterministic policy backend first, or compile immediately to Cedar/OPA?
2. How should task scope be represented without embedding model-generated prose into authority?
3. How much provenance can be propagated across free-form model generation?
4. Which attack paths can be generated deterministically from contracts?
5. What minimum identity model is useful for local agents?
6. What evidence is required for useful replay?
7. How should “excessive agency” be measured without circular LLM judgment?
8. Which controls belong inline vs asynchronous?
9. What remains open source if the managed product becomes real?
10. Can useful policy invariants be formally checked without making the developer experience unusable?
11. How should authority cross independently operated multi-agent systems?

---

## 30. Immediate Next Step

Phase 0 should establish the shared language only:

- threat model v1;
- taxonomy;
- Agent Security Contract v0.1;
- policy request/decision model;
- scenario v0.1;
- canonical evidence events;
- validation, canonicalization, and hashes;
- local schema/validation CLI;
- fixtures and negative tests.

The goal is **not** to secure a real production agent yet. The goal is to ensure Phases 1–3 can build evaluation, runtime enforcement, and contract compilation on one coherent foundation.

---

## 31. Final Product Principle

> **An agent should never be trusted merely because the model appears well behaved.**

Security comes from explicit authority, constrained execution, adversarial verification, traceable evidence, and continuous regression testing.

The model proposes.  
The security boundary decides.  
Every failure should make the next run safer.
