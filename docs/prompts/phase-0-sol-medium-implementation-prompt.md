# Sol Medium Codex Prompt — Bootstrap Repository and Implement Phase 0

> Historical completed prompt: Phase 0 has been implemented. This file records the original
> bootstrap request and is not active implementation guidance. See `AGENTS.md` and the current
> phase plan for present scope.

You are implementing **Phase 0 of the Agent Safety & Security Platform** in the repository provided with this prompt.

Your job is to take the existing documentation-first scaffold and turn it into a clean, tested Phase 0 implementation. Work directly in the repository. Do not merely propose code or return an implementation plan.

## Required reading before coding

Read these files in order:

1. `AGENTS.md`
2. `docs/prd.md`
3. `docs/architecture.md`
4. `docs/plans/phase-0-implementation-plan.md`
5. `README.md`

The Phase 0 plan is intentionally detailed. Treat it as the implementation checklist while preserving the architectural invariants in `docs/architecture.md`.

## Mission

Implement the full Phase 0 foundation so that future Phase 1 evaluation and Phase 2 runtime enforcement can share one canonical security domain model.

At completion, the repository must have a coherent, local-only implementation of:

- stable taxonomy enums and identifiers;
- principals, agent identity, task scope, and delegation models;
- tools/capabilities and tool metadata hashes;
- minimal provenance/data-artifact primitives;
- policy request/decision models and reason codes;
- approval request/decision models with exact-action binding;
- Agent Security Contract v0.1;
- strict YAML/JSON loading and structured semantic validation;
- canonical serialization;
- explicit `document_hash` and `effective_policy_hash` semantics;
- canonical security events with typed payloads;
- scenario schema v0.1 and deterministic assertion types;
- finding model;
- minimal `PolicyEngine` and `EventSink` ports only;
- JSON Schema export;
- the Phase 0 CLI commands;
- representative valid/invalid examples and fixtures;
- high-quality unit, negative, round-trip, golden, and targeted property-based tests;
- focused documentation required by the Phase 0 plan;
- a final Phase 0 implementation report.

## Critical scope boundary

Do **not** implement future phases early.

In particular, do not implement:

- a real MCP gateway/proxy;
- a production policy engine;
- `agentsec eval` execution;
- `agentsec protect`;
- LLM/model-provider clients;
- prompt-injection classifiers;
- provenance/taint propagation;
- replay;
- OAuth/OIDC;
- hosted APIs or a web UI;
- Cedar/OPA integration;
- sandbox/container orchestration.

Do not add empty modules/directories just to signal future work.

## Security semantics that must not drift

### 1. Model text is not authority

No API should authorize based directly on a prompt string. `PolicyEngine` consumes a structured `PolicyRequest`.

### 2. Task scope is not authority by itself

A task can express requested/needed capabilities, but it does not grant them. Later effective authority will be the intersection of explicit policy/delegation/task scope.

### 3. Tool identity is separate from mutable metadata

A stable tool ID must not change just because a description/schema changes. Description and schema hashes exist specifically to detect meaningful metadata change.

### 4. Approval binds to the exact normalized action

A previously approved call must not authorize a materially different call. The action digest must be deterministic and tested.

### 5. Evidence stages are distinct

`TOOL_REQUESTED`, `POLICY_EVALUATED`, `APPROVAL_*`, `TOOL_DISPATCHED`, `TOOL_RETURNED`, and `EFFECT_VERIFIED` must remain semantically distinct.

### 6. Two named hashes

Do not expose a generic ambiguous `contract_hash`.

Implement and document:

- `document_hash` — full canonical authored document except unstable/generated fields;
- `effective_policy_hash` — canonical security-relevant semantics excluding cosmetic metadata.

Test at minimum:

- map/set ordering does not change either hash;
- a cosmetic description change changes `document_hash` but not `effective_policy_hash`;
- a rule/budget/principal/data-policy change changes `effective_policy_hash`.

### 7. Strict parsing

Reject unknown security configuration fields and unsafe YAML constructs. Avoid silent coercion of security-sensitive booleans/numbers/enums.

## Implementation approach

Work in the order recommended by the Phase 0 plan unless repository reality reveals a concrete dependency reason to adjust it.

A good progression is:

1. project/tooling sanity and package importability;
2. terminology/taxonomy;
3. base domain models;
4. policy and approvals;
5. contract v0.1 + loader/semantic validation;
6. canonicalization and hashes;
7. event/evidence model;
8. scenario/finding models;
9. schema export;
10. CLI;
11. public examples and invalid fixtures;
12. focused documentation;
13. broad tests and quality pass;
14. implementation report.

## Technical expectations

Use the scaffold's Python package namespace `agentsec` and keep the core domain independent of MCP, provider SDKs, HTTP frameworks, and databases.

Use Pydantic v2 for strict typed models and JSON Schema generation unless there is a compelling repository-local reason not to. Use safe YAML parsing. Keep dependencies minimal.

Prefer explicit small modules over generic abstractions. Avoid broad `dict[str, Any]` in canonical security models except for deliberately bounded JSON-schema/JSON-value fields.

Use stable machine-readable error codes. CLI tests should assert codes/exit behavior rather than fragile full prose where possible.

## CLI required at completion

These commands must exist and be tested:

```bash
agentsec version
agentsec contract validate <path>
agentsec scenario validate <path>
agentsec schema export --out <dir>
agentsec examples validate
```

Do not expose future commands as fake placeholders.

Successful contract validation should surface at least:

```text
VALID
contract_id: ...
schema_version: 0.1
document_hash: sha256:...
effective_policy_hash: sha256:...
```

## Examples required

Create at least the three valid contracts and three valid scenarios from the Phase 0 plan:

- read-only research agent;
- support agent with approval;
- coding agent;
- indirect prompt injection scenario;
- canary exfiltration scenario;
- resource-exhaustion/budget scenario.

Also create a meaningful invalid fixture corpus covering the important validation and parsing failures.

Use only synthetic/canary secrets.

## Testing and quality bar

The default suite must run entirely locally with no API keys and no network dependency.

Cover:

- enum/identifier serialization;
- unknown fields;
- unsupported schema versions;
- duplicate and contradictory rules;
- invalid budgets/timeouts/timestamps;
- tool schema/description hash semantics;
- document/effective-policy hash semantics;
- approval action digest semantics;
- event payload discriminators;
- event sequence validation;
- scenario assertion discriminators;
- YAML safety;
- YAML/JSON semantic round trips;
- JSON Schema regeneration consistency.

Use Hypothesis only where it materially improves confidence (e.g. canonical ordering/hash invariants); do not add it for superficial coverage.

Run and fix all configured checks, expected to include at least:

```text
ruff
mypy (or the scaffold's chosen type checker)
pytest
schema/example validation
package/build sanity
```

If you change the tooling choice, justify it in the implementation report.

## Documentation required

Create/refine these files as specified by the plan:

- `docs/threat-model.md`
- `docs/evidence-model.md`
- `docs/security-contract.md`
- `docs/scenario-format.md`
- `docs/taxonomy.md`

Keep them aligned with actual code and generated schemas. Do not manually edit generated JSON Schema files.

## Required final report

Create:

`docs/reports/phase-0-implementation-report.md`

It must include:

- summary;
- implemented deliverables;
- final repository structure;
- domain-model decisions;
- contract/scenario/event schema decisions;
- hash/canonicalization decisions;
- CLI commands;
- exact tests/checks run and results;
- deviations from the plan and why;
- security assumptions/non-guarantees;
- known limitations/open questions;
- Phase 1 readiness assessment.

If you make a material deviation from the Phase 0 plan, record it there rather than silently changing semantics.

## Self-review before finishing

Before ending the session, explicitly inspect the implementation against the Phase 0 Definition of Done and Phase 1 Readiness Gate.

Pay special attention to these failure modes:

- evaluation and runtime concepts accidentally use different names/types;
- `TaskScope` accidentally grants permission by itself;
- a generic ambiguous contract hash survived;
- Pydantic/YAML silently coerces dangerous values;
- event payloads are untyped dictionaries;
- raw secret content is required by the evidence model;
- tool identity is tied to mutable metadata;
- future-phase code has leaked into Phase 0;
- docs describe behavior tests do not establish;
- generated schemas are stale.

Fix issues you find before completing the implementation.

## Completion response

When the repository work is finished, provide a concise summary containing:

1. what was implemented;
2. important design choices/deviations;
3. checks/tests run and whether they passed;
4. paths to the implementation report and key docs;
5. any genuine blockers or Phase 1 risks.

Do not stop after analysis or planning. Complete the Phase 0 implementation in the repository.
