# AGENTS.md — AI Development Guide

This repository is intentionally organized for high-quality AI-assisted development. Treat this file as the repository-level operating contract for coding agents.

## 1. Read order before changing code

For the current phase, read:

1. `docs/prd.md`
2. `docs/architecture.md`
3. the active plan under `docs/plans/`
4. relevant focused docs under `docs/`
5. existing implementation reports under `docs/reports/`

Do not infer product scope from the README alone.

## 2. Authority of documents

The documents answer different questions:

- **PRD:** product intent, user value, long-term roadmap, competitive boundary.
- **Architecture:** enduring technical constraints, trust boundaries, domain semantics.
- **Phase plan:** what must and must not be implemented in the current phase.
- **Implementation report:** what was actually implemented and any deliberate deviation.

If they appear to conflict, do not silently pick whichever is convenient. Prefer the narrowest interpretation that preserves the PRD and architecture, document the ambiguity/deviation in the implementation report, and avoid irreversible design expansion.

## 3. Current phase boundary

The scaffold is prepared for **Phase 0**.

Phase 0 builds canonical models, schemas, validation, canonicalization/hashing, local validation CLI, examples, and documentation.

Phase 0 must **not** grow into:

- a real MCP proxy;
- a production policy engine;
- a full eval runner;
- model-provider integration;
- provenance propagation;
- hosted services;
- a web UI;
- OAuth/OIDC;
- Cedar/OPA integration;
- a sandbox implementation.

## 4. Architectural invariants

Preserve these unless the architecture doc is deliberately amended with rationale:

- core domain code is framework/protocol/database independent;
- prompt/model text never becomes authorization merely by existing;
- policy evaluation consumes structured requests;
- tool identity is separate from mutable tool description/schema metadata;
- approvals bind to exact normalized actions;
- evidence distinguishes request, decision, approval, dispatch, response, and verified effect;
- evaluation and runtime share the same canonical domain types;
- all serialized security artifacts carry explicit schema versions;
- deterministic controls are the authority ceiling over probabilistic detectors/LLM suggestions;
- no agent code path should normally mutate protected security policy.

## 5. Implementation style

- Prefer small typed modules with explicit names over generic abstractions.
- Avoid `utils.py` dumping grounds.
- Avoid pervasive `Any` and unstructured dictionaries for core security models.
- Reject unknown security configuration fields.
- Prefer strict parsing over coercion.
- Use explicit error codes/types for security-relevant failures.
- Keep core tests fully local and credential-free.
- Do not add dependencies without a concrete correctness/interoperability benefit.
- Do not add future-phase directories/classes merely as placeholders.
- Do not create a plugin framework before extension points are proven.

## 6. Hash terminology

Do not expose a generic ambiguous “contract hash.” The project distinguishes:

- `document_hash`: identity of the full normalized authored document (excluding unstable/generated fields);
- `effective_policy_hash`: identity of normalized security-relevant semantics.

Cosmetic-only changes may alter `document_hash` without altering `effective_policy_hash`.

## 7. Testing expectations

Security projects need strong negative tests.

Every new validator should have invalid fixtures/tests. Test malformed schema versions, unknown fields, duplicate IDs, unsafe YAML constructs, invalid timestamp ranges, event/payload mismatches, ordering invariants, and hash stability where relevant.

Prefer deterministic assertions. Do not introduce LLM-as-judge in Phase 0.

## 8. Documentation discipline

When implementation changes a material semantic decision:

1. update the relevant focused doc;
2. update architecture only if the enduring design changed;
3. update the phase implementation report with the reason;
4. do not rewrite the PRD for implementation convenience.

Generated schemas should never be manually edited.

## 9. End-of-phase requirement

At Phase 0 completion, create:

`docs/reports/phase-0-implementation-report.md`

using the template and required sections from the Phase 0 plan.

The implementation report must include exact test/lint/type-check commands and results, deviations from plan, open questions, and Phase 1 readiness assessment.
