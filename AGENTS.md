# AGENTS.md — AI Development Guide

This repository is intentionally organized for high-quality AI-assisted development. Treat this file as the repository-level operating contract for coding agents.

## 1. Read order before changing code

For the current phase, read:

1. `docs/prd.md`
2. `docs/architecture.md`
3. the active plan under `docs/plans/`, if one exists
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

**Phase 9 local multi-agent security is implemented; review corrections are awaiting fresh independent review.**
The review-fix baseline is `6c1a185`; its parent, `1619ac4`, contains the Phase 8 corrections.
Independent Phase 7–8 acceptance remains unconfirmed; review fixes do not constitute release
acceptance. Scope, limitations and corrected findings are in `docs/multi-agent-security.md`, the
Phase 9 plan, implementation report and review-fixes report. Phases 0–8 boundaries remain protected. Hosted control-plane services
remain out of scope. Protected operator-created ENFORCE sessions support bounded single-parent
local graphs, all-ancestor restrictive authority, exact combined approvals, shared ancestry
budgets and fixed adjacent messaging with monotonic provenance. Standalone Phase 6 parent chains
and delegated-agent caps remain unsupported; only explicit `phase9-v1` graph enrollment enables
them. Model/cost budgets remain unsupported. New principals/plans require a new local session.
Trust pins/signature keys, graph topology, providers and grants are protected operator inputs,
never discovery/model/message-provided authority. RuntimeGateway owns final graph/credential/trust
freshness. Static config is not remote authentication; JWT uses pinned keys/mappings. No raw
credentials or message bodies enter evidence. Graph replay is offline, single-epoch and blocked
on missing protected material; historical graph promotion remains DRAFT. Hashes/signatures do
not attest running code.

Native authorization, generated conformance, coverage and semantic diff consume an immutable
compiled plan. Runtime compiles once at startup; mutable approval/budget/provenance state stays
runtime-owned. Data rules only restrict ordinary authority. Labels propagate monotonically;
requests snapshot exposed context, and blocked responses never enter that frontier. Critical
exposure evidence precedes ENFORCE release. MCP source/sink proof binds exact plan/discovery
identity. Explicit source labels/static sink categories are trusted configuration; no argument
can relabel context. Generated conformance proves synthetic policy/evidence behavior, not model
robustness, semantic content detection or complete model-internal taint. Unsupported graph combinations remain explicit. Replay is offline security-semantic substitution, never live tool or model execution. Source
evidence and replay identities stay separate; material redaction is a blocker. Promotion requires
explicit safe assertions and never edits security contracts. Do not add hosted services, UI,
full OAuth/OIDC lifecycle services, Cedar/OPA, general policy languages, automatic declassification or new sandbox infrastructure. Phase 7 composes with Docker/gVisor;
RuntimeGateway remains the common security boundary and configured isolation never falls back to host.

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

## 9. End-of-phase reporting

At completion of each active phase, create the implementation report required by that phase's
plan under `docs/reports/`. Use the plan's required sections and include exact test, lint, and
type-check commands and results; deviations and rationale; open questions and known limitations;
and readiness assessment for the next phase.
