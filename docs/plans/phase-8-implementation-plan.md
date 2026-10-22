# Agent Safety & Security — Phase 8 Detailed Implementation Plan

**Phase:** 8 — Supply Chain, Tool Registry & Trust
**Status:** Implemented under explicit user authorization; independent review/acceptance pending. See `docs/reports/phase-8-implementation-report.md` for actual scope, evidence and proof limits.
**Repository:** [`jasonkli21/agent-safety-security`](https://github.com/jasonkli21/agent-safety-security)
**Inspected default-branch HEAD:** `939c8582f5cec99b3f77b5d38703d7cf6d5d11e8` (`fix: address phase 7 review findings`) on 2026-10-21
**Prerequisites:** Phases 0–7, including Phase 7 review corrections; independent acceptance of Phase 7 remains a release gate, not something this document assumes has occurred.
**Authoritative sources:** `docs/prd.md` §16 Phase 8; `docs/architecture.md`, especially §§3, 5, 9, 11, 13, 17, 22–24 and the appended Phase 3–7 notes; `AGENTS.md`; `docs/adapters-isolation.md`; `docs/runtime-mcp.md`; `docs/security-contract.md`; `docs/contract-conformance.md`; `docs/evidence-model.md`; `docs/replay-incidents.md`; the Phase 7 implementation and review-fixes reports.
**Main deliverable:** A **local-first, operator-controlled tool/server/dependency trust lifecycle**: stable inventory and fingerprints, reviewed pins, deterministic change detection, explicit trust evidence and verification, meaningful risk inspection, and enforcement through the existing protected runtime boundary.

---

## 1. Why Phase 8 exists

A security contract answers **whether an agent is allowed to request an action**. Phase 7 expanded the protected action surfaces, but their implementations remain operator trust assumptions. Phase 8 answers a different question: **is the tool, server, executable, image or dependency being wired into this authorized route the operator-reviewed candidate, and what evidence supports that statement?**

Neither answer subsumes the other. A publisher-verified tool can still be overprivileged or compromised. A policy-authorized tool can be replaced, silently reconfigured, or misrepresented by untrusted discovery metadata. Phase 8 must attach supply-chain/change-control evidence to execution routes without turning it into an authorization grant or inventing code-execution attestation.

The phase is successful if a developer can inspect an actual candidate inventory, deliberately approve its expected identities, see exact changes between candidates, block a changed/unverifiable protected route under an opted-in strict policy, and review content-free evidence tying runtime dispatch to the approved snapshot. **The default remains local/offline, with zero network or paid service requirements.**

## 2. Verified repository baseline and important constraints

| Existing seam at inspected HEAD | Present behavior | Phase 8 implication |
| --- | --- | --- |
| `src/agentsec/domain/tools.py` | `ToolDescriptor` has stable tool/server fields, separate schema and description hashes | Reuse; do not redefine old hash projections. Add richer *separate* trust fingerprints. |
| `src/agentsec/adapters/mcp/discovery.py` | Discovery snapshots immutable SDK metadata; optional expected schema/description pins; duplicate/stale bindings fail ENFORCE | Preserve pins and pagination/transport semantics; provide an additive registry/trust admission layer. |
| `src/agentsec/adapters/mcp/config.py` | `ToolBinding`, `McpGatewayConfig`, explicit upstream configuration | Any trust lock location/requirement is protected operator config, never agent-controlled tool args or upstream metadata. |
| `src/agentsec/adapters/mcp/server.py` | One discovery snapshot per session; `RuntimeGateway.call` owns authorization | Add trust checks at startup, exposure, and dispatch boundary without a second policy engine. |
| `src/agentsec/runtime/bindings.py` | `ProtectedTool` and `ProtectedCall` snapshot metadata; route identity and preflight; provider rebinds route | Reuse one trust admission abstraction for native/provider/LangChain/HTTP/process and MCP. Preserve rebinding identity. |
| `src/agentsec/domain/execution.py` | `ExecutionBinding` binds adapter, revision/config and isolation | Add optional, versioned trust-snapshot identity only when actually configured; never claim it attests code. |
| `src/agentsec/runtime/gateway.py` | One trusted policy/approval/budget/provenance/evidence path; approval bound to exact action; last authority check immediately before dispatch | Trust must be checked **before approval and side effects**, and rechecked as late as supported before dispatch; no bypass or hidden retry. |
| `src/agentsec/adapters/http.py` | Fixed HTTP action with protected TLS CA and explicit effect-target assertion | Endpoint/config fingerprint is not verified server code or DNS. Do not pretend a URL or TLS session proves implementation identity. |
| `src/agentsec/isolation/backends.py` | Docker profile with `--pull=never`, optional runsc and owned cleanup | Docker image tags are not content pins; verify local immutable image identity when possible; preserve no-host-fallback guarantee. |
| `src/agentsec/replay/*` and `domain/replay.py` | Offline substitution; distinct `route_comparison` via candidate route manifest | Keep route-fidelity and trust-fidelity distinct, explicit UNKNOWN/INCOMPLETE for historical facts. Never execute a tool during replay. |
| `src/agentsec/evidence/*` and `domain/events.py` | Typed, content-minimized events; no authenticated audit ledger | Record supported trust status and digest only; do not claim signed event history. |
| `docs/reports/phase-7-review-fixes-report.md` | 735 tests, Ruff, formatting, mypy, examples, regression, schema and build gates reported passing | Record a fresh Phase 8 preflight; reports are historical claims, not proof the new workspace is green. |

**Repository-status warning:** `AGENTS.md` and README say Phase 7's review fixes await independent re-review. This plan **does not** assert their acceptance. Before implementing, read the current review disposition and verify there are no unresolved P1/P2 blockers. If the repository changed after `939c858`, inventory the delta and reconcile the plan before editing. Do not change historical implementation reports to suggest acceptance.

### 2.1 Preflight, evidence and document hierarchy

1. Record `git status --short`, exact `git rev-parse HEAD`, runtime interpreter/venv and available extras; never overwrite unrelated local changes.
2. Read `AGENTS.md`, PRD, architecture, Phase 7 plan/report/review fixes, focused docs and relevant production/tests. Inspect any newest commits and review notes.
3. Run the baseline gates from §18. Distinguish pre-existing failures from Phase 8 regressions; do not weaken tests or authorization to obtain green results.
4. Create a short implementation decision ledger for design choices where this plan deliberately leaves alternatives open. PRD is product intent; architecture/security invariants are binding; newer focused docs describe actual behavior; phase plan narrows new work. Resolve apparent conflicts explicitly, not silently.
5. Ensure no Phase 7 review blocking item is silently folded into new features. The implementation prompt is authorization to work on Phase 8, not acceptance of Phase 7.

## 3. Scope: what to ship, and what not to claim

### 3.1 In scope — one complete vertical slice

1. A **canonical, versioned local inventory** of tool and server/route candidates with stable identities, provenance/source references, descriptions and schemas, metadata fingerprints, operator-observed artifact data and explicit coverage gaps.
2. A **separate, operator-approved trust lock/policy** with pinned expectations for the relevant identities, protection against tool-supplied authority, and deterministic normalization/versioning.
3. A **deterministic trust assessment and change-diff** reporting added/removed/changed items, pinned mismatches, unobserved inputs and per-dimension evidence status.
4. A **dependency manifest** for direct/declared dependencies and safely observed artifacts, with exact names, versions, digests/source provenance when available and explicit unknowns when resolution is absent; no pretend complete SBOM.
5. **Signature verification hooks** with a real, narrow, optional verification path (recommended Ed25519 over a domain-separated canonical attestation envelope and operator-pinned public keys); success proves what was signed, not who ran code.
6. **Deterministic static risk inspection** of tool/route manifests, classification and observable configurations: structured risk findings, stable rule IDs, severity/reasons, and no unsafe auto-trust.
7. **Runtime trust admission** for opted-in protected routes via `RuntimeGateway` and existing adapters: ENFORCE fail-closed on mandatory missing/changed/unverifiable trust evidence, truthfully report SHADOW/DISABLED, and bind approved snapshot to exact action/approval/dispatch.
8. Minimal **offline CLI** and examples for `inspect → pin/review → verify → diff → scan → protect`, plus focused docs, schemas, tests and implementation report.

**Implemented launch-boundary scope:** this phase does not attest an MCP server executable before
startup. Trust-enabled ENFORCE stdio requires the operator to provide an external, operator-managed
launch boundary before agentsec connects; HTTP endpoint contact also precedes tool admission. The
config flag records that deployment prerequisite, not evidence that agentsec verified it. Do not
claim Phase 8 prevents pre-discovery startup effects or provides a first-class server provenance
graph.

### 3.2 Explicitly deferred

- Phase 9 multi-agent principals, graph traversal, recursive delegation, agent-to-agent message chain trust and recursive budgets.
- Phase 10 registry server, trust marketplace, hosted control plane, signing service, federated RBAC/SSO or SaaS billing.
- Phase 11 transparency log, fleet-wide attestation enforcement, externally witnessed audit history, full artifact/SLSA/Sigstore ecosystem support.
- Live third-party package reputation/vulnerability feeds, arbitrary repository crawling, dynamic malware detonation, generalized SBOM resolution, platform-wide auto-update, real-time supply-chain threat intelligence.
- Proving arbitrary Python callable, HTTP service, MCP server or Docker daemon runtime semantics; secure boot, trusted execution environment or cryptographic proof of actual execution.
- Replacing `RuntimeGateway`, granting new policy capabilities, rewriting `phase6-v1` compiled contract meaning, automatic risk-based authorization, or automatically approving a new fingerprint.
- Implicit execution of downloaded plugins, unsigned dependencies or dynamically discovered tools merely because inspection succeeded.

### 3.3 Trust terminology is part of the contract

Never collapse these distinct statements:

| Fact | Exact meaning | Not evidence for |
| --- | --- | --- |
| `OBSERVED` | Candidate bytes/metadata were read from a declared observation source | Operator acceptance, publisher authenticity, runtime state |
| `PIN_MATCH` | Canonical observed material equals an operator-approved expected digest | Signature, unchanged executable behavior, trusted origin |
| `SIGNATURE_VERIFIED` | Signature validates against an independently provisioned pinned trust root and domain-separated signed material | Runtime execution identity, safe code, tool authorization |
| `ADMITTED` | A named protected route satisfied the operator's chosen required predicates at check time | Eternal freshness, safety, policy ALLOW |
| `UNKNOWN` / `INCOMPLETE` | Required material unavailable or a historical record lacks necessary facts | Success or failure of implementation integrity |
| `CHANGED` / `REJECTED` | Confirmed mismatch/invalid input or unmet required predicate | Proof the candidate is malicious |

Use precise result fields instead of a single misleading boolean `trusted`. Severity labels are advisory; only explicit operator policy controls admission.

## 4. Threat model and trust boundaries

**Protected assets:** approved trust policy/lock, pinned public keys, contract/compiler identity, route configuration, executable/image artifacts, tool registry, approvals, evidence and incident/regression artifacts.

**Attacker capabilities to cover:** malicious MCP metadata/tool descriptions; tool-server replacement with unchanged name; schema or capability drift; reused version tags; mutable native callable identity; malicious or shadowed local path/dependency; forged dependency manifests; mixed-scope attestations; signer/key substitution; TOCTOU between initial inspection and action; hostile agent edits of lock file; supplied hashes masquerading as observations; untrusted server changing implementation without updating discovery; arbitrary tool return injection into registry state; replay pretending to re-attest code.

**Trust boundary diagram:**

```text
Operator-owned contract, lock, keys and protected adapter wiring
                         |
              strict validate/canonicalize
                         |
             approved trust requirements
                         |
Candidate inspection ----+----> immutable inventory/diff/scan (advisory)
   MCP metadata / file stats / package manifest (untrusted observations)
                         |
       verify evidence (source-aware; independent trust roots)
                         |
       trust admission at protected registration/startup
                         |
     agent action -> existing RuntimeGateway policy/approval
                         |
          final trust/freshness guard (where verifiable)
                         |
              exactly-one protected dispatch
                         |
        minimized dispatch/evidence + explicit limitations
```

Protect operator-owned paths outside the agent's ordinary write privilege. Static local configuration is not hardware-rooted proof. Do not ingest data from `arguments`, LLM/tool responses, framework callbacks or MCP-reported self-labels as a trust root. Untrusted descriptions are **data**, never operational instructions or prompts for an LLM scanner.

## 5. Canonical types and fingerprinting

### 5.1 Proposed module placement (adapt names to real code)

```text
src/agentsec/supply_chain/
    __init__.py
    models.py              # strict versioned inventory, lock, evidence, verdict, diff
    fingerprints.py        # domain-separated canonical metadata and raw artifact bytes
    inventory.py           # deterministic offline constructors, registry snapshot
    verification.py        # pinned expectations, optional cryptographic verification
    signatures.py          # optional Ed25519 verifier adapter, no key generation by default
    scanning.py            # static deterministic inspections; never grants privileges
    admission.py           # shared preflight/final trust guard for existing runtime
src/agentsec/cli/trust.py # inspect/verify/diff/scan commands, if CLI useful
```

Do not create unused plugin systems or empty adapters. Domain types may live in `domain/` if doing so avoids circular imports; keep the dependency direction clean. Use `SecurityModel`/`VersionedModel` for strict unknown-field rejection and immutable top-level models; **defensively copy nested dicts at trust-boundary crossings**.

### 5.2 Inventory objects and identities

Implement a minimal but expressive schema (choose exact names during implementation and document them):

- `InventorySnapshot`: `schema_version`, `inventory_id`, `captured_at` as **observation metadata only**, declared `source_kind`, sorted `ToolCandidate`s, `ServerCandidate`s and `DependencyRecord`s, plus an explicit coverage/completeness inventory. **Content digest projection excludes timestamps and non-semantic display labels**; if a timestamp is included in the full stored file, distinguish document hash from semantic identity.
- `ToolCandidate`: fully qualified `namespace/protocol/server_id/tool_id/name`, descriptor fingerprint, tool schema and description hash, selected capabilities/risk/side-effect classification as **reviewed policy-side declarations** (never inherited authority from untrusted metadata), binding digest, associated server/route identity and observation status.
- `ServerCandidate` or `RouteCandidate`: transport (`mcp_stdio`, `mcp_http`, `native`, `http`, `process`, `docker`...), protected adapter ID, stable endpoint/config identity, implementation artifact reference(s), observed configuration/digests, explicit verification limits and source provenance.
- `DependencyRecord`: package/ecosystem/normalized name, declared vs resolved version (if known), reference to direct parent, optional artifact path/digest/hash algorithm, provenance kind and explicit missing facts. Stable sorting and bounded nesting/size. Do not invent resolved versions from range constraints.
- `TrustLock`: versioned, reviewed expectations for exact candidate identity + dimensions; an explicit policy for which checks are mandatory (`require_metadata_pin`, `require_artifact_digest`, `require_signature` as applicable), allowed signers/key IDs and candidate sets. Unknown/unlisted candidates default **not admitted** when lock-required mode is enabled. No wildcards or broad permissive defaults in first version.
- `TrustAssessment`: per-object verified observations, `PIN_MATCH`/mismatch/unknowns by dimension, signer verification result, required coverage gaps, stable reason codes, `ADMITTED`/`REJECTED`/`INCOMPLETE` result and semantic snapshot digest.
- `RegistryDiff`: deterministic added/removed/changed items with field-category and redacted digest comparisons; distinguish policy/route changes from schema/description changes and from unknown, not simply "same name".
- `RiskFinding`: stable rule ID, target ID, category (e.g. `SUPPLY_CHAIN_CHANGE`, `TOOL_POISONING`), severity, concise redacted explanation, evidence field path and remediation suggestion; never include secrets or execute referenced artifacts.

Avoid mixing `ToolDescriptor.trust` (Phase 0 provenance trust class) with supply-chain verification status. Keep identity and digest fields context/domain separated to prevent cross-type substitution.

### 5.3 Fingerprint specification

Reuse `canonical_json` and `content_digest` when hashing structured model projections, but define a **versioned, domain-separated projection** for each new purpose: e.g. `{kind:"agentsec.tool-metadata.v1", identity:{...}, schema_hash:..., description_hash:..., declared_properties:...}`. Stable tool name alone is insufficient. Include protocol/server scope and relevant protected routing/binding configuration. Preserve existing `ToolDescriptor.schema_hash`, `.description_hash`, contract hashes and `ExecutionBinding` semantics.

Use **raw SHA-256 of bytes** for local file content and OCI-style observed image digest where genuinely available; do *not* feed a raw binary blob through `content_digest` or equate a tag to digest. Declare exactly which bytes have been hashed, path/symlink handling, allowed file kind/size, and what can mutate afterward. A file digest is not signature verification. A certificate chain on HTTPS authenticates the TLS peer under the configured CA policy; it does not prove application code.

Canonical object order independence: reorder maps/sets or registry discovery order → same fingerprint; meaningful change to schema/description/tool/server/route/dependency → expected field-specific change. Detect duplicate IDs, ambiguous normalized names, conflicting paths and digest collisions due to invalid projection design.

### 5.4 Dependency manifest minimum useful behavior

Support an operator-supplied local manifest with direct dependencies and referenced artifacts; `pyproject.toml` *declared* requirements may be ingested using standard `tomllib` if trivial, but never mark them resolved or reproducible without a lock/artifact observation. Optional conversion from a local lockfile is fine if fully deterministic, bounded and tested; do not expand to network resolution. Show whether coverage is `DECLARED_ONLY`, `RESOLVED_LOCKED`, `ARTIFACT_HASHED` or `UNKNOWN`, not a fake complete SBOM. A name/version match is not proof of bytes.

## 6. Registry and trust lock lifecycle

**Prefer an in-process immutable registry snapshot, not a daemon/service.** The source of approved expectations must be explicitly separate from observed inventory and scanner recommendations. Use a deliberate, auditable promotion step rather than `inspect` writing directly into trusted lock state.

Reference UX:

```text
1. inspect discovered/protected candidates       (read only, no execution)
2. scan candidate metadata/manifests             (advisory findings)
3. diff candidate against current reviewed lock  (exact change summary)
4. operator reviews & deliberately pins          (outside agent write authority)
5. verify candidate against lock/keys            (offline; report gaps)
6. activate strict trust requirement             (only if required facts are verifiable)
7. gateway admits matching candidate then enforces ordinary policy
8. unexpected change -> safe rejection/signal, no automatic acceptance
```

### 6.1 Registration and mutation safety

- Registry is a snapshot keyed by qualified IDs. Duplicate qualified identities, duplicate manifest keys, conflicting descriptors and incomplete required relationships fail loudly.
- Lock and trust-key material are independently supplied; untrusted candidate cannot specify its own trusted key, acceptable signer, verification algorithm, or expected digest.
- Registry lookup is exact, with no fuzzy name resolution, implicit aliases or wildcard fallback. Unknown tool/server is not implicitly authorized.
- All producer SDK/tool dictionaries are copied and validated before comparison; no post-validation mutation can silently change a stored expected fingerprint.
- Concurrency-safe decisions must bind to one immutable inventory+lock generation; lock updates create new generations. Do not reuse approvals across generations.
- Set a bounded size for manifests, descriptions, schemas, lists and file inspection. Fail closed for unsupported required checks in ENFORCE rather than trying to hash unlimited/unsafe inputs.

### 6.2 Change detection and compatible diffs

Classify: `NEW`, `REMOVED`, `METADATA_CHANGED`, `ROUTE_CHANGED`, `ARTIFACT_CHANGED`, `DEPENDENCY_CHANGED`, `SIGNER_CHANGED`, `INCOMPLETE`. Distinguish `not observed` from `unchanged`. For changed description/schema, use existing pins as inputs; for route/image and dependency changes, compare their own identity dimensions. Output deterministic machine-readable JSON and stable human summaries suitable for CI. No automatic policy widening and no auto-lock rewrite.

## 7. Signature verification: a real narrow hook, never an attestation claim

Define a pure verification port (e.g. `SignatureVerifier.verify(signed_payload, signature, trusted_key_ref) -> VerificationResult`) and **one concrete optional Ed25519 implementation** if optional `cryptography` is already practical. Verified material should be a canonical, domain-separated, versioned object with explicit `subject_kind`, `subject_id`, `content_digest`, scope/producer and declared expiry if appropriate. Verify exactly the locked expected subject and payload; reject algorithm downgrade, key substitution, wrong domain, wrong subject, expired signing facts, malformed public keys/signatures, unsupported algorithms, duplicate key IDs and mutable/cross-tenant scope confusion.

Trust keys are **operator-controlled configuration**, not embedded in the candidate or automatically downloaded from a claimed issuer. Treat verification as `SIGNATURE_VERIFIED` only for the signed statement. It does **not** establish that the runtime executed the signed binary/image, that dependencies were safe, or that the signer had trustworthy release practices. If an implementation cannot justify cryptographic validation safely, ship a well-tested port and report `SIGNATURE_UNSUPPORTED` rather than implementing a pretend verifier; explain this deviation as a missing exit criterion, not a success.

Keep normal installs light: core pure types/verification should work without an optional crypto extra. Under no circumstances sign with an ephemeral auto-generated key and call it a production trust root.

## 8. Deterministic static tool-risk inspection

Static, offline, bounded inspection only. Create several useful **explainable rules**, each with stable rule ID and field path. Candidate rules:

| Rule family | Grounded signal | Interpretation |
| --- | --- | --- |
| Sensitive action surface | `CODE_EXECUTION`, `DESTRUCTIVE`, `FINANCIAL`, `IDENTITY_PRIVILEGE`, `INFRASTRUCTURE` | Reviewed capability needs explicit authority/approval/isolation; not "malicious". |
| Data egress exposure | declared sensitive source labels combined with external sink / missing classification | Coverage gap or escalation risk; never infer clean outputs. |
| Unpinned mutable implementation | executable path with no verified bytes, mutable image tag, absent required publisher/source pin | Trust coverage warning/block under chosen strict requirements. |
| Metadata or route drift | schema/description/transport/binding/endpoint differs from reviewed lock | Exact change needing human review. |
| Suspicious description metadata | deterministic bounded markers for instruction-like or authority-spoofing text in description | Potential tool-description injection; indicator only, not a comprehensive LLM-content detector. |
| Missing dependency provenance | declared dependency has no resolved artifact/source | Supply-chain coverage gap, not a vulnerability claim. |

Scan **metadata and declarations**, not arbitrary code execution; parsing/regex must be resource-bounded and avoid pathological patterns. Findings cannot add capabilities, change trust requirements, bypass a deny, auto-fix a lock or silently suppress enforcement. Tests should explicitly show high-risk-but-approved and low-risk-but-unpinned cases diverge as intended.

## 9. Enforcement integration and race semantics

### 9.1 Core rule: trust restricts authorization, never grants it

Formalize for protected action `a`:

```
can_dispatch(a) = existing_runtime_can_dispatch(a)
                  AND configured_trust_requirements_met(a)
```

Under no configured trust lock/gate, preserve existing Phase 7 behavior with an explicit `NOT_CONFIGURED`/`UNASSESSED` state; **do not** claim a verified supply chain. In strict ENFORCE, unknown/missing required proof, changed candidate, wrong signer or stale generation blocks action. In SHADOW, record truthful would-block trust findings while preserving existing mode semantics; DISABLED must not fabricate checks or override isolation/transport safety. Document any non-recoverable setup errors that should block even in shadow/disabled (e.g. invalid security config).

### 9.2 Shared gateway admission surface

Provide a narrow, reusable trust-validation interface consumed by `RuntimeGateway` (or a contained shared wrapper with **proof of identical semantics**), not five ad-hoc adapter checks. Prefer:

1. **Registration/startup gate:** operator-configured lock and key validation; discovery snapshot/build; strict coverage; no tool exposure under a strict missing/changed trust requirement.
2. **Pre-approval gate:** bind immutable trusted lock generation, candidate and required proof to a route; if not admitted under ENFORCE, reject **before** approval broker, budget commitment, TOOL_DISPATCHED and side effects. If the gateway has already emitted TOOL_REQUESTED or a trust signal, preserve truthful event ordering.
3. **Final pre-dispatch gate:** re-evaluate a supported **local, bounded, no-network, no-side-effect freshness predicate** after approval, before event/dispatch; ensure no intervening `await` or newly mutable state between final check and dispatch entry where the existing invariant permits. If impossible, report `RUNTIME_FRESHNESS_UNVERIFIABLE`; do not silently promote startup pins to runtime proof.
4. **Binding:** trust lock/snapshot generation participates in exact action digest and approval identity when configured; changing trust expectations or route after approval invalidates it. Preserve old omitted fields/hash identity for historical calls with no Phase 8 trust metadata.
5. **Failure truthfulness:** emit safe failure codes and category `SUPPLY_CHAIN_CHANGE` / `TOOL_POISONING` as appropriate, with no secrets; keep unknown effects unknown if dispatch already started. Never retry automatically or use an unguarded fallback.

Be precise about race limits: hashing a file then launching the same mutable path is not atomic attested execution. Prefer an immutable content-addressed reference/open-file handle where the host primitive allows it, or downgrade freshness to `UNVERIFIABLE` and refuse a policy that requires a guarantee the platform cannot provide. A `DockerProfile.image="local:tag"` with `--pull=never` alone is **not** an image digest pin. `docker inspect` or an image ID assertion can narrow uncertainty but does not independently attest daemon behavior. Remote HTTP/MCP code can change while reported schema stays identical; a pin on discovery metadata is not live server attestation.

### 9.3 Adapter-specific obligations

- **MCP:** reuse the existing discovery snapshot and hash pins; qualify the tool by gateway + server + wire tool name + descriptor, bind server/upstream route identity; protect tools/list visibility under strict policy; no first-use discovery update or silent adoption. If live implementation identity is unobservable, expose the gap. Preserve pagination, request-ID guard and error conventions.
- **Native Python and provider wrappers:** require operator-supplied implementation revision as a claim, not proof; optionally validate an observed local module/artifact bytes pin when safely resolvable. `ProtectedCall.for_adapter()` must carry/rebind trust route correctly; provider IDs/call arguments are correlation data, never proof or grants.
- **LangChain/LangGraph:** trust checked on protected tool, **not** on arbitrary callback/tracing side effects, which remain outside the gateway; docs must be explicit.
- **HTTP:** bind fixed route/CA config and any supported pinned endpoint identity, but do not claim TLS authenticates service code; preserve no redirects/ambient proxies/unsafe URL parsing.
- **Process:** inspect/pin trusted absolute executable artifact bytes only if safely obtainable; reject unsafe path/symlink/cwd transitions where strict guarantee is claimed. Existing cancellation/cleanup path stays intact.
- **Docker/gVisor:** separate image tag from observed content/image ID, verify operator-required image identity using a bounded local mechanism if implemented; preserve runtime selection, isolation digest, no pull/host fallback and cleanup drain. Never assert gVisor enforcement merely because runtime flag says `runsc`.

### 9.4 Two integration strategies (select one and justify)

**Preferred:** an optional `TrustGuard`/`TrustAdmission` bound to `RuntimeGateway.call`, with only additive trust fields in `ExecutionBinding`/dispatch evidence when actually enabled. Preserve shared action construction and existing gateway decision path. Avoid callbacks that an untrusted caller can override.

**Alternative:** a protected registered-call wrapper with a strictly checked non-bypassable route and an explicit final check at the same critical dispatch boundary. If using it, demonstrate with tests that MCP and all other adapters cannot evade the guard by calling the gateway through a different path. A purely CLI check or pre-registration scanner **does not** satisfy the runtime enforcement exit criterion.

## 10. Evidence, replay, regression and conformance

### 10.1 Evidence minimization

Add only clearly named optional safe trust facts, such as approved lock digest, inventory generation/fingerprint, candidate qualified identity digest, verification status/method, failed requirement codes and trust decision ID. Include them in action/dispatch binding only where they change protected execution identity. Avoid raw manifests, descriptions, descriptions' text fragments, binary paths with secrets, PEM keys, URLs with credentials, env, headers, JWTs, tool arguments and package credentials. Existing `TOOL_DISPATCHED` continues to mean dispatch **attempted**, not integrity-attested effect. Preserve legacy omission of absent fields.

### 10.2 Replay and incident semantics

- Historical Phase 0–7 artifacts lacking trust facts remain readable, with `TRUST_UNKNOWN`/`INCOMPLETE` rather than `VERIFIED` or retroactive failure.
- Offline replay still never performs registry discovery, network/file trust lookup, key fetch, program execution or signature verification against running candidates. If offline signature checking of **supplied bytes** is supported, label it separately from runtime evidence.
- Extend (or supplement) `CandidateRouteManifest` with candidate trust metadata **only if the distinction can be represented faithfully**. `route_comparison` continues to mean route-identity comparison; add a separate trust comparison/verdict if needed. Do not silently redefine `UNCHANGED` route as trusted route.
- Regression promotion/incident classification may preserve minimized trust mismatch indicators. It never silently changes the approved trust lock or contract. Future strict readers get regenerated schemas; old reports preserve historical identities.
- Conformance coverage, if extended, must distinguish supported operator-provided trust requirements from unsupported external execution attestation; never report complete policy semantics based on static inventory alone.

## 11. Local CLI, examples and documentation

A compact `agentsec trust` namespace is recommended:

```text
agentsec trust inspect ... [--format text|json]  # create/read offline candidate inventory
agentsec trust scan <inventory> [--format ...]  # advisory deterministic findings
agentsec trust diff <reviewed-lock> <inventory> [--format ...]
agentsec trust verify <reviewed-lock> <inventory> [--keys <protected-keyset>] [--format ...]
```

CLI signatures are illustrative; adapt to actual constructors and avoid promising inspection of arbitrary live servers without a trustable observation source. A command named `pin` should **not** silently convert untrusted discoveries into approved lock material; if an explicit `lock propose` output exists, mark it `UNREVIEWED` and write with exclusive-create, requiring deliberate out-of-band operator promotion. Maintain established CLI exit-code conventions: meaningful nonzero for strict trust failures, stable output, no raw exception/data leaks; `--format json` canonical and predictable.

Add synthetic end-to-end examples: a pinned benign tool, a changed description/schema, a substituted process artifact, an unknown remote runtime, and a signature with known test-only key. Include an explicit operational step for guarding trust files outside the agent's edit authority. Update `AGENTS.md`, README, `docs/README.md`, `docs/architecture.md` appended phase section, MCP/adapter/evidence/replay/security-contract docs only where behavior changes. Do not rewrite historical phase reports; add `docs/supply-chain-trust.md` and `docs/reports/phase-8-implementation-report.md`.

## 12. Sequenced implementation workstreams

### W0 — Reconcile and baseline

Record HEAD, working tree and Phase 7 re-review gate; run tests/type/lint/examples. Draw an exact dependency map of descriptor metadata, MCP discovery, `ProtectedCall`, `RuntimeGateway`, approvals and replay projections. Inventory historical serialization/goldens affected by optional fields. **Deliverable:** short preflight ledger in report; no Phase 8 feature changes until interfaces are understood.

### W1 — Domain models and canonical trust projections

Add strict models, bounded inputs, stable qualified keys and domain-separated fingerprints with explicit raw-byte vs canonical-JSON distinctions. Build deterministic serializer, independent trusted lock reader and thorough golden property tests. **Deliverable:** local inventory and lock round trip + source-aware status representation.

### W2 — Inventory, dependency provenance and diffs

Adapt MCP discovery/Phase 7 protected registry snapshots without linking runtime to MCP types. Add operator-provided dependency data and safe local artifact inspection only for supported artifact kinds. Implement exact differential report, including absence/unknown/change. **Deliverable:** offline inspect/diff proves changes without executing tools.

### W3 — Trust verification and signature hook

Implement policy-owned expectations, non-upgrading trust status and narrow optional signature verifier. Exercise wrong-key/domain, missing/unknown artifacts and changed package/route. **Deliverable:** reasoned `TrustAssessment` and deterministic exit codes; no signature laundering.

### W4 — Static risk scanner

Build deterministic rule engine with bounded inspected text and provenance of findings. No LLM or network. **Deliverable:** useful advisory report and targeted negative tests.

### W5 — Shared enforcement integration

Add optional trust admission/final freshness guard in gateway and wire into `ProtectedCall` and MCP. Bind approved trust generation to action/approval/dispatch identity; no protected route bypass. **Deliverable:** changed/unknown strict candidate cannot request approval or dispatch; compliant route still needs ordinary policy/authority.

### W6 — Adapter/cancellation/mode compatibility

Exercise native/provider/LangChain/HTTP/process/Docker/MCP, SHADOW/DISABLED, mid-approval change, concurrent calls, startup race, cleanup failure, SDK mutation and historical fallback. **Deliverable:** broad regression evidence with honest unobservable-backend limitations.

### W7 — CLI, examples, docs, generated schemas and report

Publish one synthetic full workflow, update docs for actual guarantees only; regenerate JSON Schemas, run quality gates, compare diff, conduct self-review. **Deliverable:** review-ready commit and implementation report, no unrelated code churn.

**Implementation strategy:** each workstream may be committed separately. Keep scope narrow: a high-quality pinned local registry with **real enforcement** is preferable to a broad but decorative inventory service.

## 13. Non-negotiable security invariants

1. **Trust never expands authority:** `ADMITTED` does not imply `PolicyOutcome.ALLOW`; contract, task/delegation, approval, budget and flow restrictions still apply.
2. **Independent trust roots:** expected digests, signers, key material and trust requirements never come from agent args, discovered metadata or manifests under candidate control.
3. **No silent trust on discovery:** unknown/unlisted/changed candidate not admitted when strict lock is required.
4. **No metadata-equals-code claim:** schema/description pin is only metadata equivalence, not runtime semantics.
5. **No misleading cryptography:** hashes are unkeyed, signatures bind exact material and trusted keys, producer claims aren't attestation of execution.
6. **No false freshness:** snapshot/lock races invalidate exact approvals; weak host semantics downgrade proof/deny when required.
7. **Same enforcement core:** no duplicate PDP, approval broker, budget engine or provenance policy in registry/adapter code.
8. **No bypass through adapter rebinding:** provider/framework wrapping or unchecked raw MCP clients cannot reuse protected labels to dispatch as verified.
9. **No uncontrolled fallback:** strict trust failure, Docker/image failure and cancellation never fall back to host/unverified dispatch.
10. **No leak:** canonical events/reports do not expose secrets, request bytes, keys, raw descriptions or untrusted exception text.
11. **No hidden mutation:** pinned expectations are operator-reviewed, change needs explicit new generation, no auto-updated lock on verification.
12. **No regression of history:** absent fields remain absent; old contract/evidence/replay/regression hashes are unchanged unless a deliberate versioned semantic change is documented.
13. **Bounded offline inspection:** no network fetch, package installation, shell eval, remote schema resolution or tool invocation for inventory/scan/verify/diff.
14. **Report accurately:** incomplete verification, unsupported signer/protocol/backend and unknown actual effects remain visible, not converted into pass/fail fiction.

## 14. Failure codes, status behavior and compatibility

Proposed stable safe codes (refine/centralize, avoid leaking secrets): `TRUST_LOCK_INVALID`, `TRUST_TOOL_UNLISTED`, `TRUST_PIN_MISMATCH`, `TRUST_CANDIDATE_UNOBSERVED`, `TRUST_SIGNATURE_INVALID`, `TRUST_SIGNATURE_UNSUPPORTED`, `TRUST_RUNTIME_FRESHNESS_UNVERIFIABLE`, `TRUST_ADMISSION_REJECTED`, `TRUST_REGISTRY_STALE`, `TRUST_SOURCE_UNSUPPORTED`. Avoid raw third-party error string propagation; preserve original chain internally when safe.

ENFORCE rejects before approval/budget/dispatch for required trust failures. SHADOW reports would-block without stating that enforcement blocked a tool. DISABLED skips mandatory policy/trust denial while retaining transport/isolation invariants; if the existing mode behavior differs, document the actual behavior and test it rather than inventing a new one. Invalid supplied trust roots/lock must never silently degrade to permissive mode.

Maintain existing `schema_version: "0.1"` discipline with additive optional fields and precise omission of unset fields on old paths. Do **not** bump compiled `phase6-v1` or alter `effective_policy_hash()` for operational trust-only wiring. If changing authored contract semantics genuinely becomes necessary, stop and document versioning/migration separately; don't smuggle it in.

## 15. Independent conformance and attack-driven test matrix

Every case should have an assertion at the **actual effect boundary** (fake dispatcher counter, approval broker counter, budget/evidence snapshots), not just a model validation test.

| Test family | Required cases / expectation |
| --- | --- |
| Parsing/canonicalization | Unknown fields/versions, duplicate keys/IDs, excessive length/depth, invalid enum, unordered candidate sequence, Unicode/escape collision, null/empty distinctions; stable fingerprints. |
| Identity/keying | Identical tool names on distinct servers, tool renamed with same metadata, server replaced under same ID, namespace collision, stale candidate, accidentally unqualified lookup; never silently alias. |
| Metadata change | schema, description, declared side-effect/capability, upstream transport, resource binding, TLS config, isolation/image, package; appropriate versioned digest changes. |
| Trusted baseline | Candidate supplies expected SHA/key itself; untrusted replacement lock; tool description claims `trusted`; all ignored/rejected as trust roots. |
| Artifact bytes | Changed file with same version/path, symlink substitution, relative path traversal, non-regular file, oversize file, Docker tag updated with unchanged tag; no false verification. |
| Signature | Wrong key, modified payload, correct signature for different subject/domain, revoked/unlisted key, unsupported algorithm, stale/expired envelope; no `SIGNATURE_VERIFIED`. |
| Completeness | Missing dependency artifact, declared-only package, unknown upstream implementation; strict requirement rejects, report explicitly incomplete. |
| Scanner | High-risk action *with valid pin* still needs policy; harmless-looking unpinned tool is not admitted; suspicious instructions remain inert strings. |
| Runtime ordering | Strict reject before approval/budget/dispatch; both authorization deny and trust admit still deny; approval followed by trust generation/route change rejected; new approval required. |
| Race/concurrency | Simultaneous calls consistent snapshot, attempted update during approval, mutable post-registration SDK object, last-moment artifact change where checked; no stale approval reuse. |
| Mode truth | ENFORCE, SHADOW, DISABLED; missing/changed/unverifiable; accurate signal and no fake blocked dispatch in shadow. |
| Adapter spread | Native, OpenAI/Anthropic/Gemini-shaped, LangChain wrapped, HTTP, process/Docker and MCP; one policy/approval path and protected trust identity in each supported flow. |
| Transport/cleanup | MCP duplicate request IDs/pagination, no redirect/proxy inheritance, TLS pin behavior, process group cleanup, Docker `rm -f` drain, no host fallback on trust failure. |
| Evidence/privacy | No manifest raw bytes, user args, private keys, headers, secrets, URLs with credentials; only safe IDs/digests/status. Check error messages too. |
| Historical replay | Phase 5/6/7 recorded bundles replay and regress as before; absent trust → UNKNOWN/INCOMPLETE; never do network/filesystem/tool re-attestation during replay. |
| Reproducibility | CLI repeated runs byte-identical machine JSON (except intentionally excluded observations), inspection offline, generated schemas agree with models. |

Prefer focused tests in `tests/unit/test_supply_chain.py`, `tests/unit/test_trust_admission.py` and small integration tests (names adaptable). Use fake verifier/clock/dispatcher/registry/file reader and controlled tmp-paths; tests do not require production credentials, running Docker, network or external APIs. A Docker/runsc smoke test can remain an **optional** explicitly labeled operational verification.

## 16. Acceptance criteria (all mandatory unless noted optional)

Implementation evidence for the checked items is recorded in the Phase 8 report; these checks do
not constitute independent acceptance of Phase 7 or Phase 8.

- [x] Fresh, reconciled baseline recorded; Phase 7 acceptance gate status explicit.
- [x] Strict versioned schema for inventory, trust lock, verification report, diff and scanner findings; deterministic identities, unknown fields rejected, generated schema exports.
- [x] Tool/server/route fingerprint matches its **specified material** and is stable under irrelevant ordering; meaningful changes detected.
- [x] Local declared dependency manifest and coverage truthfulness: no fabricated resolved/digested dependencies.
- [x] Pinned key verification hook works with a real optional verifier or is explicitly reported as incomplete if not shipped; no implicit trust root.
- [x] Static risk scanner produces deterministic, explainable findings and cannot grant authority.
- [x] At least one complete protected MCP flow and one non-MCP Phase 7 flow demonstrate strict trust gate and zero side effects on failed admission.
- [x] All other relevant adapters covered by shared API or explicit tested/documented unsupported strict path; no silent bypass.
- [x] Approved trust generation changes action/approval identity; mismatch before dispatch fails without budget commit or dispatch; any limits on runtime freshness are stated precisely.
- [x] Mode semantics and error/event ordering preserved; existing policy/approval/identity/provenance safeguards do not weaken.
- [x] Old contracts, schema hashes, effective-policy identities, replay bundles, incident/regression manifests and generated examples remain compatible where fields absent.
- [x] Offline CLI workflow usable with synthetic fixture; protected lock promotion is deliberate rather than automatic.
- [x] Documentation, test matrix, self-review and detailed implementation report complete; exact verification evidence included.

**Non-blocking stretch, only after the above:** richer CycloneDX/SPDX import/export; broader local image inspection; optional additional signature scheme. These must not displace actual gateway trust enforcement.

## 17. Required security self-review before finalizing

Explicitly trace four cases end-to-end: (1) safe, correctly pinned tool; (2) policy-denied but trusted tool; (3) policy-allowed but substituted tool; (4) approval granted followed by changed trust generation. For each identify exact source of trust root, action identity, check point, evidence, budget/approval behavior, dispatch counter and observable residual risk. Try to find alternate entry points and provider/framework rebinding bypasses. Review every `await` between final freshness check and dispatcher entry, mutable alias, key substitution, downgrade path, parser sink, unprotected filesystem write, network side effect and error string.

Compare implementation against **both** the phase plan and broader PRD/architecture threat objectives. A passing planned test suite cannot excuse an unanticipated security bypass. Audit docs for misleading "signed", "trusted", "attested", "immutable", "verified" and "fail closed" assertions.

## 18. Verification commands

Run commands matching actual repo tooling; capture exact results and environment:

```bash
git status --short
git rev-parse HEAD
python --version
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
.venv/bin/agentsec examples validate
.venv/bin/agentsec eval examples
.venv/bin/agentsec regression run --root examples/regressions
.venv/bin/agentsec schema export --out schemas/generated
.venv/bin/python -m build --no-isolation
git diff --check
```

If `.venv` is unavailable use the documented project setup; record exact alternatives and missing optional extras. Additional targeted security tests and CLI smoke tests are mandatory. Never describe a command as PASS if it wasn't actually executed. Generated schemas should be diff-reviewed for accidental compatibility changes.

## 19. Implementation report and handoff requirements

Write `docs/reports/phase-8-implementation-report.md` with:

1. exact starting and final HEAD, tree cleanliness and Phase 7 review gate status;
2. architecture/different trust-level decisions and deviations from this plan;
3. file/API map and how registry snapshots, manifest, pins, signature verification and guard compose;
4. explicit policy-vs-trust truth table by enforcement mode;
5. cryptographic signed-byte projection and key ownership, if implemented;
6. cross-adapter and actual effect-boundary tests with negative cases;
7. precise raw-byte and endpoint/image/runtime verification limits;
8. schema and historical compatibility decisions;
9. all commands run, counts/results, environment caveats and tests not run;
10. self-review with discovered/fixed residual gaps;
11. known risks and deferred Phase 9/hosted/attestation work;
12. a concise independent-review readiness statement without self-certifying correctness.

Do not rewrite prior reports as if historical results changed. Leave unrelated worktree changes intact, and produce a focused reviewable commit(s).

## 20. Phase 8 exit principle

Phase 8 should give users an **inspectable, pinned, independently reviewed and enforceable** local tool inventory, with signatures and dependency provenance represented truthfully and with no claim that metadata proves runtime code execution. The same contract and gateway still decide **what may happen**; the new supply-chain layer restricts **which implementation candidates may be admitted**. That boundary is the foundation for later multi-agent trust in Phase 9—not an early implementation of it.
