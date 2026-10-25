# Agent Safety & Security — Phase 11 Detailed Implementation Plan

**Phase:** 11 — Enterprise Security Platform (bounded, self-hosted reference slice)
**Status:** Implemented bounded reference; independent acceptance pending. See the Phase 11 implementation report for deviations and verification.
**Repository:** https://github.com/jasonkli21/agent-safety-security
**Observed baseline:** `main` at `48ec4e6bc64a5cf8d0221884b3279743c994a405` (2026-10-25 UTC)
**Product authority:** `docs/prd.md` §16 Phase 11 and §§12, 17–19, 23, 25–26; `docs/architecture.md` §§3, 5, 9–18, 23–26 and Phase 9–10 appendices; `AGENTS.md`
**Operational authority:** `docs/managed-control-plane.md`, `docs/plans/phase-10-implementation-plan.md`, `docs/reports/phase-10-implementation-report.md`, `docs/security-contract.md`, `docs/contract-conformance.md`, `docs/evidence-model.md`, `docs/replay-incidents.md`, `docs/multi-agent-security.md`, `docs/identity-delegation.md`, `docs/supply-chain-trust.md`, `docs/runtime-mcp.md`.

> This plan authorizes no production deployment, live database migration, GitHub write or acceptance declaration. Baseline includes Phase 10 review corrections F10-01–04, but independent Phase 10 review remains pending. Phase 7–9 independent acceptance is also unconfirmed. Inspect actual HEAD, worktree and any newer findings before implementation; treat inherited review gates as open.

## 1. Objective and honest enterprise scope

Deliver an executable, optional, locally runnable **enterprise governance and evidence reference** on top of the Phase 10 control plane. It should let an operator:

1. exchange a signed policy candidate between explicitly trusted organizations, then import it as a **local DRAFT** requiring recipient-side independent review;
2. run a bounded **finite policy-impact projection** for selected enrolled agents, preserving unknowns and unsupported semantics;
3. triage a tenant-scoped metadata-only incident and record an independently approved, expiring **risk acceptance**;
4. export minimized, tenant-scoped governance, incident and posture observations to **offline SIEM JSONL**, plus a cryptographically signed export manifest verified with an independently pinned public key;
5. run, back up, restore and diagnose a **single-instance private reference deployment**, with measurable recovery and an operator support/runbook template.

The PRD also names support/SLA. Deliver support procedures and proposed SLO measurement criteria, **not** a contract, a staffed support promise or a claim of production-grade availability. Cover all Phase 11 roadmap labels while being candid about bounded implementation. No live enterprise cloud, external IdP, SIEM, model service, production credentials or remote peer is required by the reference demo/tests.

### 1.1 Existing implementation to preserve

The current `src/agentsec/control_plane/` implements `team-v1`: pinned externally issued Ed25519 JWTs, separate HUMAN/SERVICE/REPORTER identities, live DB membership checks, org-qualified SQLite `user_version=1`, immutable reviewed `phase6-v1` contract revisions, CAS publish, minimized RUNTIME/CI reports, receipts, audit, and **REPORTED_UNVERIFIED** posture. Key entry points are `models.py`, `store.py`, `service.py`, `auth.py`, `policies.py`, `metadata.py`, `api.py`, and `cli/team.py`. The API is `/v1/orgs/{org}/...`; CLI `agentsec team init/provision/serve/posture`. Existing compiler identities are `document_hash`, `effective_policy_hash`, `compiled_plan_digest`; `semantic_diff`, conformance and coverage are finite/synthetic.

Phase 10 report records 103 focused control-plane/projection tests passing following corrections, but the full suite in that environment was **974 passed and 11 setup errors** from denied localhost socket binding. This is not a green full suite, and the implementation report is not independent acceptance. Re-run and classify tests accurately under the Phase 11 environment.

### 1.2 Nonnegotiable architectural invariants

- Local `RuntimeGateway`, protected compiled plans, Phase 6 identity, approvals, Phase 7 isolation, Phase 8 trust admission and Phase 9 `MultiAgentSession` retain final enforcement authority. Enterprise features cannot change running grants, perform remote activation, auto-roll out policy, enroll graph peers, mint runtime identities or loosen an approval. Existing runtime works offline with control plane/signing/SIEM unavailable.
- Federation may influence **what an authorized human reviews**; it cannot become remote policy authority. Trust keys, mappings, source selection and deployment remain protected operator inputs, never model/tool/message- or bundle-provided permissions.
- A signed artifact authenticates **the bytes and signer key**, not truth of agent self-reporting, verified runtime effects, a secure host, or tamper-evident SQLite. No generic “attested secure” result.
- Incident/risk/SIEM paths accept strictly allowlisted opaque IDs, enums, counts and timestamps. Never accept raw `SecurityEvent`, prompts, tool arguments/results, full replay traces, bearer tokens, emails, URLs, secrets, arbitrary descriptions or source documents. **Federation export is an explicit, separate source-sharing action** and must never run as telemetry.
- `team-v1` and historical `0.1`, `phase6-v1`, `phase9-v1` semantics remain stable; new wire families are explicit `enterprise-v1`. Generated schemas derive from typed models, never hand-edited JSON.
- No default outbound networking or public listener. Preserve Phase 10 loopback restriction absent a separately designed and tested TLS/proxy boundary. No enterprise workflow suppresses underlying unknown/failed CI, replay, posture or policy results.

### 1.3 Vocabulary / assurance labels

| Feature | What may be claimed | What must **not** be claimed |
| --- | --- | --- |
| Federation | Signature and explicit pinned peer/source/target trust checked, candidate locally recompiled | Origin review is recipient authorization; signed bundle auto-activates |
| Evidence signature | Authenticity/integrity of exact signed canonical export | Runtime/host attestation, truthful effect or tamper-proof DB |
| SIEM | Minimized offline JSONL with replayable record identity and known snapshot bounds | Exactly-once remote delivery or content-secret detection |
| Incident | Audited, versioned central workflow referencing limited metadata | Verified root cause, raw forensics stored centrally |
| Risk acceptance | Expiring governance decision with separate approver | Policy exception, green score, suppression of failure |
| Fleet simulation | Deterministic finite compiler/diff comparison and per-agent applicability | Model/trajectory forecast or proof of deployed state |
| Private reference | Single-node tested setup/recovery and stated limits | HA, public SaaS, certified compliance or SLA |

## 2. Threat model and trust ownership

| Surface | Trust owner | Attack vectors | Required behavior |
| --- | --- | --- | --- |
| Team HTTP and workflows | Pinned external JWT, current org membership, role, subject kind | Forged/stale tokens, cross-tenant IDOR, role spoofing, actor revocation | Reauthorize at read/mutate/commit; tenant-qualified lookup and error responses |
| Federation | Offline operator-pinned partner key + origin/target/policy scope | Malicious sender, replay/downgrade, altered source, wrong target, unsigned key override | Deny before import; local immutable draft only |
| Signing and exported bytes | Operator-controlled signing key separate from JWT issuer | Algorithm confusion, ambiguous serialization, swapped manifest, key rotation | Domain-separated Ed25519 canonical signing; verify exact bytes and independent pin |
| Reports/SIEM | Tenant-scoped strictly allowlisted projection | Raw payload injection, reporter-encoded data, export path traversal, cross-org cursor | Minimize and bound, atomic private output, preserve unverified assurance |
| Incident/risk | Server-side org membership, independent role, CAS and audit | Self approval, stale close, expired exception, scope switch | Reject or conflict; never rewrite runtime/CI verdict |
| Simulation | Immutable source, current publication and protected inventory | Stale policy, spoofed loaded-plan report, unsupported semantics, resource exhaustion | UNKNOWN/BLOCKED, short lock, bounded cohort, no activation |
| Persistence/deployment | Protected SQLite/config/key files, explicit migrations | Untrusted restored files/sidecars, crash, concurrent writers, corrupt schema | Fail closed, consistent backup/migration, no silent mode relaxation |

Threats **not solved** include dishonest signing issuer/operator, compromised private signing key, malicious host administrator, malicious reporter covert channels within allowed fields, power-loss durability under every filesystem, or actual remote SIEM/network availability. List these separately from tested properties.

## 3. Technical design and workstreams

Build small typed enterprise modules (suggested `src/agentsec/enterprise/{models,signatures,federation,simulation,exports,workflows}.py`) while preserving `control_plane` as the tenant authentication, service, API and SQLite owner. New CLI commands live under `agentsec team ...`; avoid an unrelated orchestration framework, second PDP or general query engine. Keep core domain, compiler and runtime imports free from team/enterprise dependencies.

### W0 — Baseline, design lock and protocol

1. Inspect latest repository + dirty tree; read PRD, architecture, Phase 10 report/corrections, focused docs and tests. Check pending independent review findings and stop/reconcile if they affect Phase 11 trust boundaries.
2. Before substantial implementation, create `docs/enterprise-security.md` with trust/dataflow diagram, key purposes, role matrix, record/state schemas, bounds, failure codes, migration plan, assurance claims and unsupported features.
3. Reuse strict Pydantic `SecurityModel` conventions: reject unknown fields, duplicate JSON keys and coercion; bounded ASCII identifiers, UTC timestamps with ordering, capped collection sizes, finite counters and deterministic serialization. Prefix all new external formats `enterprise-v1`.
4. Specify canonical JSON **bytes** (normalized representation, UTF-8, field order, exclusion of signature, no duplicate fields), domain-separated messages `agentsec:enterprise-v1:federation\n` and `agentsec:enterprise-v1:export\n`, key/purpose enums and exact digest algorithms. Preserve distinction between normal hashes and signatures. Fixed vectors must be independently reproducible.

**Gate:** signer, verifier, trust pin, storage, tenant, role and runtime separation defined unambiguously.

### W1 — Typed storage, RBAC and explicit migration

- New narrowly scoped record kinds: enterprise incident, transition/idempotency, risk acceptance, federation replay high-watermark and optional export checkpoint; model caps, org-qualified keys/indices and explicit CAS. Prefer extending `ScopedStore` rather than unscoped raw SQL spread across endpoints. `Store.transaction()` remains single-instance; every mutation and audit row commit atomically.
- If schema changes are needed, introduce `user_version=2` with **explicit offline** `agentsec team migrate` or equivalent. Refuse unknown versions and do not auto-upgrade on `serve`. Preflight regular non-symlink owner-private DB/WAL/SHM using existing POSIX checks, require safe consistent backup, run transactional upgrade and integrity verification, preserve v1 data and fail/rollback on error. Windows existing-DB admission remains unsupported until genuine ACL checking exists.
- Scope protected identity and memberships exactly as Phase 10. Define new role-per-operation permissions: OWNER can administer exports/trust and approve risk; EDITOR can open incidents/request risk/simulate; REVIEWER can review/resolve according to explicit matrix; VIEWER read-limited; SERVICE remains narrowly read-only; REPORTER can never manage enterprise records. In particular, bulk export and federation import are **not implied by ordinary VIEWER permission**. HUMAN-only for review/risk acceptance.
- Stage expensive parse/sign/simulation/export operations **outside** the `BEGIN IMMEDIATE` global lock. Reauthorize and CAS-check actor permissions, object versions, source and publication generation before commit/return. Short transactions and no non-tenant-scoped leakage in errors/pagination.

**Gate:** v1→v2/fresh-v2/restart/rollback tests, revoked actor, two-org IDOR and two-connection CAS pass; Phase 10 behavior preserved.

### W2 — Signed offline policy federation

**Contract.** A strict FederatedPolicyBundle contains enterprise-v1, origin org, intended target org, origin policy key and immutable revision, optional explicit recipient mapping, phase6-v1 compiler, document_hash, effective_policy_hash, compiled_plan_digest, source UTF-8, issue/expiry times, bounded monotonic peer sequence, key ID/purpose, digest and Ed25519 signature. Signature covers **origin, destination, identities, sequence, times and source** via one canonical byte sequence. Bound source, parser cardinality and envelope size. No issuer private keys, JWTs, origin approval votes, capabilities or deployment instructions.

**Trust.** Operator-owned FederationTrustConfig (protected local file, empty by default) pins origin, destination, source policy key, permitted local policy key, key ID, public key and validity/revocation epoch. Never use bundle-provided keys, dynamic JWKS or team JWT keys as implicit federation trust. Verify envelope, size, schema, destination, signer purpose, signature and time **before parsing untrusted source**. Locally parse/recompile phase6-v1, recompute all three identities and reject unsupported semantics/mismatch.

**Workflow.** An authorized recipient HUMAN Editor/Owner explicitly imports into a new immutable **local DRAFT**. Store provenance separately from authority. Recipient submit → independent review → publication stays mandatory; importer cannot self-review. Exact same digest/sequence/local-ID retry is idempotent; altered same-sequence and lower/replayed sequence after later acceptance conflict. Peer sequence high-watermark is scoped by recipient org and origin/policy; key rotation does not reset replay protection. No remote publish, local pin, automatic trust, graph enrollment, cross-tenant read or membership union.

**Surface.** Prefer offline agentsec team federation export/import/verify, with explicit identity, source, destination, trust and signing-key paths. If an authenticated import API is needed, apply identical role, parsing and body bounds. Private signing keys are CLI inputs, never persisted in team SQLite or exposed in HTTP. Refuse unsafe symlink/world-readable key/output paths; write files privately/atomically; never echo source/private keys in error text.

**Tests:** two real tenant contexts and recipient review; tampered bytes/hash/target/sequence/key/purpose, untrusted partner, invalid/expired time, unsupported compiler, duplicate JSON key, stale replay, conflicting import, signer rotation and membership revocation; runtime unchanged.

**Gate:** signed candidate round trip and negative matrix, with no authority transfer.

### W3 — Incidents and risk acceptance

Keep Phase 5 domain Incident and RegressionCase unchanged. New team IncidentCase has org-scoped case ID, finite same-org references to opaque agent/run/receipt IDs and optional customer-side incident/bundle digest marked UNVERIFIED_REFERENCE, fixed category/severity, assignee identity, state, expected version, timestamps and minimized transition history. No arbitrary narrative, link, email, script, tool argument, full trace or policy source. Verify same-org references server-side if known; never dereference supplied digest into central sensitive content.

Finite workflow: OPEN → TRIAGED → MITIGATING → RESOLVED → CLOSED; deliberate REOPEN returns to OPEN; DISMISSED requires explicitly authorized disposition. Require enumerated resolution and **independent HUMAN closure for high-severity cases**. Define individual role rights: VIEWER/SERVICE read-only; EDITOR can open/triage with bounds; REVIEWER can independently resolve; OWNER can close/reopen/manage. Check active roles/assignee at mutation, legal source state, exact expected version, CAS and audit; same retry returns same result, changed retry conflicts. Never assert remediation verified from a status transition.

RiskAcceptance is separate: exact org and incident or policy revision + optional agent/environment; objective reason enum and bounded non-sensitive justification code (not prose), requester, distinct current HUMAN OWNER approver, version, request/decision timestamps, expiry (recommend maximum 30 days), and REQUESTED/APPROVED/REJECTED/REVOKED states with computed EXPIRED or STALE effectiveness. Verify target scope/status at approval; requestor cannot self-approve, requester/approver cannot edit approved object, expired/withdrawn/superseded targets lose effective acceptance, and renewal is a new independently reviewed record.

Risk acceptance is shown **beside**, never in place of, underlying advisory posture flags and REPORTED_UNVERIFIED, incident severity and CI/replay/regression failures. It does not alter PolicyDecision, runtime approval, publication checks, signed evidence, or CI exit code. Closing a case does not prove the actual risk disappeared.

**Tests:** cross-tenant IDOR, forged/disabled roles, revoked assignee, stale version/concurrent retry, invalid transition, audit rollback, high-severity self-closure, self risk approval, exact expiry boundary, target supersession/revocation, and unchanged local DENY/CI FAIL/SHADOW flags during an active acceptance. Secret/raw canaries absent from DB/API/export/log.

**Gate:** independent authorization and expiration affect governance only.

### W4 — Bounded fleet policy-impact projection

Add read-only simulate operation on immutable candidate revision + selected enrolled inventory. This is **finite policy simulation**, not a live agent/model replay. Reuse control_plane.policies.assess, compile_contract phase6-v1, semantic_diff, run_conformance and coverage_report with current parser/semantic limits. Compare to current published source where possible. Do not trust a reporter policy_revision to prove loaded bytes.

Input: target org, candidate revision, policy key, expected publication generation, optional bounded explicit agent IDs (e.g. ≤100). Under current authorization snapshot exact source/assessment, publication and selected inventory IDs/versions in a short transaction. Perform shared candidate/baseline compile/diff **outside** the global SQLite write lock (not per-agent compiler work); then reauthorize and verify candidate bytes/identities, publication generation and affected inventory versions before returning/persisting. Stale snapshots must conflict or explicitly invalidate results.

Output FleetSimulation carries plan identities, conformance/coverage gaps, finite difference categories RESTRICTIVE/EXPANSIVE/MIXED/UNCHANGED/UNCLASSIFIED, and each agent COMPARED/UNKNOWN/INELIGIBLE with reason. Eligible requires protected configured expected revision/plan alignment; reported labels alone do not qualify. Missing/stale/withdrawn baseline, unsupported atoms, Phase 9 graph semantics, no comparable plan or unknown diff must be UNKNOWN/UNCLASSIFIED, never safe. Cosmetic document-only diff stays distinguishable from semantic change. No model prediction, actual loaded-policy proof, effects, score, auto-publication or rollout.

Bound cohort, parser work, output bytes/time and concurrency. Prefer ephemeral results; if stored, keep only minimized digest/status metadata with expiry. Never insert candidate policy body into telemetry.

**Tests:** expansion/restriction in permissions, identity, approval and budgets; cosmetic vs semantic; missing baseline, wrong configured plan, disabled agent, unsupported atoms, malicious candidate, stale generation and actor revocation during assessment, cross-org cohort, concurrent other-tenant read, no dispatch/network.

**Gate:** deterministic finite impact plus explicit uncertainty; simulation does not participate in PDP/PEP.

### W5 — Offline SIEM export and signed evidence

Create strict EnterpriseSecurityRecord allowlist from org-scoped audit metadata, incident/risk transitions and selected minimized report/posture fields. Fields: event time, opaque actor/asset/correlation IDs, action/type/severity/outcome, assurance label GOVERNANCE_RECORD versus REPORTED_UNVERIFIED, record kind, enterprise-v1, stable record fingerprint and tenant-relative export sequence. No full SecurityEvent, revision source, free-text review body, JWT, email, resource/argument/result, raw replay, arbitrary labels or URLs. Explain that malicious reporters may still encode data in UUID/count channels; allowlisting minimizes rather than proves secrecy.

Agentsec team export siem writes deterministic, bounded JSONL to an explicit private local destination. Obtain a consistent tenant-scoped snapshot in short transaction, with stable ordering/pagination and an org + filter/format-bound high-watermark/checkpoint. Serialize/sign/write **outside** global write lock. Disclose expired/purged gaps; never fabricate missing rows. Use private adjacent temp file + fsync/atomic rename as practical; refuse symlink/unsafe overwrite and leave no falsely complete artifact after interrupted write. Downstream ingest is at-least-once with stable record dedupe, not exactly-once delivery.

Sign separate EvidenceExportManifest containing org, record classes, interval/sequence bounds, count, exact JSONL byte length/SHA-256, schema/format, issuance, signer key ID/purpose, signature. Canonicalize manifest and use **export-specific Ed25519 domain** distinct from federation. Offline export verify independently pins public key, recomputes bytes/digest and signature, and emits verified/invalid/unsupported status. Unsigned outputs remain labeled UNSIGNED. Key stays outside DB/HTTP/logs. Provide a versioned generic SIEM field mapping and offline validation example, not an outbound connector by default.

**Tests:** golden canonical/signature vectors, altered/reordered/truncated/appended JSONL, switched manifest/org/key/purpose, malformed encoding/duplicate key, unknown/revoked key, content canaries, cross-org export, cursor replay/purge gap, concurrent update/write fault, deterministic rerun, unsafe path, no source/token in errors.

**Gate:** exact signed-byte provenance and minimized SIEM output, with truthful assurance.

### W6 — Private deployment and support

Provide optional reproducible single-node local deployment: pinned/controlled build, nonroot process, protected config/public-key and SQLite volume, signing key offline from server, loopback service default, no credential/access logs, safe health semantics, bounded body/time/concurrency, graceful shutdown, zero default egress. If private remote network listener is added, require separately tested TLS/proxy/forwarded-header trust, network isolation, authentication and rate limits; otherwise keep remote exposure unsupported. Never silently permit 0.0.0.0.

Runbook: init → explicit migration with backup → keys → serve → observe → SIEM export → consistent backup/restore → rotate/revoke signing trust → repair incomplete export/federation → membership revocation → rollback. Protect DB, WAL/SHM and parent directories. Reproducible backup/restore/failure-injection smoke; report actual recovery measurements, not invented RTO/RPO. Include proposed SLO signals (availability, error rate, export lag, time to recover, signature failures), operator support triage/escalation checklist and evidence-collection guidance; explicitly **no commercial SLA, HA or compliance certification**.

**Gate:** credential-free private demo works; key/storage failures fail closed; offline runtime remains functional.

## 4. Interfaces, resources and sequencing

Prefer adding strictly modeled endpoints beneath /v1/orgs/{org}/enterprise/... for incident/risk and read-only simulation operations. Keep existing team-v1 routes exactly compatible. A federation-import HTTP route is optional and must reuse verified human identity and local draft permissions; offline signing/export and private-key handling must remain CLI-only. A signer/private-key HTTP upload route is explicitly forbidden. Produce a precise endpoint/role/request/response/status-code table in docs/enterprise-security.md before adding routes. Validate JSON bodies, duplicate keys, unknown query parameters, pagination, maximum bytes, content type and timeouts at ingress.

Use specific stable codes (existing TOKEN_INVALID, DENIED, NOT_FOUND, CONFLICT, INVALID_INPUT, STORE_UNAVAILABLE plus narrowly defined SIGNATURE_INVALID, TRUST_UNAVAILABLE, MIGRATION_REQUIRED, SIMULATION_UNSUPPORTED if necessary). Do not confuse security denial with malformed input or surface parsing/source/key/token content in an error. Tenant absence should not enable cross-org enumeration. Bind any approved export/case read to an explicit permission beyond generic VIEWER read when its disclosure is broader. Current membership, kind and token expiry must be rechecked during every transaction, including retried transitions.

Work should proceed in this order:

| Order | Workstream | Concrete proof before next step |
| --- | --- | --- |
| W0 | Baseline and design lock | Architecture/roles/keys/canonical bytes/threat table approved in focused doc |
| W1 | Storage, strict schemas, RBAC, migration | v1 data preserved through opt-in v2 migration; tenant and CAS tests |
| W2 | Federation + signature core | Pin/verify/import DRAFT; replay, tamper, rotation and review separation tests |
| W3 | Incident + risk workflows | Independent decision, expiration and unsuppressed failures; rollback |
| W4 | Fleet finite comparison | Stale source/version, unsupported atoms and no-write-lock analysis tests |
| W5 | Signed minimized SIEM export | Exact-byte verifier, no raw input, scoped cursor and failure-safe output |
| W6 | Private single-node demo + runbook | Secure defaults, backup/restore, no real secrets, offline runtime |
| W7 | Regression, docs and report | Full reproducible quality evidence and review-ready handoff |

Keep modules small and typed, use existing dependencies where justified (cryptography already present with PyJWT extra), avoid new generic plugins, distributed stores, background fleet queues and future Phase 12 placeholders. Use reviewable commits where practical but no push/PR/deployment without separate authorization; preserve unrelated files.

## 5. Mandatory adversarial acceptance matrix

Create fixed-clock, synthetic-key, temporary-private-SQLite tests at the unit, service, API and file/CLI layers. Tests should exercise **actual authorization/SQLite transaction paths**, not only model validation.

| Domain | Positive case | Required adversarial cases |
| --- | --- | --- |
| Federation | Two orgs, pinned signing peer, signed source imported to recipient DRAFT and independently reviewed | Alter source/digest/scope/destination/key/purpose/timestamp/sequence; forged algorithm; unknown peer; replay/race; duplicate JSON field; unsupported compiler; no local activation |
| Signed export | Canonical fixed vector signs, verifies exact file and source/key manifest | Reorder/truncate/append/edit records, manifest swap, wrong org/key/domain, revoked key, untrusted embedded public key, SHA-only forgery |
| SIEM privacy | Scoped JSONL record set + deterministic mapping and checkpoint | Raw prompt/tool args/token/source canary, oversized row, cross-tenant IDs, cursor reuse, purge gap, partial write/retry, no default outbound traffic |
| Incident workflow | Legal triage/resolve/close/reopen and minimized audit | Editor high-severity self-closure, changed retry, stale version, revoked assignee, unknown/cross-org reference, invalid transition, transaction fault |
| Risk acceptance | Distinct OWNER approval with exact target and expiry | Same actor self-approves, forged role, superseded target, timezone/expiry, unauthorized renewal, effect on runtime deny/CI FAIL/alerts |
| Simulation | Cosmetic and substantive finite diffs, cohort with one eligible and one unknown | Unsupported atom, missing/stale policy, wrong expected plan, reporter spoofed loaded revision, cross-org agent, concurrent mutation/revocation, oversized cohort, no execution |
| Store/migration | v1→v2 with real data, new v2 init, restart, consistent backup/restore | Unknown/corrupt DB, symlink/unsafe WAL, concurrent opener, partial migration, injected exception, cross-tenant leakage |
| Prior phases | Default installation and Phase 10 flows work; runtime works with team unavailable | No enterprise artifact becomes Phase 6 credential, Phase 8 trust pin, Phase 9 graph member, runtime approval or compiled security plan |
| Operational | Single-node synthetic demo, locked-down paths, safe health/recovery | Nonloopback insecure bind refused, private key/log leak, unexpected egress, absence of container/runtime explicitly reported if unavailable |

Include role-by-endpoint negative cases and property/golden tests for canonical encoding, signature purpose separation and data minimization. Fuzz reasonably bounded parsers. For performance, prove compilation/signing/export happen outside SQLite shared write lock and that per-agent processing is bounded; do not claim large-fleet scale without benchmark.

## 6. PRD traceability and acceptance criteria

| Phase 11 PRD capability | Required delivered slice | Must stay unsupported/qualified |
| --- | --- | --- |
| Policy federation | Signed offline bundle, protected peer pin, target scope, recipient DRAFT + normal review | No automatic remote sync, rollout, cross-org RBAC |
| SIEM export | Deterministic privacy-filtered JSONL, versioned mapping and retry/dedupe story | No live SIEM service, exactly-once remote delivery |
| Incident workflows | Auditable metadata-only case lifecycle, references and independent severe closure | No automatic detection/remediation or raw centralized trace |
| Private deployment | Reproducible hardened single-instance private setup and restore drill | No HA, public exposure by default or certification |
| Signed attestations/evidence | Signed export snapshot with pinned offline verifier and explicit assurance type | No TPM/TEE/running-code verification or tamper-evident SQLite claim |
| Fleet policy simulation | Finite candidate/current policy comparison and per-agent unknown/eligibility | No model/tool execution, effect proof or real deployment forecast |
| Support/SLA | Operator runbook, support escalation template and measurable sample SLOs | No contractual SLA or staffed support claim |
| Risk-acceptance workflow | Independent, expiring, scoped and non-suppressive governance decision | No exception to PDP/runtime approvals/review checks |

### End-to-end demo

Synthetic two-org local fixture should show: separate externally signed human roles; pin an offline federation signing key; export a candidate from alpha to beta; reject a wrong-destination/tampered bundle; import correct candidate as DRAFT; inspect finite beta fleet projection with at least one explicitly UNKNOWN agent; recipient independent review/publish; open and triage metadata-only case; approve then expire an independent risk acceptance with underlying CI/posture issue still visible; emit minimized SIEM JSONL, sign and verify, then modify one byte and fail verify; stop team service and still demonstrate local RuntimeGateway/graph enforcement using the existing offline example. No actual deployment, remote keys, live SIEM or model calls.

### Quality gate

Run and report **exact commands and real results**:

- Focused new enterprise/unit/integration tests and preexisting Phase 10 control-plane tests.
- Entire local pytest suite, with environment-specific socket permission failures distinguished from real regressions; repeat network-dependent subset in appropriate environment when feasible.
- Ruff lint and format checks, mypy strict source checks, package build and wheel/sdist import with and without optional control-plane/enterprise dependencies.
- Schema export regenerated from models and drift comparison; examples validate, relevant evaluation/regression demos and Phase 9 graph demo.
- Synthetic two-tenant enterprise demo, migration/rollback/backup verification, deterministic cryptographic vector verifier, privacy canary search, no-default-egress assertion.

All new security validators need invalid/unknown/duplicate/stale negative fixtures. Preserve backwards compatibility and fully credential-free standard CI. Do not equate an author-run green suite with security acceptance or claim tests impossible to run.

## 7. Documentation, non-goals and stop conditions

Update docs/enterprise-security.md, docs/managed-control-plane.md (additive interactions), docs/README.md, README.md, AGENTS.md current-boundary line, examples/team/ documentation, generated schemas and architecture appendix for enduring changes only. Do not rewrite PRD to rationalize an implementation shortcut. Sweep older phase docs and reports for contradictory descriptions and preserve historical status; document changes without implying retroactive completion. Separate capability status IMPLEMENTED_REFERENCE / ADVISORY_ONLY / UNSUPPORTED / NEEDS_INDEPENDENT_REVIEW.

Outside Phase 11: hosted SaaS/HA/multi-region/distributed SQL; cloud billing, scheduled fleet jobs and arbitrary analytics; public networking without verified TLS/proxy model; automatic federation, policy rollout/activation, runtime signing/TPM attestation; arbitrary SIEM integrations and outbound webhooks; automated incident response, external ticket integrations, broad secrets manager; arbitrary policy merger, agent-learning/Phase 12 adaptive recommendations; contracts/SLAs, certification and 24/7 operations.

If sound key ownership, cryptographic serialization, tenant isolation, persistence, source privacy or fail-closed policy behavior cannot be achieved, **stop that feature and mark unsupported**; never ship permissive fallback disguised as a Phase 11 feature. Do not silently delete unrelated work, migrate live data, expose a network listener, publish a PR or contact external services.

## 8. Required implementation report

Produce docs/reports/phase-11-implementation-report.md with:

1. exact start/end SHA, git status/branch, authorization scope and any baseline drift; Phase 7–10 unclosed independent-review gates;
2. PRD/architecture/focused-doc traceability and delivered-vs-deferred capabilities;
3. full trust/keys/canonicalization/signature lifecycle, federation import and nonactivation model;
4. tenant/RBAC matrices, typed APIs/CLI/schema, storage migration/recovery/rollback and CAS/concurrency design;
5. incident/risk states and statuses, fleet projection assumptions/unknowns, privacy and SIEM schema/export/verification;
6. threat matrix mapped to named tests with negative results, unverified assumptions and unsupported environments;
7. exact test/lint/type/schema/build/demo commands and outputs, package versions and environment limitations;
8. private deployment, backup/restore, key rotation, output durability and throughput/latency/recovery measurements;
9. docs staleness sweep, deviations, residual risks and next-phase recommendations;
10. **readiness for independent review only**, never unearned release acceptance or production/SLA claim.

No GitHub push, PR, cloud deployment, real IdP, live migration or external message is authorized by this plan.
