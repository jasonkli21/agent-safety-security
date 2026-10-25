# Agent Safety & Security — Phase 10 Detailed Implementation Plan

**Phase:** 10 — Managed Team Control Plane (bounded reference implementation)
**Status:** Bounded reference implementation complete; independent review pending (see `docs/reports/phase-10-implementation-report.md`)
**Repository:** https://github.com/jasonkli21/agent-safety-security
**Planning baseline:** `main` at `6dfa0d56057c3bcf85bb9fc070ea1e43491899ef` (Phase 9 review fixes, 2026-10-25 UTC)
**Roadmap authority:** `docs/prd.md` `16 (Phase 10), ``12, 17–19, 23, 25–26
**Architecture authority:** `docs/architecture.md` ``3, 5–6, 9–11, 13–18, 23–26 and Phase 3–9 appended decisions
**Current operational sources:** `AGENTS.md`, `docs/multi-agent-security.md`, `docs/identity-delegation.md`, `docs/security-contract.md`, `docs/contract-conformance.md`, `docs/evidence-model.md`, `docs/replay-incidents.md`, `docs/supply-chain-trust.md`, `docs/runtime-mcp.md`, `docs/reports/phase-9-implementation-report.md` and `docs/reports/phase-9-review-fixes-report.md`.

> This plan authorizes no deployment, credentials, production tenant onboarding, GitHub write, or independent acceptance. At the planning baseline, Phase 9 is implemented and review fixes are present but **fresh independent Phase 9 acceptance remains unconfirmed**. Phase 7–8 independent acceptance also remains unconfirmed. Treat these as inherited release gates, not as reasons to silently discard the requested Phase 10 plan.

## 1. Outcome and calibrated phase boundary

Deliver an **optional, locally runnable/self-hostable control-plane reference service** that demonstrates the central Phase 10 value: a team can review immutable security contract revisions, explicitly publish a reviewed version, enroll agents into an inventory, ingest carefully minimized run/CI metadata, and inspect organization-scoped posture without moving the enforcement boundary out of the customer runtime.

The Phase 10 PRD names organizations, RBAC/SSO, shared policy registry, review workflow, centralized inventory, hosted evidence metadata, dashboards/alerts, CI integration and fleet posture. Cover each in a narrow, functioning vertical slice. A minimal JSON API and CLI/text posture dashboard satisfy the first Phase 10 surface; production cloud hosting, graphical UI, email/pager integrations and enterprise operations are **not claimed**. Make the distinction explicit in documentation and acceptance.

**Non-negotiable product invariant:** existing `agentsec` contract compilation, local policy decision, approvals, Phase 7 adapters/isolation, Phase 8 trust admission and Phase 9 graph decisions must work with zero control-plane availability and no new default dependency. A publication is governance metadata, not authorization. It must not mutate a running `RuntimeGateway`, grant a capability, enroll a graph peer, supply a trusted identity, or bypass local operator pins/approval. No automatic remote policy activation.

### 1.1 Baseline reality

- Python 3.12+, Pydantic v2, Typer, YAML/jsonschema; optional `identity` extra uses pinned-key PyJWT; optional `mcp`/`trust`/`langchain` extras. No web service/database/control-plane modules currently exist.
- CLI entry point is `src/agentsec/cli/main.py`; immutable compiled plan in `src/agentsec/compiler/models.py` with explicit `document_hash`, `effective_policy_hash` and `compiled_plan_digest` identities.
- `compile_contract(contract)` defaults to `phase6-v1`; Phase 9 requires explicit `multi_agent=True`, `phase9-v1` and protected local session enrollment.
- `SecurityEvent` is a privacy-minimized local domain artifact, but still **not automatically safe to upload in full**. `EventSink` and JSONL evidence are local.
- Phase 9's `MultiAgentSession` and graph replay have one-event-loop, single-epoch, protected-configuration limitations. Managed inventory is not agent-to-agent identity verification.
- The main CI workflow runs tests, lint, type-check, examples and build without external credentials. Preserve this property.
- `AGENTS.md` currently labels Phase 9 the active boundary. Implementation may update the status line to accurately describe an explicit Phase 10 opt-in reference slice, while preserving all older limitations and open review gates.

### 1.2 Planning assumptions and stops

1. Start from current `main`; inspect git status, commit and documentation before implementing. If newer work changes the contract/identity/evidence surface, reconcile this plan rather than overwriting it.
2. Keep release and test gates distinct: test passes do not mean security review acceptance, and Phase 10 self-review does not close Phase 7–9.
3. Use production-style trust boundaries even in a local demo: strict request schemas, safe defaults, bounded payloads, transactional state, explicit authentication/authorization.
4. If sound SSO verification, persistence isolation or receipt provenance cannot be delivered in the phase, reduce claimed assurance and mark the affected capability unsupported; do not ship a permissive shortcut.
5. Do not auto-update PRD to conform to code. Document justified deviations in the implementation report.

## 2. Threat model and security ownership

| Boundary | Trusted owner | Untrusted inputs and threats | Required response |
| --- | --- | --- | --- |
| Human/team API ingress | Service configured with operator-pinned issuer, audience, keys and mappings | Bearer tokens, headers, path org IDs, request bodies; token substitution, forged roles, cross-tenant IDOR | Verify locally; derive caller identity from verified claims plus server-side membership; deny unknown/revoked access |
| Enrollment/reporting | Authorized org operator and narrowly scoped reporter binding | Agent-submitted IDs, claimed modes, policy versions, counters, CI verdicts | Restrict reporter to bound org/agent/repository; validate schema and limits; record observations as *self-reported*, never attested |
| Policy registry | Reviewed immutable server records, explicit operator-controlled release process | Authored policy YAML/JSON, descriptions, client-supplied hashes/diffs/test results | Re-parse and compile server-side; recompute identities; reject conflicts; require reviewer separation; prevent unsafe auto-activation |
| Persistence | Control-plane service and configured storage owner | Concurrent updates, tenant identifier mistakes, restarts, stale revisions, corrupt DB | Transactional compare-and-set, scoped unique keys/queries, migration checks, durable audit rows, fail closed on corruption |
| Client ↔ control plane | Explicit opt-in, configured TLS and credentials | Offline periods, stale/superseded releases, malicious responses/metadata, replay of reports | Bounded HTTPS requests; pin expected revision/content locally; preserve local enforcement and no implicit trust of registry |
| Local agent/runtime | Existing protected operator wiring and RuntimeGateway | Model text, discovered tools, messages, delegated peers trying to claim team authority | No authority path from team API fields to local grants, policy requests, approval decisions or graph enrollment |
| Hosted metadata | Dedicated minimized types, server retention policy | Secrets, PII, action arguments, raw traces, tool output, unsafe strings, equality-leaking digests | Allowlist-only summaries; reject unknown/raw fields; bounded size/cardinality; no raw event stream ingestion |

Test against attackers who control an API client, malicious cross-tenant member, compromised reporting agent/CI job, draft-policy author, stale reviewer, forged OIDC token, untrusted registry response and concurrent API requests. A malicious service operator or compromise of the host/DB is outside this reference implementation's defended boundary; do not claim cryptographic tamper-proof audit.

## 3. Deliverable architecture

```text
Local/customer trust domain                  Optional team control-plane trust domain
+----------------------------------+          +------------------------------------+
| Existing agentsec runtime        |          | AuthN + membership-scoped RBAC      |
| compiler / policy / approvals    |          | org + inventory registry            |
| local evidence / replay / graph  |          | immutable revisions + review        |
| operator-pinned policy selection |          | minimized metadata + posture        |
+----------------+-----------------+          +----------------+-------------------+
                 | explicit opt-in metadata/registry requests   |
                 +----------------------------------------------+
                          no synchronous runtime dependency
```

Recommended package boundaries (adjust only with a documented reason):

- `src/agentsec/control_plane/models.py`: strict public versioned types; no runtime-authority grants.
- `src/agentsec/control_plane/auth.py`: pinned issuer/audience/signature verification, server-side principal binding and role checks.
- `src/agentsec/control_plane/store.py`: SQLite transactions and scoped queries; no generic database abstraction framework.
- `src/agentsec/control_plane/service.py`: authorization-neutral state transitions around explicit authenticated context.
- `src/agentsec/control_plane/api.py`: thin HTTP adapter, bounded JSON, safe error handling.
- `src/agentsec/control_plane/metadata.py` and `posture.py`: customer-side projection, ingestion validators, aggregate posture/alert rules.
- `src/agentsec/cli/team.py`: bounded `agentsec team ...` workflows; update `cli/main.py`.
- `docs/managed-control-plane.md`, `examples/team/` and `tests/unit/test_control_plane_*.py`, `tests/integration/test_team_control_plane.py`.

Keep existing core domain, compiler and runtime modules unchanged unless a concrete bug requires an additive, backward-compatible helper. No conversion of local runtime to a network-dependent PEP. Do not add a general plugin system.

### 3.1 HTTP and persistence choice

Use a small, documented optional web stack (e.g. FastAPI plus ASGI server under `[control-plane]`, with HTTP test client in dev extras) and stdlib SQLite for a **single-instance reference deployment**. The choice must be justified against existing dependencies and tested; do not add a distributed database, queue, caching fleet, hosted SaaS infrastructure, frontend build chain or elaborate ORM. Default bind to loopback. If exposed beyond loopback, require operator-configured TLS termination and reject insecure/bogus forwarding assumptions; explicitly document limitations of reverse proxies and deployment secrets.

Use parameterized SQL, WAL as appropriate, foreign keys, tenant-qualified constraints, bounded transactions, schema migration/version check, monotonic server revision numbers and deterministic UTC timestamps. No implicit DB creation or migration in production mode without a deliberate command. Crash/restart tests should verify atomicity. Avoid security decisions based only on SQLite row presence without role checks.

### 3.2 Version and protocol semantics

Introduce an explicitly versioned `team-v1` wire namespace backed by strict Pydantic objects with unknown-field rejection, strict scalar parsing, size bounds, stable error codes and explicit limits. Reuse `VersionedModel` / `SecurityModel` where compatible. Avoid silently changing `schema_version: "0.1"` on historical artifacts; new team objects may carry both schema and domain protocol identifiers if needed. Generate JSON Schemas from source models (never edit generated JSON manually). Distinguish ID/hash concepts:

- `document_hash`: normalized complete authored policy document identity;
- `effective_policy_hash`: normalized executable semantic intent;
- `compiled_plan_digest`: immutable exact compiled representation for a compiler mode;
- policy registry revision ID, organization ID and approval/publish generation: governance identities, **not** substitute runtime authority or signatures.

Exact semantics should use `canonical_json` / existing canonicalizer and server-computed IDs, not client-provided digests. Reject same ID with mismatched content and ambiguous duplicates.

## 4. Team identity, SSO and RBAC

### 4.1 Human authentication

Implement verification of **externally issued**, operator-pinned asymmetric OIDC-compatible JWTs (issuer, audience, pinned public key and algorithm, subject mapping; strict `iss`/`aud`/`sub`/`exp`/`nbf`, bounded skew, no remote `jku`/`x5u`, no `none`/HS algorithm confusion). Provision users by stable `(issuer, subject)`; display names/emails are not stable IDs. Pin rotation must be explicit and safe; no auto-fetching mutable JWKS or unbounded discovery. Reuse audited verification code where practical, but do not rebrand Phase 6 **agent** `VerifiedCredential` as a team human login. Separate trust domains.

Do **not** implement password storage, login UI, OAuth authorization-code/token exchange, token minting, full OIDC discovery or a new identity provider. A fixture issuer/keypair and an external-IdP setup recipe suffice for deterministic tests. Avoid persisting JWTs, claims, private keys or Authorization headers.

### 4.2 Role model and tenant isolation

Define an explicit finite role/permission matrix, e.g.:

| Role | Read registry/inventory/posture | Draft policy | Review policy | Publish policy | Manage membership/enrollment | Report metadata |
| --- | --- | --- | --- | --- | --- | --- |
| Owner/Admin | Yes | Yes | Yes* | Yes | Yes | No by default |
| Policy editor | Yes | Yes | No | No | No | No |
| Policy reviewer | Yes | No | Yes* | No | No | No |
| Auditor/Viewer | Yes | No | No | No | No | No |
| Bound agent/CI reporter | Own scoped status only | No | No | No | No | Bound scope only |

*The author cannot approve their own revision, even if owner/admin; a separate verified human reviewer must act. Publication requires an approved exact revision; publisher identity/action is independently audited. No ambiguous `role=admin` request fields, wildcard grants or token-embedded role authority. Roles and membership status are DB-owned, checked on every request. Revocation must affect the next authorized API request; the user token alone is insufficient.

Enforce organization boundaries in **every** service/store operation, including list, get, update, read-by-ID, error reporting, pagination, aggregates, retention and audit. Tenant IDs and membership are resolved from authenticated principal plus explicit selected org; never trust caller-supplied org headers. A user may belong to several orgs but must explicitly select one for a request, and a reporter must be bound to exactly the permitted org/agent/repo tuple. Bootstrap first owner via offline operator command/config, not public unauthenticated signup. Membership and reporting token issuance/rotation/revocation are protected operator workflows.

## 5. Shared policy registry and review workflow

### 5.1 Immutable revisions

Persist an immutable, bounded policy revision containing organization, policy key, version/generation, canonical source artifact **only when deliberately opted in**, server-computed hashes, compiler-version/mode and machine-derived conformance/coverage/diff summary, author, creation time and state. Document that contract bodies may contain sensitive resource selectors; default metadata-only mode must not upload them automatically. A centralized authoring demo may use synthetic/non-sensitive policies. Protect stored bodies and restrict read permissions.

States: `DRAFT → IN_REVIEW → APPROVED → PUBLISHED → SUPERSEDED/WITHDRAWN`, with explicit rejection/rework transition to **a new immutable draft** (do not mutate approved bytes). Specify all permitted transitions, permission checks and version preconditions. No silent edits, deletion of audit history or self-approval. Protect against concurrent approver/publisher races and stale base generations with transactional CAS. Idempotent retries must not create duplicate publications or votes.

### 5.2 Semantic safety of publication

Before review, server parses/validates and compiles the **exact bytes** with existing `load_contract`, `compile_contract`, conformance/coverage and `semantic_diff` where applicable. Record unsupported atoms, explicit mode gaps, exact source and candidate policy identities, expansion/restriction/unknown outcomes and test provenance. The reviewer must see the differences and uncovered/unproven dimensions, not a single “secure” score. Reject publication on invalid/unsupported schema, semantic diff errors or missing review; require explicit separate-review acknowledgement of any expansions or gaps, with narrow fielded rationale (not an unstructured “accept all risk” enterprise waiver). If a safe comparison is unavailable, mark UNKNOWN and do not represent it as equivalent; prefer BLOCKED pending a future mechanism.

Make clear that synthetic conformance does not prove model safety, complete data provenance, runtime admission, tool identity, TLS, isolation or code attestation. A published revision is approved configuration, **not** a grant to agents. Do not distribute live approval decisions or runtime delegation grants.

### 5.3 Distribution and local adoption

Expose exact immutable revision retrieval only to authorized, authenticated readers. Optional local CLI `team policy inspect/fetch` can retrieve and verify content/hash from configured TLS endpoint, but **must not activate** it. Local `team policy pin` (if implemented) must be an explicit protected operator action recording expected org/policy/revision and exact expected hash; never implicitly swap a running gateway or graph snapshot. An authenticated network response and content digest are not signed attestation (deferred Phase 11). If adopting a revision, normal `agentsec` local validation, startup compilation, identity, trust pins and operator authorization still apply.

If network offline or data malformed, allow existing local enforcement to continue unchanged; registry/dashboard/remote fetch can fail. Do not claim central instantaneous revocation of a policy already pinned in a running offline process.

## 6. Inventory, evidence metadata, CI and posture

### 6.1 Registration and agent inventory

Operator registers agent record: org, stable agent ID, environment, protected owner/team binding, optionally linked policy key/revision and an expected plan identity. Initial inventory may include Phase 9 graph ID as a **reported/reference** relationship, not verified graph enrollment. Prefer protected operator enrollment/rotation over anonymous self-registration. Reporter identity is separate from agent principal authority. Support enabled/disabled lifecycle and bounded lease/last-seen reporting. No inference that a heartbeat proves runtime enforcement, attests loaded bytes or authorizes remote peers.

Require authZ on create/list/get/revoke, per-agent visibility of own status, correct org/environment/agent binding and rejection of recycled ID confusion. Inventory changes must not feed `MultiAgentSession` authority or compiler paths.

### 6.2 Safe metadata projection and ingestion

Provide an explicitly opt-in **customer-side projection** from local `SecurityEvent`, eval/replay/conformance/regression outputs to a **new allowlist-only metadata envelope**. Suggested fields: org/agent/environment/revision reference, reporter-scoped run ID (opaque and bounded), period, counted decision/approval/dispatch/return/effect categories, coverage/completeness statuses, denied/error/regression counts, minimal normalized timestamps and hashed snapshot identity when intentionally configured. Omit raw event payloads and original event streams; forbid prompts, completions, action args, tool responses, credentials, arbitrary summaries, raw resources, destination URLs, full policy contents, incidental principal emails and user-provided extra fields. Reject oversized dimensions and high-cardinality label sets. Consider whether cross-tenant equality of stable digests leaks information; prefer scoped opaque IDs where possible.

Server validates reporter binding and service-computed aggregates/shape but labels data as `REPORTED_UNVERIFIED` unless independently corroborated. Idempotency keys scoped to org/reporter/source/run with canonical content digest; retry of same content returns same receipt, changed content conflicts. Persist receipt time, source time, status and cause; reject impossible windows, excessive future skew and counter contradictions. No claim of exactly-once delivery across untrusted sources. Bounded retention/purge with org scoping and testable privacy limits.

### 6.3 CI workflow and fleet posture

Build a credential-free local CI fixture demonstrating `agentsec contract test` / `coverage`, `eval` and `regression` result projection to a constrained team API payload. Reporting credential exists only in opt-in deployment; default `.github/workflows/ci.yml` remains fully offline and requires no token. Unknown coverage, incomplete evidence and DRAFT regressions remain distinct from PASS. A CI reporter scoped to one repo/environment may not publish policy, register arbitrary agents or write another team's metrics.

Expose deterministic `team posture` read APIs and CLI/text summaries: per-tenant inventory totals, recently reported/stale/unknown agents, policy revision coverage, last accepted CI report, unresolved finding categories, integrity/completeness counts and actionable **advisory** flags. Put thresholds and time windows under protected operator config with explicit units and bounds. Never label “protected” simply because an agent self-reported ENFORCE or posted a successful CI run. Optional alert records are rule-derived and deduplicated, delivered via read API/CLI in this phase; no email/webhook/pager service. Provide clear `UNKNOWN` / `STALE` / `BLOCKED` states alongside `HEALTHY_REPORTED` instead of fabricating fleet assurance.

## 7. API, CLI, lifecycle and operational guardrails

### 7.1 Minimum end-to-end use case

1. Local operator bootstraps a synthetic org and the first owner with pinned test issuer.
2. Owner provisions a second reviewer, editor and narrowly scoped agent/CI reporter.
3. Editor uploads a bounded example contract revision; service recomputes hashes, compiler mode, gap/coverage and semantic diff.
4. Independent reviewer approves the exact immutable revision; publisher publishes under CAS.
5. Operator registers a local agent and explicitly associates a desired/pinned policy revision; no runtime policy mutation occurs.
6. Locally run baseline `agentsec` security tests/fixture events; project only minimized metadata and submit via a scoped reporter.
7. Viewer inspects team inventory, review history, metadata completeness, CI posture and advisory alerts.
8. Simulate team service outage, stale publication, reporter revocation and cross-org access; existing local evaluation/runtime path is unaffected.

### 7.2 Narrow public surface

Design precise API names before coding; expected families include:

- `/v1/orgs/{org_id}/members` and `.../reporters` for privileged provision/revoke/list;
- `.../policies/{policy_key}/revisions`, `.../reviews` and `.../publish` for immutable governance;
- `.../agents` and `.../agents/{agent_id}/reports` for enrollment and scoped metadata;
- `.../ci-runs`, `.../posture`, `.../alerts` and `.../audit` for inspection.

Use standard safe methods, body validation, pagination cursor restrictions, stable conflict/authorization/errors, finite record limits, no secret echo and cross-tenant non-enumeration. CLI should expose `agentsec team init/serve`, inspection and reporting commands where justified; avoid redundant CLI wrappers for every API. Document exact endpoint/command contract and fixture invocation.

### 7.3 Operational quality

- Default loopback-only and test-key demo. Real IdP/public TLS setup is opt-in with explicit production warning; refuse unsafe settings for nonloopback.
- No private JWT signing keys in repository, fixtures except test-only keys clearly marked, logs or persisted records.
- Structured audit for *team governance* changes (actor, org, action, target, timestamp, version/outcome; no policy body/token); not the existing runtime `SecurityEvent` lifecycle and not cryptographically tamper-evident.
- Bound data sizes, timeouts, request rates or documented single-instance admission limits; avoid HTTP thread starvation and indefinite request bodies.
- Schema migrations deterministic, backup/restore recipe and startup compatibility checks. Deny on unavailable database, malformed config, invalid identity or inconsistent state.
- No silent fallback to `STATIC_TRUSTED_CONFIG` for remote humans/reporters.
- A single-instance reference does not establish distributed quotas, HA, global ordering, secure multitenancy against host admins, signed release attestation or production compliance.

## 8. Sequenced workstreams

**W0 — Baseline and design lock**
- Inspect actual HEAD, dirty state, PRD/architecture, Phase 8–9 reports, exact compiler/hashes, evidence, identity, CLI and test conventions. Record inherited unaccepted gates.
- Write `docs/managed-control-plane.md` design/threat matrix before substantial code; choose HTTP/persistence dependencies and typed API/state transition schema. Stop if identity/tenant trust is undefined.

**W1 — Typed domain, migrations and auth**
- Strict team-v1 models, storage schema, bootstrap and membership/reporter separation.
- Pinned asymmetric token verifier with all negative tests; server-side RBAC/tenant-qualifier helpers.
- Verify no route allows unauthenticated org discovery. Stop if IDOR or role spoofing is possible.

**W2 — Registry/review**
- Exact validation/compilation/hash semantics; immutable revision state machine; diff/coverage and gap evidence; conflict-free publish and audit.
- Independent reviewer/author checks; publication without runtime activation.
- Stop on stale-approval bypass, mutated reviewed bytes or weak comparison represented as safe.

**W3 — Inventory/reporting**
- Protected operator enrollment, scoped reporter identity, minimized local exporter and API ingestion, idempotency/retention.
- Adversarial privacy tests and no full `SecurityEvent` upload.
- Stop if any raw secret/action argument can pass schema/serializer into the control plane.

**W4 — Posture/CI and operator experience**
- Read-only scoped posture/alert computations and CLI/text dashboard; deterministic CI fixture and end-to-end example.
- Outage/offline compatibility, stale/unknown states and bounded auth errors.

**W5 — Regression, docs and release gate**
- Full credential-free suite plus focused security matrix, reproducible commands, migrations/restart/concurrency tests, build/schema checks and packaging with optional dependencies.
- Update `README.md`, `docs/README.md`, `AGENTS.md`, relevant architecture appendix and focused docs if the design changes enduring constraints.
- Write `docs/reports/phase-10-implementation-report.md` with all required details. Do not self-declare independent acceptance.

## 9. Minimum adversarial verification matrix

| Case | Expected behavior |
| --- | --- |
| Forged unsigned/symmetric JWT, swapped `kid`/algorithm, wrong issuer/audience, expiry/nbf, unknown subject, key URL header, duplicate key mappings | Rejected before tenant/member resolution; no authorization |
| User token accepted as reporter or reporter token used for human RBAC; revoked membership/reporter; token with forged role claims | Denied; current DB membership/scopes decisive |
| Tenant A accessing or enumerating Tenant B by path, ID, pagination, report/alert/audit, bulk status | No cross-tenant content or existence leak |
| Editor self-review; owner self-review; outdated review after revision bytes/version altered; simultaneous publish; out-of-order version | Rejected or conflict; audit consistent; no mutable approved bytes |
| Same policy ID and different content; cosmetic/document vs semantic change; stale compiler mode; unsupported atoms | Correct server-computed identities, diff/gaps and review obligations; no false equivalent |
| Fetch/pin stale or malicious policy body, control-plane unreachable | No local runtime/graph alteration; hash/version mismatch blocked |
| Reporter tries agent/org/repo spoofing, oversized/high-cardinality fields, raw prompt/tool args/event payload, impossible times | Rejected; no sensitive data persisted or logged |
| Duplicate report with same idempotency key and payload, conflicting retry, concurrent reports, crash between writes | Exact same receipt, conflict or atomic rollback; never double count |
| Missing/stale reports, DRAFT regression, SHADOW/DISABLED, unknown coverage, absent effect verification | Explicit unknown/advisory posture; no “verified protected” claim |
| Store unavailable/corrupt or migration mismatch; API request cancellation | Fail closed with safe error; no partial publication/membership changes |
| Legacy contract/eval/runtime/MCP/graph functions with team extra **not** installed and zero network | Identical existing behavior and passing tests |
| Cross-tenant activity under a user legitimately belonging to both orgs | Scope is explicit per request; no accidental union |
| Reflected HTML/script in names, unexpected content types/UTF-8, dangerous URLs, pagination and time boundaries | Sanitized output, strict parsing, finite limits and no server-side fetch |
| Signed token/log/audit secret canary search, retention purge, deletion of one tenant's metadata | No leaked token/secret; scoped purge preserving governance audit policy |

Use fixed clocks and ephemeral SQLite test databases; no real SaaS accounts, cloud provisioning, Docker daemon, external network or model calls in core CI. Ensure test cases exercise actual API/service/store integration, not only Pydantic validation.

## 10. Acceptance and evidence gates

**Functional**
- Two-org fixture demonstrates independently provisioned reviewers/editors/reporters, immutable review→publish, enrollment, metadata submission and read-only posture; unauthorized cross-org operations are denied.
- A published policy is fetched/inspected with exact server-computed identities, no automatic enforcement/graph activation.
- CI fixture produces acceptably minimized metadata from real local evaluation/regression outputs, retains DRAFT/unknown statuses honestly.
- Restarted reference service preserves correct revision/audit/tenant state; conflicting concurrent mutation is atomic.
- Clear operator setup, local demo, threat assumptions and limitations.

**Security**
- Default-deny remote RBAC; pinned externally issued identity, separated team and runtime principals; reviewer separation and revocation tested.
- Organization isolation is enforced at persistence and API boundaries; no raw event bodies, JWTs, keys, private content or action arguments in metadata paths.
- Content digest, policy hashes and remote reporting never misrepresented as authentication, attestation, runtime effect verification or an authorization grant.
- Local RuntimeGateway, Phase 8 supply-chain checks and Phase 9 session ownership stay authoritative and offline-capable.
- No route allows control plane to remotely widen protected capabilities or bypass existing runtime approvals.

**Quality**
- Exact commands, environment/dependency versions and result counts in report: `pytest -q`, `ruff check .`, `ruff format --check .`, `mypy src`, `agentsec schema export` + generated-schema drift comparison, `agentsec examples validate`, `agentsec eval examples`, `agentsec regression run --root examples/regressions`, targeted Phase 9 graph demonstration/regression, and `python -m build`.
- Default and optional `control-plane` test/import/packaging paths both work; CI remains credential-free.
- New state machine and persistence have negative and concurrency tests, durable audit assertions and a clear migration story.
- Document explicit not-done items; no fake “100% secure” score and no acceptance of inherited Phase 7–9 review gates.

## 11. Non-goals / deferred to later phases

- Production multi-region hosted SaaS, Kubernetes/Terraform deployment, managed billing, HA, distributed leases/queues and large-fleet scale.
- Complete browser-based SSO flow, password or token issuer, automatic JWKS/OIDC discovery, full cloud IAM provider.
- Enterprise policy federation, cryptographic release/remote-runtime attestations, signed evidence chains, cross-org sharing, compliance certifications, SIEM export and generalized risk-acceptance workflow (Phase 11 territory).
- Runtime tool/approval delegation from team roles; dynamic graph enrollment or A2A network transport; streaming raw prompts/tool arguments to cloud.
- Real-time guaranteed remote kill switch, automatic promotion/rollout to running gateways, emergency privilege expansion, and remote inline PDP.
- LLM-based posture judges, secret/content detectors claimed as proofs, full frontend dashboards, email/pager/webhook notifications and arbitrary analytics query language.

## 12. Required implementation report and handoff

Create `docs/reports/phase-10-implementation-report.md` containing:

1. starting and ending SHAs, dirty-tree state and scope authorization; inherited review gates;
2. PRD/architecture/focused-doc alignment and deviations;
3. complete interface/schema/persistence/authN/authZ/tenant-boundary map;
4. immutable policy state machine and local activation non-relationship;
5. customer-side projection and privacy proof, CI/reporting/inventory/posture limitations;
6. threat matrix disposition with precise tests and any unsupported cases;
7. command outputs, counts, dependency/tool versions, schema drift and build evidence;
8. any failed tests/unreproduced environment or network scenarios;
9. migrations, operational limitations, known risks and next-phase follow-ups;
10. readiness verdict **for independent review**, not unearned release acceptance.

Avoid incidental refactoring of Phases 0–9. Do not modify unrelated user files or publish/deploy without separate authorization.
