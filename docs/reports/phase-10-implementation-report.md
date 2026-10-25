# Phase 10 implementation report

## 1. Baseline, authorization and review status

Starting HEAD: `6dfa0d56057c3bcf85bb9fc070ea1e43491899ef`, branch `main`.
The requested scope was the attached Phase 10 prompt and installed companion plan, entirely in
this session, no subagents, one local commit, no push/deployment/PR. No subagents were used.
Initial dirty state contained untracked `PHASE-0-SOL-MEDIUM-PROMPT.md` and
`docs/plans/phase-10-implementation-plan.md`. The unrelated prompt is untouched/excluded; the
Phase 10 plan is included as the authoritative supplied source. No companion plan existed at
`/Users/jasonkli/Downloads/agent-safety-security-phase-10-implementation-plan.md`, so no conflicting
external version required reconciliation. The attached implementation prompt was read, not
copied into runtime inputs or treated as authorization beyond the user's requested scope.

Final implementation identity is the single commit containing this report (`git log -1 --format=%H
-- docs/reports/phase-10-implementation-report.md`); its parent is the starting HEAD above. A file
cannot embed its own eventual Git commit hash without changing that hash. The final handoff
records the resulting SHA. Intended final dirty state: only the pre-existing unrelated prompt.

Independent acceptance of Phases 7–9 was **not established** by their correction reports or by
this implementation. Phase 10 is ready for independent review, not self-certified release
acceptance. No enterprise compliance, cryptographic runtime attestation or hosted readiness claim.

## 2. Implementation map and traceability

| PRD Phase 10 capability | Delivered reference slice |
| --- | --- |
| Organizations, SSO, RBAC | `control_plane/auth.py`, `models.py`, `service.py`: pinned external Ed25519 JWT, explicit organization selection, DB-owned roles, separate HUMAN/SERVICE/REPORTER identities |
| Shared registry and reviews | `policies.py`, `service.py`: immutable uploaded sources, canonical compiler identities, full synthetic conformance/coverage and finite diff, independent review and CAS publication |
| Protected inventory | `service.py`: operator membership/enrollment/revocation, exact agent/environment/repository binding, optional desired revision/plan association |
| Central metadata and CI | `metadata.py`: explicit event/evaluation/conformance/regression/replay projections; fixed allowlisted reports, receipts and idempotency |
| Fleet dashboard/alerts | `service.py`, `api.py`, `cli/team.py`: scoped read-only JSON/text posture, distinct runtime/CI observations and deduplicated advisory flags |
| Persistence/API | `store.py`, `api.py`: single-instance SQLite, tenant-qualified storage, transactions, migrations/version gate, bounded Starlette adapter |
| Operator experience | `agentsec team init/provision/serve/posture`, `examples/team/demo.py`, `examples/team/README.md` |
| Schema/compatibility | 12 generated team schemas; additive CLI/schema-export registration; no core runtime, Phase 6/9 semantics or historical schemas changed |

`docs/managed-control-plane.md` was written before substantial code and records trust boundaries,
role matrix, ten mandatory design decisions, failure/status semantics, state machine, storage,
minimization, outage and operating limits. Architecture adds only the enduring separation decision;
PRD scope was not rewritten. README, docs index, report index and AGENTS current boundary are updated.

Starlette supplies standard ASGI routing/request handling, Uvicorn supplies bounded local serving,
and PyJWT/cryptography supply asymmetric verification. They are optional `[control-plane]`
dependencies, not dependencies of the local core. SQLite is stdlib; no ORM or generic plugin/store
framework was added. HTTPX is a development test-client dependency. Default CI installs/tests the
extra and the synthetic demo but needs no reporting credential and sends no remote telemetry.

## 3. Protocol, identity, roles and persistence

All new public artifacts use strict `team-v1` models: unknown fields and scalar coercion rejected,
finite opaque IDs, bounded counters, source bytes, times and collection sizes. Existing `0.1`,
`phase6-v1` and `phase9-v1` meanings are preserved. Schemas are generated from Python models.
The documented API is rooted at `/v1/orgs/{org}/`; collection endpoints, exact revision/source
inspection, transitions, reports, own-status, posture/alerts, audit and metadata-purge are listed
in the example README. All service methods recheck authorization inside a SQLite transaction.

JWT checks: pinned issuer, one exact audience, kid and EdDSA/Ed25519 public key; signature,
provisioned subject, finite numeric exp/nbf, ordering/freshness and bounded skew. Unknown/remote
key headers, duplicate JSON claims/headers, none/HS confusion, invalid signature, unprovisioned
subjects and private key configuration are rejected. No remote IdP/discovery call or token minting.
Global protected `(iss,sub)` bindings remain separate from tenant memberships and reporter scopes.
Only offline tools can create identity bindings/first owners. No HTTP signup or token issuance.

OWNER manages/publishes and can author/review; EDITOR authors/submits; REVIEWER reviews;
VIEWER reads. SERVICE can only read with VIEWER membership. REPORTER never takes a user role and
can only report/read its exact protected enrollment. Token role/org claims confer no authority.
Current membership/reporter status is checked on every request, including retry. A reviewer must
retain active HUMAN review permission at publication. Multiple memberships select one path org,
never a union. One real human per provisioned subject binding is an operator/IdP prerequisite.

SQLite uses explicit exclusive initialization, file mode 0600, user_version=1, foreign keys,
WAL, a two-second busy timeout, parameterized org-qualified keys and BEGIN IMMEDIATE. Reporter
bindings have a unique cross-org constraint; protected reporter identities cannot be recycled
into another org/agent/source. Store methods require org scope. Global identity lookup is the
explicit offline/provisioned identity directory, never an unscoped tenant-data read API. Audit
sequence values returned to clients are per-tenant ordinals to avoid exposing other tenant volume.

No automatic migration/recovery occurs. Unknown DB versions, corrupt DBs, missing/unavailable
storage and failed transactions fail closed. Publication and receipt failure injection tests
establish rollback/retry behavior; restart tests establish durable source/state/audit persistence.
This is not a power-loss/storage-device or distributed transaction proof. Governance audit is
content-minimized and durable, not signed/tamper evident or inaccessible to host admins.

## 4. Review, publication and nonactivation

Policy body upload requires explicit `upload_source=true`; reports cannot carry a body. Source
bytes and computed assessment are stored separately under immutable SQL triggers. All authorized
members may intentionally read source; finer source-reader roles are deferred. No policy content
is in audit/report records. Parser limits additionally bound rules, data dimensions and scope
resources before compilation/probe/diff work. Client-provided hashes/compiler results are rejected.

DRAFT -> IN_REVIEW -> APPROVED -> PUBLISHED -> SUPERSEDED is the normal flow. Review rejection
and owner withdrawal lead to WITHDRAWN; rework requires a new draft. Exact request/version/actor
transition retries are idempotent; changed retries conflict. The review request, acknowledgements
and finite rationale are durable and inspectable with the revision. Authors cannot self-review,
including owners. Publisher checks current base generation, exact source/assessment/compiler,
current reviewer permission and approved state; concurrent sibling releases cannot both publish.
Supersession, publication pointer, retry and governance audit update atomically.

Server computes document_hash, effective_policy_hash and compiled_plan_digest using existing
canonical compiler code. Cosmetic/semantic distinction is tested. Full derived conformance,
coverage and semantic diff are available for review. Initial-policy, expansion and gap decisions
require separate typed acknowledgements. Unsupported intent, comparison/compiler errors and
unknown semantic changes block submission/publication. Synthetic conformance cannot establish
model robustness, adapter proof, complete taint, running-code identity or effect verification.

`verify_fetch` recompiles returned source and matches all three expected identities and compiler
mode without writing configuration. API source retrieval is authenticated and tenant scoped.
There is no remote policy-client/pin/activation/rollout mechanism and no remote grants. A service
response, report, digest or publication cannot become RuntimeGateway policy, Phase 6 authority,
trust admission, approval or Phase 9 enrollment. Runtime modules do not import the team service.

## 5. Projection, receipts and advisory posture

Fixed metadata includes only bounded UUID run ID, protected opaque agent/environment/repository,
source enum, normalized period, fixed lifecycle counters, completeness/coverage/mode/CI/regression/
replay status enums. A serializer explicitly handles UUIDs without changing historical canonical
serialization. Local projectors select counts/status fields; they never dump event/result models.
Event summaries/IDs/arguments/prompts/resources/results, arbitrary labels/free text, JWTs, keys,
URLs, emails, full findings and source evidence never enter the report schema. Unknown fields,
raw-event canaries, oversized payloads, impossible windows/counters and scope spoofing fail before
persistence and diagnostics. Policy-source upload is a deliberate, separate registry operation.

Reports remain REPORTED_UNVERIFIED, including claimed ENFORCE, reported completeness and effect
counts. Runtime/CI observations are separately retained in posture so a CI PASS cannot mask
SHADOW/DISABLED runtime reporting. Missing/stale observations, UNKNOWN coverage, DRAFT regression,
BLOCKED replay, incomplete capture and absent effect verification remain visible. Alerts are
read-time advisory rules with no external notification or fabricated protection score.

Idempotency commits canonical org/reporter/source/run content with one receipt. Identical retries
return the receipt; changed content conflicts. Scoped retention purge removes expired receipts
while retaining compact tombstones and governance history. Another tenant's receipt survives.
Lifetime ceilings of 1,000 records per kind/org (including tombstones/retry records) intentionally
fail closed on saturation; no silent pruning/reuse undermines idempotency. A future reviewed
archival/migration design is required for ongoing large-fleet use. Explicit operator purge is
required; there is no background retention daemon. Allowlisting minimizes disclosure but cannot
prevent a malicious reporter encoding secrets in numeric/UUID channels; it is not a detector or
covert-channel proof. Host compromise and forged-but-valid reports remain outside assurance.

## 6. Verification

Commands use `.venv/bin/` because no unqualified `python` is available in this execution shell.
Environment: Python 3.12.13; Pydantic 2.14.1, PyJWT 2.15.1, cryptography 50.0.2, Starlette 1.8.0,
Uvicorn 0.54.0, pytest 9.1.1, Ruff 0.17.1 and mypy 2.4.0.

| Exact command | Final result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | PASS — 972 tests in 106.23s; local loopback test-server permission |
| `.venv/bin/python -m pytest -q tests/unit/test_control_plane_projection.py tests/integration/test_team_control_plane.py` | PASS — 90 tests |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS — 216 files |
| `.venv/bin/mypy src` | PASS — 131 source files |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS — generated from source, never hand edited |
| `.venv/bin/agentsec schema export --out /tmp/agentsec_phase10_schemas` | PASS |
| `diff -ru --exclude=.gitkeep schemas/generated /tmp/agentsec_phase10_schemas` | PASS — no drift; historical schemas unchanged |
| `.venv/bin/agentsec examples validate` | PASS — 3 contracts, 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS — all 6 expected outcomes matched |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS — 2 ACTIVE passes, 1 DRAFT retained |
| `.venv/bin/python examples/multi_agent/local_session.py` | PASS — existing local gateway/graph slice |
| `.venv/bin/agentsec graph validate --config examples/multi_agent/graph.json` | PASS — 3 nodes/depth 3; structurally valid, not authenticated |
| `.venv/bin/agentsec graph replay --config examples/multi_agent/replay.json` | PASS — 2 requests, no blockers; candidate comparison UNKNOWN |
| `.venv/bin/agentsec graph regression --case examples/multi_agent/regression.json --source examples/multi_agent/replay.json` | PASS — explicit assertion, no blockers |
| `.venv/bin/python examples/team/demo.py` | PASS — two tenants, review/publication, fetch, real local CI projection, revocation/IDOR/outage, local graph continues |
| `UV_CACHE_DIR=/private/tmp/agentsec-phase10-uv-cache uv pip install --python .venv/bin/python --no-deps --no-build-isolation -e '.[control-plane]'` | PASS — editable extra installation with already present optional dependencies |
| `.venv/bin/python -m build` | FAILED — isolated environment cannot reach package index to obtain setuptools>=77 |
| `.venv/bin/python -m build --no-isolation` | PASS — sdist and wheel using installed build requirements |
| `git diff --check` | PASS |

Initial sandboxed full suite: 955 passed, 11 setup errors because existing HTTP/TLS fixtures
could not bind loopback sockets. Rerun with test-server permission resolved those errors. Two
existing ssl.PROTOCOL_TLS deprecation warnings remain. Intermediate development failures (UUID
canonical handling, posture tie/source ordering, an over-broad simulated dependency removal,
a missing new review-record argument and strict literal opt-in parsing) were corrected and
covered by final reruns. None is reported
as a final pass without rerunning the affected checks. The initial uv install cache permission
failure was resolved by placing its cache in writable /private/tmp. No external services or
credentials were used. Live IdP/OAuth flow, public TLS/proxy, cloud, real model/tool and
Docker-daemon testing were **not run** in this local phase. Fresh dependency resolution could
not complete offline; installed optional dependencies were verified and the isolated build
failure is recorded above. The wheel was also imported directly using:

```bash
.venv/bin/python -c 'import sys; sys.path.insert(0,"dist/agent_safety_security-0.1.0-py3-none-any.whl"); import agentsec.control_plane.api as api; assert ".whl/" in api.__file__; print("PASS: wheel control-plane import")'
```

Negative/integration evidence covers forged/none/HS/wrong-key JWT, issuer/audience/subject/kid,
nbf/expiry and duplicate claims, remote headers, identity-kind confusion, revoked memberships,
reporter exact scope and lifecycle, tenant-scoped read/write/diff/source/posture/alerts/audit and
pagination, dual memberships and identical revision IDs, self/stale review, explicit expansions,
immutable bytes, sibling publication through one/two DB connections, durable review requests,
rollback after publication write, restart, invalid/unsafe contract schemas, unsupported compiler/
intent, fetched-body mismatch, secret canary omission, report retry conflicts/concurrency,
contradictory counters/times, retention/tombstones/tenant purge, UNKNOWN/DRAFT/SHADOW/effect gaps,
store outage and offline gateway/graph execution. Default-core testing denies imports of team
HTTP/crypto libraries while exercising compiler, team CLI module import and real graph example;
root CLI retains its existing MCP dependency behavior (MCP itself imports Starlette when installed).

## 7. Deviations, operations and readiness

Narrow safe alternatives: Ed25519/EdDSA only; phase6-v1 registry compilation only; loopback-only
HTTP rather than accepting a proxy assertion; no remote fetch client/pin workflow; flat org-scoped
revision/report endpoints instead of nested policy/CI route aliases; one finite review-reason enum
rather than arbitrary prose waivers. Source viewing is shared among org members. Keys/bindings
rotate offline; metadata retention is explicit operator purge. A JSON/text dashboard replaces UI
and read-time advisory flags replace pager delivery. These choices preserve Phase 10 value without
expanding local authority or claiming production operations. A separately pinned remote transport,
OIDC login lifecycle, HA/distributed ordering, production retention/archival/quotas, browser UI,
SSO provider interoperability, encryption at rest beyond host controls, signed audit/releases and
code attestation remain deferred. No production reverse-proxy/TLS exposure is supported here.

Backup/restore: stop the single service and use SQLite's online backup API (or `.backup`) to a
private new destination; protect that copy because it contains opt-in policy sources and identity
bindings. Restore the consistent DB with mode 0600 alongside protected public-key config; start
only after version/integrity checks. Do not copy a live main database without WAL consistency or
edit user_version to bypass migration checks. A corrupt/unavailable DB blocks team operations,
never causes runtime fallback or authority changes.

Ready for independent review of this bounded reference slice. Phase 7–10 independent acceptance
and production readiness remain open. No deploy, push or PR was performed.

## 8. Independent review corrections (F10-01–04)

Starting correction baseline: `539feafb1e8db1808110e7fe4834e53ff795d37c` (the reviewed Phase 10
implementation). The first independent review identified four P2 findings. All four are corrected
in the current worktree; this is evidence for a fresh review, not an acceptance decision. Phases
7–9 remain open. The unrelated pre-existing untracked `PHASE-0-SOL-MEDIUM-PROMPT.md` was preserved
and is excluded from the commit.

### F10-01 — bootstrap issuer validation and atomic initialization

`team init` now validates the TeamConfig and pinned keys, org ID, HUMAN owner kind and exact
configured owner issuer before opening a database. The first binding, organization, OWNER
membership and audit entry are inserted in one transaction. A failed bootstrap closes and removes
only the exclusive new database and its WAL/SHM sidecars; a pre-existing path is never replaced.
The offline retry story is to correct the protected inputs and rerun `init`. There is no signup or
remote provisioning. Tests cover an unconfigured issuer, invalid org, injected bootstrap failure,
existing DB preservation, successful signed synthetic owner access, and direct transaction
rollback behavior. The team command reports stable error codes without source data.

### F10-02 — advisory posture evidence

`Metadata.policy_revision` is an optional opaque revision label. It carries no body or digest and
remains a reporter claim. `AgentPosture` now has separate `policy_alignment` (`UNKNOWN`,
`REPORTED_MATCH`, `MISMATCH`) and `effect_evidence` (`NONE`, `REPORTED_UNVERIFIED`) dimensions.
Missing expected policy or reporter correlation, a missing/non-published expected revision,
expected-plan mismatch, superseded expected policy and reporter mismatch prevent green
classification. Dispatched work with
no reported effect verification is a gap; positive effect counts remain unverified. Read-only
zero-dispatch reports may meet the advisory classifier when the other evidence aligns, while
effect evidence stays `NONE`. CI replay must report `PASS`; UNKNOWN/BLOCKED remains a gap and FAIL
is a failure. The guide and demo state that `HEALTHY_REPORTED` is an advisory interpretation of
self-reported fields, never runtime attestation. Model-derived team schemas were regenerated.
Tests include a healthy read-only report with aligned policy, no-policy/unknown-replay and
dispatched-without-effect gaps, and an incomplete first-party projection that cannot appear green.

### F10-03 — private SQLite admission

Before reopening, POSIX storage admission checks the DB and any existing WAL/SHM sidecars with
`lstat` semantics: regular non-symlink file, current effective UID owner and no group/world mode
bits. The opened database inode is compared with the checked path. Unsafe restored storage fails
closed with `STORE_UNAVAILABLE`; the service does not chmod user files. New initialization remains
exclusive and creates mode 0600. Tests cover 0600 acceptance, 0644/0660 rejection, a symlink, an
unsafe WAL sidecar, and restart of a private DB. POSIX is the supported existing-DB admission
boundary; Windows ACL checks are not implemented and existing DB reopen fails closed there.
Operators should repair a stopped copy and protect parent directories/backups. Path checks do not
defend against a privileged host administrator or a malicious concurrent directory writer.

### F10-04 — staged assessment and short CAS commit

Revision creation and submit/approve/publish now take an authorized snapshot, perform bounded
assessment outside the global `BEGIN IMMEDIATE` transaction, then reauthorize and verify the
actor, immutable source/assessment, workflow version and publication generation before writing.
Transition retries still recheck the exact retry identity/content. Concurrent same-content draft
creation remains idempotent. A stale snapshot conflicts; assessment output is never accepted from
a client or treated as an authorization source. Existing sibling-publish CAS/rollback behavior
remains covered; new controlled tests show an unrelated beta posture read completes while alpha
assessment is paused and a reviewer revoked during staged assessment cannot approve.
No sustained malicious-policy throughput benchmark was run; the change removes assessment time
from shared write-lock occupancy but does not claim distributed or HA storage.

### Correction verification

Environment: Python 3.12.13, Pydantic 2.14.1, PyJWT 2.15.1, cryptography 50.0.2, Starlette 1.8.0,
Uvicorn 0.54.0, pytest 9.1.1, Ruff 0.17.1 and mypy 2.4.0.

| Exact command | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q tests/integration/test_team_control_plane.py tests/unit/test_control_plane_projection.py -p no:cacheprovider` | PASS — 103 tests |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS — 216 files |
| `.venv/bin/mypy src` | PASS — 131 source files |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS — generated from models |
| `.venv/bin/agentsec schema export --out /tmp/agentsec_phase10_fixed_schemas && diff -ru --exclude=.gitkeep schemas/generated /tmp/agentsec_phase10_fixed_schemas` | PASS — no schema drift |
| `.venv/bin/agentsec examples validate` | PASS — 3 contracts, 3 scenarios |
| `.venv/bin/python examples/team/demo.py` | PASS — two-tenant review, unverified posture, outage and offline Phase 9 demo |
| `git diff --check` | PASS |
| `.venv/bin/python -m pytest -q -p no:cacheprovider` | **974 passed, 11 errors** — all 11 occur during setup of legacy `tests/unit/test_adapters_isolation.py` loopback HTTP/TLS fixtures; sandbox returns `PermissionError: Operation not permitted` on localhost socket bind. No Phase 10 test fails. This sandbox result differs from the independent handoff's full-suite failures and its five-failure parent comparison; no new parent comparison was run in this environment. The full suite is not green. |

No external identity provider, production tenant, public listener, real policy, runtime authority,
or live model/tool service was used. No independent acceptance gate is closed by this report.
