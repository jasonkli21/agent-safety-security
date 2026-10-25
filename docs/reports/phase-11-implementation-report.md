# Phase 11 implementation report

## 1. Baseline, authorization and review status

Started on `main` at `48ec4e6bc64a5cf8d0221884b3279743c994a405` (2026-10-25).
The end-of-verification HEAD, before the requested single implementation commit, is the same
SHA. The implementation commit is the commit containing this report; obtain its exact SHA with
`git log -1 --format=%H -- docs/reports/phase-11-implementation-report.md`. Its SHA is also returned
in the session handoff. Embedding a commit's own SHA in its committed contents is self-referential.

User explicitly authorized implementation and **one local commit**, all in this session, with
no subagents. No subagents, push, PR, external services/credentials, public listener, production
migration or deployment were used. Initial untracked files were `PHASE-0-SOL-MEDIUM-PROMPT.md`
and `docs/plans/phase-11-implementation-plan.md`. The former is untouched and excluded; the latter
is the supplied implementation contract, included with its status updated. No baseline reset.

Independent acceptance of Phases 7–10 remains open, including fresh review of F10-01–04. Author-run
tests are not independent acceptance. Phase 11 is ready **for independent review only**.

## 2. Traceability and delivered scope

Read PRD, architecture, Phase 11/10 plans, focused security/identity/evidence/runtime/replay/
conformance/trust/graph/control-plane docs, implementation/review-fix reports and existing code.
The PRD was not rewritten. The enduring additive boundary is recorded in the architecture appendix.

| PRD Phase 11 capability | Delivered | Qualification |
| --- | --- | --- |
| Federation | Offline Ed25519 source bundle, protected exact peer pin, local recompilation and tenant DRAFT import | No remote fetch/sync/activation, no origin review transfer |
| Incident workflows | Typed metadata-only case state machine, CAS/retry/audit, independent severe closure | No raw forensics, automatic remediation or effect verification |
| Risk acceptance | Exact case/revision version, independent OWNER decision, ≤30-day expiry, stale/revoked views | Annotation only; CI, policy decisions and posture remain unchanged |
| Fleet simulation | Finite shared compiler/conformance/coverage/diff, protected inventory alignment and explicit unknowns | Advisory, no model/tool execution, graphs or loaded-byte proof |
| SIEM/evidence | Minimized tenant audit pages and report/posture/case/risk observations, signed exact-byte manifests | Offline only, reporter assurance remains REPORTED_UNVERIFIED |
| Private deployment | Nonroot POSIX single-node recipe, consistent verified backup/restore checks, recovery/key runbook | Loopback only; no hosted/public/HA/Windows ACL support |
| Support/SLA | Support triage/SLO measurement worksheet and synthetic backup timing | No commercial SLA, production benchmark or staffed support |

## 3. Trust, keys, canonicalization and federation

`enterprise-v1` is separate from team-v1 and historical domain/compiler versions. Canonical payload
bytes use existing project canonical JSON: sorted keys, UTF-8, compact separators, explicit
null/default fields, normalized UTC Z times, ordered arrays. This is not a claim of RFC 8785.
The signed message is exact purpose prefix plus canonical payload, excluding the signature:
`agentsec:enterprise-v1:federation\n` or `agentsec:enterprise-v1:export\n` with one LF.
Algorithm, purpose, key ID, origin/target and all relevant identities/bytes are signed. Ed25519 only;
private keys are bounded owner-private regular POSIX files. Sign/verify imports crypto lazily.
A committed fixed canonical-byte/signature vector uses a publicly known synthetic seed, distinct
from the fixture JWT issuer. Verification cross-checks the vector through cryptography directly.

Operator-protected pins bind exact origin, target, source/local policy key, key ID, purpose,
not-before/expiry and enabled status. No embedded key, JWT key fallback, JWKS discovery or remote
lookup. Import verifies signature/pin/time **before source compilation**, rejects unsupported
semantics or any document/effective-policy/compiled-plan identity mismatch, and creates only an
immutable recipient DRAFT authored by the importing HUMAN. Existing submit/review/publish remains
mandatory. No change enters runtime identity, approvals, trust locks, graph enrollment or policy.

Replay high water is tenant + origin + source-policy, independent of signing key. Lower sequences
and changed same-sequence requests conflict; exact latest actor/request retry returns its original
DRAFT result. Rotation/revocation does not clear replay records. Concurrent publication, membership
or protected trust change during staged assessment prevents import. Signing keys/source are never
stored in audit; deliberate opt-in revision source remains in the existing source table.

## 4. Storage, roles, APIs and workflows

No DDL change is needed: existing generic tenant-qualified records support `case`, `risk`,
`enterprise_retry` and `federation`. SQLite remains **user_version=1**, for both new/reopened stores.
There is no v2, migration command, silent upgrade, or production data migration. Consequently
v1→v2/interrupted-migration tests are inapplicable; instead tests preserve real v1 data and all
enterprise records through consistent backup/reopen, reject unknown versions/unsafe WAL, and
inject backup/workflow faults. This is a deliberate smaller design under the plan's conditional
"if schema changes" instruction. Existing immutable-source triggers and F10 corrections remain.

Every service mutation uses existing tenant authorization, current membership/kind/token expiry,
short SQLite transaction, expected version and atomic audit. Exact transition retries bind actor,
request and object/version. Changed retries conflict, revoked actors cannot reuse receipts. Existing
HUMAN/SERVICE/REPORTER separation persists. See enterprise-security.md for the complete role table.

| Operation | Request → response | Permission |
| --- | --- | --- |
| POST enterprise/cases | CaseInput → IncidentCase | HUMAN OWNER/EDITOR |
| POST enterprise/cases/{id}/transitions | CaseTransition → IncidentCase | triage/mitigate: OWNER/EDITOR; resolve/dismiss: OWNER/REVIEWER; close/reopen: OWNER |
| GET enterprise/cases/{id} | IncidentCase | member read; VIEWER SERVICE allowed |
| POST enterprise/risks | RiskInput → RiskAcceptance | HUMAN OWNER/EDITOR |
| POST enterprise/risks/{id}/transitions | RiskTransition → RiskAcceptance | HUMAN OWNER; distinct requester on approval |
| GET enterprise/risks/{id} | RiskView including current disposition | member read; VIEWER SERVICE allowed |
| POST enterprise/simulate | SimulationInput → FleetSimulation | HUMAN OWNER/EDITOR |
| offline import | ImportRequest → recipient Revision | HUMAN OWNER/EDITOR + independent protected pin |
| offline SIEM snapshot | ExportCursor → ExportPage | HUMAN OWNER only |

Paths are under `/v1/orgs/{org}/`. Existing duplicate-rejecting bounded JSON/body/query handling is
reused; unknown fields/coercion/versions fail. No signing/private-key or trust-upload HTTP route.
Stable errors reuse DENIED/NOT_FOUND/CONFLICT/INVALID_INPUT/POLICY_BLOCKED/STORE_UNAVAILABLE plus
SIGNATURE_INVALID (422) and TRUST_UNAVAILABLE (403). Errors contain no source/token/key material.
Generated enterprise schemas cover the public models. No existing generated schema changed.
CLI is `agentsec team enterprise request/federation-export/verify-federation/export-siem/
verify-export/backup`; the private recipe gives exact arguments. It never selects ambient credentials.

Cases progress OPEN→TRIAGED→MITIGATING→RESOLVED→CLOSED; explicit terminal reopen and nonterminal
dismiss are supported. Resolution codes are controlled; HIGH/CRITICAL closure/dismiss requires a
HUMAN different from creator and resolver. Assignee must remain an active same-org HUMAN. Same-org
agent/receipt references are checked, including receipt/agent consistency. No notes/URLs/raw events.

Risk approval requires a distinct current HUMAN OWNER, current requesting role and exact current
target version/status. Expiry is >request time and ≤30 days, with exact-boundary EXPIRED. Target
change/supersession/closure or revoked/demoted participants produces STALE. Renewal needs a new ID.
Revocation/rejection is durable; a state transition does not attest remediation. GET derives current
risk disposition beside the original record. Historical retry responses are original records;
read current disposition before treating an approval as effective. No runtime/CI code consumes risk.

## 5. Simulation and minimized signed exports

Simulation snapshots candidate source/identity, publication/baseline state and selected inventory
versions under authorization. Shared compiler/diff/conformance runs outside the global write lock;
commit-phase read reauthorizes and compares exact snapshots before returning. Cohort ≤100 unique
agents; existing source/cardinality limits apply; output capped at 1 MiB. Protected expected current
published revision and plan are needed for COMPARED; absent/mismatched/unsupported material is
UNKNOWN, disabled agents INELIGIBLE. Directionless identity/configuration/timeout changes are
UNCLASSIFIED even when finite partition comparison exists. Cosmetic source/document change remains
distinct from unchanged executable policy. No simulation source body is emitted as telemetry.

SIEM pages use durable tenant audit order (relative sequence independent of other tenants), at most
1,000 records, typed org/format cursor and high water. Unknown/cross-org cursors fail closed. Each
page is a consistent snapshot; posture is snapshotted and audit version/current owner rechecked.
Facts on historical audit rows are explicitly **current snapshot observations**, not reconstructed
historical state. Purged report payload is MISSING; audit remains. Subsequent pages can observe
newer facts/high water; retaining original signed pairs preserves what was observed. Fingerprints
bind org/sequence/audit identity for downstream dedupe, not mutable observation fields. This is
at-least-once offline ingestion, not exactly-once delivery or a global multi-page frozen snapshot.

Projection allows only controlled actions/kinds/states/severity, opaque IDs, UTC timestamps,
versions, denied counter, CI outcome, posture/alignment/effect-evidence labels and assurance. No
policy source, raw SecurityEvent, prompts/results, resources/arguments, credentials, free-form
notes or URLs. Report records enforce REPORTED_UNVERIFIED; signed origin never elevates it.
Fixed-channel covert encoding by malicious reporters is not solved. A source comment canary is
stored only by deliberate opt-in policy ingestion and is absent from SIEM output; arbitrary case
notes are rejected at ingress. Signatures do not prove honest operators/reporters or secure hosts.

Manifest separately binds format, org, exact range/high water/count/length/SHA-256 and signing key.
Verifier checks independent pin/signature, exact bytes and canonical typed rows. Reorder/truncate/
append/edit, wrong key/domain/manifest, unknown key and embedded public-key additions fail. Output
uses private temp+fsync+exclusive hard-link publication without overwrite, plus directory fsync.
JSONL precedes manifest: interrupted pairs are unsigned until a matching manifest verifies.
No live SIEM connector or default transmission exists. The guide includes a generic field mapping.

## 6. Threat-by-test evidence

All new tests are credential-free with temporary private SQLite, fixed clocks and synthetic keys.
Names below are in `tests/integration/test_enterprise.py` unless otherwise specified.

| Threat/property | Named tests |
| --- | --- |
| Pinned recipient DRAFT/review, replay and rotation | test_federation_draft_retry_rotation_and_review |
| Wrong org/target/policy/mapping/key, expiry/future, identity mismatch | test_federation_scope_time_and_identity_fail_closed (8 cases) |
| Tamper before parse, revoked pin | test_federation_tamper_before_parse_and_revoked_pin |
| Algorithm/purpose/compiler/version/type/date/hash/unknown fields | test_federation_strict_wire (10 cases), test_duplicate_json_and_duplicate_pins |
| Revocation/trust/publication race during unlocked compile | test_federation_revocation_during_assessment (3 cases) |
| Case state/CAS/retry, high self closure | test_case_lifecycle_cas_retry_independent_severe_closure |
| Transaction failure and audit rollback | test_case_audit_failure_rolls_back |
| Self risk approval, exact expiry, target staleness/revocation | test_risk_independence_exact_expiry_stale_and_revocation; test_risk_expiry_bounds; test_risk_revision_supersession_and_approver_revocation |
| Governance never suppresses DENY, failing CI or posture | test_risk_does_not_suppress_runtime_deny_or_ci_failure |
| Role/kind/tenant mismatch, revoked actor/assignee | test_enterprise_mutation_role_and_tenant_denial; test_revoked_role_on_exact_retry_and_assignee; test_cross_tenant_case_risk_references |
| Missing baseline, protected alignment, disabled/unknown agents | test_simulation_missing_baseline_then_finite_and_unknown; test_simulation_unsupported_draft_is_unknown |
| Budget/permission/approval/identity/cosmetic differences | test_simulation_finite_categories (8 cases) |
| Revoked role/concurrent inventory/publication, unlocked compile | test_simulation_snapshot_race_and_outside_lock (3 cases) |
| Cohort bound/duplicate/cross-org inventory | test_simulation_bad_cohort_and_cross_tenant |
| Privacy, cursor scope, exact bytes, tamper variants, private output | test_export_scope_privacy_and_exact_byte_signature |
| Wrong purpose/key/manifest and embedded key | test_signature_domain_separation_and_pinned_key; test_signed_export_wrong_manifest_and_embedded_key |
| Golden canonical bytes/signature | test_fixed_canonical_export_vector; tests/fixtures/enterprise-signature-vector.json |
| Unsafe/missing/symlink signing key, failed export cleanup | test_protected_key_and_interrupted_export; test_key_path_missing_public_parent_and_unknown_db_version |
| Real v1 backup/reopen, unsafe WAL, injected backup failure | test_backup_restore_retains_enterprise_and_unsafe_wal; test_backup_failure_removes_only_new_output |
| Two SQLite connections CAS | test_two_connections_workflow_cas |
| Cross-org API, unknown/raw/duplicate input | test_enterprise_api_strict_input_and_roles |
| Actual CLI export/sign/verify and safe key failure | test_offline_cli_round_trip_and_sanitized_errors |
| No default network attempts | test_enterprise_no_network_dispatch |
| Reauthorization after posture snapshot | test_export_snapshot_reauthorizes_revoked_owner |
| Imports and real local gateway graph with optional packages blocked | tests/unit/test_enterprise_imports.py::test_default_imports_and_runtime_without_optional_dependencies |

Existing 103 control-plane tests and the full prior-phase suite preserve F10-01–04 and local runtime
semantics. Default-import testing found a preexisting eager MCP SDK import through a type-only
coverage annotation. Converting that import to TYPE_CHECKING with deferred annotations fixes the
default CLI without changing MCP coverage behavior. No dependency was added.

## 7. Verification commands and environment

Python 3.12.13, macOS 27.0.1 arm64, SQLite 3.50.4; pydantic 2.14.1, cryptography 50.0.2,
PyJWT 2.15.1, starlette 1.8.0, uvicorn 0.54.0, pytest 9.1.1, Ruff 0.17.1, mypy 2.4.0,
build 1.6.1. Run commands from the repository root.

| Exact command | Result |
| --- | --- |
| `.venv/bin/pytest -q tests/integration/test_enterprise.py tests/unit/test_enterprise_imports.py tests/integration/test_team_control_plane.py tests/unit/test_control_plane_projection.py` | PASS — 170 tests |
| `.venv/bin/pytest -q` | PASS — 1,052 tests, 2 inherited TLS deprecation warnings, 37.09s; approved loopback fixture access |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS — 232 files |
| `.venv/bin/mypy src` | PASS — 139 source files |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS — source-generated enterprise schemas |
| `.venv/bin/agentsec schema export --out /tmp/agentsec-phase11-final-schema` | PASS |
| `diff -ru --exclude=.gitkeep schemas/generated /tmp/agentsec-phase11-final-schema` | PASS — no drift |
| `.venv/bin/agentsec examples validate` | PASS — 3 contracts, 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS — 6 expected outcomes matched, including expected failures |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS — 2 ACTIVE passes, 1 DRAFT |
| `.venv/bin/agentsec graph validate --config examples/multi_agent/graph.json` | PASS — structurally valid, not authenticated |
| `.venv/bin/agentsec graph replay --config examples/multi_agent/replay.json` | PASS — SECURITY_SEMANTIC, 2 requests, 0 deliveries, no blockers |
| `.venv/bin/agentsec graph regression --case examples/multi_agent/regression.json --source examples/multi_agent/replay.json` | PASS |
| `.venv/bin/python examples/team/enterprise_demo.py` | PASS — two orgs, wrong destination/tamper denial, recipient review, finite/UNKNOWN, risk expiry, signed/tampered SIEM, backup and offline local graph |
| `.venv/bin/python -m build --no-isolation --outdir /tmp/agentsec-phase11-build` | PASS — wheel and sdist |
| `.venv/bin/python -I examples/team/package_smoke.py /tmp/agentsec-phase11-build` | PASS — archive contents, wheel imports and local protected graph |
| `.venv/bin/python -I examples/team/package_smoke.py /tmp/agentsec-phase11-build --without-extras` | PASS — wheel with crypto/JWT/HTTP/MCP/LangChain imports blocked |
| `.venv/bin/python -I examples/team/package_smoke.py /tmp/agentsec-phase11-build --sdist` | PASS — unpacked sdist imports and local protected graph |
| `.venv/bin/python -I examples/team/package_smoke.py /tmp/agentsec-phase11-build --sdist --without-extras` | PASS — unpacked sdist with optional imports blocked |
| `git diff --check` | PASS |

The first restricted full run during implementation reported 1,016 passes, 1 schema-drift failure
(before regeneration), and 11 socket-fixture setup errors. Regeneration resolved drift; approved
loopback access resolved the environment errors. An intermediate full run passed 1,047 tests.
New negative-test authoring also exposed missing test imports and the preexisting optional MCP
import described above; all are corrected. A schema comparison initially included repository
`.gitkeep`; the corrected command explicitly excludes it. No failed/environment-limited result
was counted as a pass. Final full test log was `/tmp/agentsec-phase11-final-tests.log`.

## 8. Operations, limits and independent-review questions

Synthetic consistent backup + integrity verification measured 0.0025s on the final demo's tiny
fixture (other runs 0.0026–0.0034s). Backup restoration/reopen and unsafe-sidecar rejection are
functional tests; no production RPO/RTO, availability, p95 latency, throughput or large-fleet
benchmark is claimed. The private recipe supplies the operator worksheet and recovery drill.
No Docker daemon/public TLS proxy/Windows ACL/real SIEM/IdP/production migration was tested.

Deliberate bounded deviations: retain SQLite v1 rather than add an unnecessary migration; use
reproducible nonroot POSIX local recipe rather than a container; individual case/risk reads rather
than bulk search UI; offline import/export rather than HTTP signing or trust configuration;
metadata references support known agent/receipt and exact risk targets, not arbitrary local replay
bundles/run digests; audit-retained page snapshots rather than an immutable multi-page export job.
No unsupported feature has a permissive placeholder/fallback. Graph semantics remain UNKNOWN in
enterprise simulation; actual Phase 9 behavior stays protected and tested separately.

Review particularly: complete caller/role matrix and historical retries; peer replay recovery after
restoring an older backup; exact signature canonicalization/pin lifetime; source privacy versus
explicit source sharing; concurrent snapshot invalidation; current-observation versus historical
SIEM semantics; durable file behavior under actual power loss/filesystem faults. Trusted operators,
host administrators, dishonest reporters, compromised keys, clock integrity, protected ancestor
directories and malicious Python application code remain outside the proven boundary. SQLite
is not tamper-evident. OS-level containment and trusted issuer provisioning remain operator work.

Documentation sweep updated current README/AGENTS/docs index, architecture appendix, managed
control-plane interaction, team examples/private runbook, Phase 11 plan status and report index.
Historical PRD, phase implementation reports and inherited acceptance caveats are preserved.
Readiness: **NEEDS_INDEPENDENT_REVIEW**, not release/production acceptance. No Phase 12 work.

## 9. Changed files

```text
AGENTS.md
README.md
docs/README.md
docs/architecture.md
docs/enterprise-security.md
docs/managed-control-plane.md
docs/plans/phase-11-implementation-plan.md
docs/reports/README.md
docs/reports/phase-11-implementation-report.md
examples/team/README.md
examples/team/enterprise_demo.py
examples/team/package_smoke.py
examples/team/private-reference.md
schemas/generated/enterprise-case-input.schema.json
schemas/generated/enterprise-case-transition.schema.json
schemas/generated/enterprise-case.schema.json
schemas/generated/enterprise-export-cursor.schema.json
schemas/generated/enterprise-export-manifest.schema.json
schemas/generated/enterprise-export-page.schema.json
schemas/generated/enterprise-federation-bundle.schema.json
schemas/generated/enterprise-federation-payload.schema.json
schemas/generated/enterprise-import-request.schema.json
schemas/generated/enterprise-pin.schema.json
schemas/generated/enterprise-risk-input.schema.json
schemas/generated/enterprise-risk-transition.schema.json
schemas/generated/enterprise-risk-view.schema.json
schemas/generated/enterprise-risk.schema.json
schemas/generated/enterprise-security-record.schema.json
schemas/generated/enterprise-signed-export.schema.json
schemas/generated/enterprise-simulation-input.schema.json
schemas/generated/enterprise-simulation.schema.json
schemas/generated/enterprise-trust-config.schema.json
src/agentsec/adapters/mcp/coverage.py
src/agentsec/cli/enterprise.py
src/agentsec/cli/main.py
src/agentsec/contracts/schema_export.py
src/agentsec/control_plane/api.py
src/agentsec/control_plane/errors.py
src/agentsec/control_plane/store.py
src/agentsec/enterprise/__init__.py
src/agentsec/enterprise/exports.py
src/agentsec/enterprise/federation.py
src/agentsec/enterprise/files.py
src/agentsec/enterprise/models.py
src/agentsec/enterprise/service.py
src/agentsec/enterprise/signatures.py
tests/fixtures/enterprise-signature-vector.json
tests/integration/test_enterprise.py
tests/unit/test_enterprise_imports.py
```
