# Enterprise security reference (enterprise-v1)

Status: IMPLEMENTED_REFERENCE / NEEDS_INDEPENDENT_REVIEW. Phases 7–10 acceptance remains open.
This optional single-node POSIX reference adds governance only. No runtime imports this package.

```text
Protected offline pin + signed source -> verify -> local compile -> recipient HUMAN DRAFT
JWT -> current tenant membership -> case / risk / finite simulation -> scoped SQLite
Scoped audit + minimized facts -> offline JSONL -> separate offline signature -> pinned verifier
RuntimeGateway / local approvals / trust / graphs continue with all enterprise services absent
```

## Contract and bounds

All wire models reject unknown fields/coercion; ingress uses the duplicate-rejecting existing
loader. IDs are bounded ASCII labels; times must be UTC, signatures Ed25519, SHA-256 digests.
Canonical bytes are project canonical JSON: UTF-8, sorted keys, compact separators, explicit
null/default fields, UTC Z dates, ordered arrays, no Unicode normalization. Signature is excluded
from the payload. Prefix bytes are `agentsec:enterprise-v1:federation\n` and
`agentsec:enterprise-v1:export\n` (a literal LF). Algorithm, purpose and key ID are signed.
A pin independently binds purpose/key/origin/target/source-policy/local-policy and validity.
Pins are protected offline files; no HTTP trust provisioning or embedded-key trust exists.
Private keys are private regular POSIX files used only by offline CLI. Federation admission uses
only a currently enabled, in-window pin. Export verification also has an explicit archival mode:
the protected pin must carry `archive_until`, the manifest issue time must be within the pin's
original validity, and `revoked_at` (if set) must follow issue time. The verifier's current time
must not exceed `archive_until`; callers cannot supply a historical `--at` value. Routine expiry
can preserve verification, while key compromise requires an operator-recorded effective revocation
time. Keep retired public pins and revocation metadata in protected backup. Archival mode applies
only to SIEM exports and never federation imports. The signed issue time is signer-asserted; without
an independent timestamp authority, archival verification establishes signature integrity and
consistency with operator pin history, not when the signature was actually created. CLI output
labels this as `ISSUE_TIME_ASSERTED`.
A signer authenticates bytes, never running code, host identity or truthful reporter claims.

Source export is deliberate and separate from telemetry: explicit origin/target/signer selection.
Source max 64 KiB, envelope/file max 1 MiB; policies reuse Phase 10 cardinality bounds. Cohort max
100 unique IDs, stored records max 1,000 per kind/tenant; export max 1,000 audit records per page.
No arbitrary notes, URLs, arguments, raw events or source are accepted by incident/risk/SIEM types.
Allowed enum/opaque-ID channels can still encode information; this is minimization, not detection.

## Roles and interfaces

All operations reauthorize current tenant membership and token expiry, including retries.
SERVICE/VIEWER can read individual cases/risks only; REPORTER cannot use enterprise workflows.

| Operation | HUMAN roles | Endpoint POST under /v1/orgs/{org}/enterprise/ |
| --- | --- | --- |
| Open case / request risk / simulate | OWNER, EDITOR | cases / risks / simulate |
| Triage / mitigate | OWNER, EDITOR | cases/{id}/transitions |
| Resolve / dismiss | OWNER, REVIEWER | cases/{id}/transitions |
| Close / reopen | OWNER | cases/{id}/transitions |
| Decide/revoke risk | OWNER, distinct from requester for approval | risks/{id}/transitions |
| Federation import | OWNER, EDITOR | Offline authenticated CLI/service only |
| SIEM snapshot | OWNER | Offline authenticated CLI/service only |
| Case/risk read | all members, VIEWER SERVICE | GET cases/{id}, risks/{id} |

Request/response models are generated as enterprise schemas. Errors reuse DENIED (403),
NOT_FOUND (404), CONFLICT (409), INVALID_INPUT/POLICY_BLOCKED (422), STORE_UNAVAILABLE (503),
plus SIGNATURE_INVALID (422), TRUST_UNAVAILABLE (403). Existing ingress size/time limits apply.
There is no private-key HTTP endpoint. Offline `team enterprise` accepts typed request files
with explicit DB/config/token/org. Signing and verification commands do not contact a service.

Cases: OPEN → TRIAGED → MITIGATING → RESOLVED → CLOSED; OWNER reopen to OPEN from terminal
states; REVIEWER/OWNER dismiss nonterminal cases with a resolution code. HIGH/CRITICAL closure
requires a HUMAN distinct from creator and resolver. An enabled HUMAN assignee is required.
Transitions are CAS with actor/request-bound exact retry and transactional audit. Every new case
transition also appends a metadata-only history entry with exact versions, actor, UTC time, states,
finite resolution and optional accepted-risk ID. `GET .../cases/{id}/history` is member-readable;
SERVICE/VIEWER visibility matches individual case reads. History writes, case state, retry receipt
and audit commit together. Existing cases have no fabricated history: `complete_from_version`
marks the version before the first recorded post-upgrade transition. History uses the existing
1,000-record per-kind bound. `ACCEPTED_RISK` requires an explicit risk ID that is approved, active,
scoped to this case and its exact current version. Pending, expired, revoked, stale, unrelated or
missing risk cannot resolve a case as accepted.
Risk targets are exact case/revision versions. REQUESTED → APPROVED/REJECTED; APPROVED → REVOKED.
Approval requires distinct HUMAN OWNER, current target/requester and future expiry ≤30 days from
request. At exact expiry disposition is EXPIRED; changed target or revoked requester/approver is
STALE. Renewal creates a new ID. Risk is annotation only and cannot change CI/posture/PDP.

Simulation snapshots candidate/publication/inventory, assesses once outside the write lock,
then reauthorizes and checks exact snapshot. COMPARED requires protected expected plan and current
published revision alignment, plus exact candidate agent ID, environment and principal/owner
binding to that enrolled agent. Any candidate binding mismatch is UNKNOWN with
`CANDIDATE_BINDING_MISMATCH`; missing/stale/unsupported baseline is UNKNOWN/UNCLASSIFIED; disabled
agents are INELIGIBLE. No claim about loaded bytes, model behavior, tools, graphs or future effects.
Finite change categories/conformance/coverage are advisory; policy source never enters telemetry.

## Storage, export and recovery

Existing user_version=1 generic tenant-qualified records are sufficient; no DDL change or migration
is introduced. New kinds are additive; no automatic upgrade or live migration occurs. To keep
single-instance audit scans bounded without changing schema, the reference has a hard cap of
10,000 total audit rows across all tenants. At capacity, audited mutations fail closed with
`AUDIT_CAPACITY`; export refuses an already-over-cap legacy database before counting or paging.
This deliberate global ceiling creates cross-tenant availability coupling and requires a separately
reviewed schema/migration design before larger deployments. Export pages remain at most 1,000 rows,
and cursor offsets above 10,000 fail. No large-fleet throughput or production latency is claimed.
Existing
private DB/WAL/SHM admission and immutable source triggers remain. Unknown versions fail closed.
Offline backup uses SQLite backup plus integrity check, exclusive private output and cleanup on
failure. Restore only to private regular owner files while service is stopped; preserve protected
JWT and federation pins separately. Windows restored databases/signing files remain unsupported.

SIEM uses the durable append-only tenant audit sequence as cursor; cursor embeds org and format.
Each row has stable fingerprint, tenant sequence, controlled action and strictly projected
case/risk/report facts at snapshot. Purged report facts are explicitly MISSING; audit is retained.
Projection is an observation at snapshot time, not a reconstruction of historical case state.
A repeat at the same unchanged snapshot yields identical bytes. Consumers dedupe by fingerprint
(org, sequence, audit identity); mutable observation fields may change on a later snapshot.
No arbitrary SQL/filter cursor. Short consistent snapshot; JSON/sign/write occurs outside lock.
A separate manifest signs exact bytes/count/range/org/digest/format. Export uses private temporary
file, fsync and exclusive atomic link (no overwrite). A directory-fsync failure after publication
attempts to remove only the destination inode linked by that invocation and fsyncs cleanup; if
ownership cannot be established or cleanup fails, the CLI reports `PUBLICATION_UNCERTAIN`. JSONL
and manifest are separate artifacts. If manifest publication fails, JSONL may remain as an unsigned
orphan; quarantine it and retry with new names. Accept only verified pairs.
Signed origin remains separate from REPORTED_UNVERIFIED report assurance. No live SIEM transmission.
Mapping: sequence→event.sequence, at→@timestamp, kind→event.category, action→event.action,
actor→user.id, target→event.id, assurance→agentsec.assurance. Never promote reporter assurance.

## Private operations and support

Use a dedicated nonroot POSIX account, umask 077, private parent directory and Python virtualenv;
install the controlled wheel with control-plane extras. Run `agentsec team serve` on 127.0.0.1 only.
Do not put signing keys in the server volume. No public proxy/listener, HA or container isolation
claim. Reproduce locally with `python examples/team/enterprise_demo.py`; no credentials/network.
Stop service before backup/restore or changing trust. Verify backup integrity, reopen restored copy,
verify immutable source identities, and execute synthetic read/deny checks before resuming. Keep
original DB untouched for rollback; never restore an older DB as a way to reset federation counters.
After lost storage, rotate peer trust/sequence scope under a separately reviewed recovery procedure.

Support triage: record version, safe error code, schema version, timestamp, org opaque ID and
operation; reproduce using synthetic data. Never collect tokens, source, private keys or raw traces.
For signature failure quarantine the pair, independently verify pin/key/time and regenerate from
trusted storage. For CONFLICT refresh versions; for interrupted output remove only known temp files.
Revoke compromised memberships/pins, stop service, preserve a private consistent backup and involve
an operator. Proposed SLO measurements: loopback request success/error rate, p95 latency, export lag,
backup age, measured restore duration and signature failure count. Operators choose targets and
measure in their environment. No staffed support, commercial SLA, certification or recovery promise.

Unsupported: remote federation/autosync, activation, hosted SaaS, public ingress, live SIEM, arbitrary
analytics, runtime/TPM attestation, source secret scanning, semantic forecasts, distributed quotas,
automated remediation and Phase 12 recommendations. Privileged host/operator and compromised keys
remain trusted risks. Independent review is required before any release acceptance.


Foundation-readiness correction: the audit append guard checks the existing 10,000th row before
appending, allowing exactly 10,000 total rows. A further append raises AUDIT_CAPACITY inside the
governance transaction, rolling back its mutation. The ceiling remains global across tenants;
one tenant can exhaust shared availability. No SQLite schema/cursor change or automatic purge.
