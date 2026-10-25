# Managed team reference control plane (team-v1)

Phase 10 is an optional single-instance SQLite/HTTP reference service. Independent acceptance
of Phases 7–9 remains open. No production hosting or enterprise compliance is claimed.

```text
External issuer -- pinned Ed25519 JWT --> HTTP boundary --> membership RBAC --> scoped SQLite
Operator -------- offline bootstrap -----^                   |
Local evidence -- explicit minimized projection -------------> reports/posture
Local operator <-- authenticated immutable fetch ------------- registry/review
RuntimeGateway / compiler / graph: no control-plane dependency or remote authority input
```

## Design lock

All human, service and reporter identities use externally issued EdDSA JWTs, with operator-pinned
Ed25519 public keys, issuer and audience. Only `alg`, `kid`, `typ` headers are accepted. No remote
key lookup, token issuance, role claims, automatic IdP discovery or Phase 6 credential conversion.
Distinct `(issuer, subject)` bindings identify HUMAN, SERVICE or REPORTER callers. Membership and
reporter revocation are read from the database inside every service transaction. A human with
several memberships must select one organization in the path; there is no union of memberships.
SERVICE may read as VIEWER only; only HUMAN can manage, author, review or publish. REPORTER has
no membership role and may submit/read only its exact enrolled agent/environment/repository.
Operator changes pinned keys/config and restarts for rotation; membership/reporter revocation
applies on the next request. Same real human must have one provisioned binding; the operator is
responsible for external subject uniqueness across identity providers.

| Role | Read metadata/source | Draft/submit | Review | Publish/withdraw | Manage/purge |
| --- | --- | --- | --- | --- | --- |
| OWNER | yes | yes | other author only | yes | yes |
| EDITOR | yes | yes | no | no | no |
| REVIEWER | yes | no | other author only | no | no |
| VIEWER | yes | no | no | no | no |
| REPORTER | own status | no | no | no | own report only |

Offline `team init` validates the org, HUMAN owner and exact pinned issuer before creating storage.
The owner binding, org, membership and bootstrap audit are one transaction. If bootstrap fails,
the CLI closes and removes only the database and SQLite sidecars it created; an existing path is
never replaced. Retry with corrected inputs by rerunning `init`. Provisioning additional identity
bindings is offline operator work; owners manage only already provisioned identities through the
API. There is no public signup. Records and IDs cannot be recycled.

## Publication

Sources are opt-in bounded UTF-8 YAML/JSON strings stored only in immutable revisions, never in
audit or metadata reports. All members can deliberately fetch source; callers needing stronger
source compartmentalization require a later role extension. Revision ingestion recompiles exact
source with the existing strict parser and phase6-v1 compiler, computes document/effective/plan
hashes, synthetic conformance, coverage and finite semantic diff against the current publication.
Phase9 compilation is unsupported here because registry enrollment supplies no protected graph.
Limits bound policy rule/resource cardinalities before compilation. Unsupported intent blocks
submission; compiler/diff errors fail closed. Initial revisions compare against an explicit
no-publication baseline, requiring independent initial-policy acknowledgement. Unknown semantic
changes block submission; expansions, identity/budget/approval changes and coverage gaps require
separate fielded review acknowledgements. These are governance decisions, not runtime exceptions.

`DRAFT -> IN_REVIEW -> APPROVED -> PUBLISHED -> SUPERSEDED` is the normal path. A reviewer may
reject IN_REVIEW to WITHDRAWN; an owner may withdraw DRAFT/IN_REVIEW/APPROVED/PUBLISHED. Rework always
creates a new immutable draft. Every mutation binds expected version. Bounded parsing, compilation,
conformance, coverage and diff run outside the process-wide SQLite write lock. A short transaction
reauthorizes the actor and rechecks exact source, assessment, workflow version and publication
generation before the CAS write. Supersession and publication are one transaction. Stale
votes and sibling publish races conflict. Identical transition retries with the same actor/action/
expected version return the same result; changed retry contents conflict. No remote activation or
pin command exists. Fetch verification checks all three identities and never touches local config.

## API and failure contracts

All endpoints are `/v1/orgs/{org}/...`. GET collections accept bounded integer `offset` and `limit`
(1–100); no caller SQL/cross-org cursor. Collection families: members, reporters, agents, revisions,
reports, audit; GET posture and alerts; GET revisions/{id} and source; POST revisions, transitions,
members, agents, reporters, reports; POST metadata-purge. Exact JSON models and endpoint details
are in `api.py` and generated team schemas. All responses use JSON; no HTML rendering. IDs are
restricted opaque ASCII labels. Request bodies reject duplicates, unknown fields and coercion.
No policy content or validation input is reflected in errors. No request/access/token logs.

| Condition | HTTP / stable code |
| --- | --- |
| missing / invalid or expired JWT | 401 TOKEN_MISSING / TOKEN_INVALID |
| absent/revoked membership, wrong tenant or reporter scope | 403 DENIED |
| absent object inside authorized tenant | 404 NOT_FOUND |
| stale version/base, transition or retry conflict | 409 CONFLICT |
| unsupported compiler/policy, unknown semantics | 422 POLICY_BLOCKED |
| malformed/unknown fields or invalid counters/times | 422 INVALID_INPUT |
| wrong content type / oversized body | 415 CONTENT_TYPE / 413 TOO_LARGE |
| DB unavailable/corrupt/version mismatch | 503 STORE_UNAVAILABLE |

## Storage, minimization and operations

SQLite user_version=1, foreign keys, explicit initialization, WAL, bounded busy timeout, single
connection transaction lock. Tenant-qualified primary/foreign keys and scoped store methods;
immutable revision source/assessment columns protected by SQL triggers. Mutable workflow uses CAS.
On reopen, the database and existing WAL/SHM files must be regular, non-symlink files owned by the
current uid with no group/world permission bits before SQLite opens them. Unsafe restored paths fail
with `STORE_UNAVAILABLE`; move or repair a copy while stopped, then retry. The check is supported
on POSIX only; Windows ACL validation is not implemented, so reopening an existing DB there fails
closed. Newly initialized files are created private. Protect parent directories and backups too;
a privileged host administrator remains outside this boundary.
Durable governance audit stores only opaque actor/target/action/version/time, never JWT/source or
raw event content. Metadata receipts are separate and expire under explicit scoped purge; compact
idempotency tombstones survive purge so expired run IDs cannot replay/double count. Audit retention
is operator-managed and not tamper evident. Backup with SQLite online backup API while stopped or
using a consistent SQLite backup; restore database plus protected issuer config to a private path,
then start only after version/integrity validation. Unknown migrations are refused; no automatic
upgrade or destructive recovery. Host admins can inspect/modify all tenants.

Reports are a new fixed allowlist: opaque UUID run ID; enrolled agent/environment/repository;
optional opaque policy revision label; source RUNTIME/CI; bounded UTC period; fixed lifecycle
counters; completeness, coverage, CI, regression, replay (including BLOCKED) and runtime-mode
enums. No free text, URLs, arbitrary claims or labels, event IDs, hashes of private resources,
arguments, prompts, results, principal names/emails or raw SecurityEvent uploads.
Only protected inventory labels are echoed. Local projector deliberately counts selected typed
fields, never dumps an event/result. A compromised reporter can encode data in numeric/UUID
channels; allowlisting is minimization, not content detection or a covert-channel proof.
All reports are REPORTED_UNVERIFIED. `policy_alignment` is `UNKNOWN` without both an operator
expected published revision and a matching reporter-declared revision; an absent, mismatched,
superseded or withdrawn expected revision is a visible gap/mismatch. This opaque label is a claim,
not proof of loaded bytes or runtime activation. `effect_evidence` is `NONE` when no positive
effect count is reported and `REPORTED_UNVERIFIED` when one is; dispatched work with no reported
verified effect is a gap. A read-only run can still be `HEALTHY_REPORTED` if the other reported
dimensions align, while its effect evidence remains `NONE`. CI replay must be `PASS`; `UNKNOWN` or
`BLOCKED` remains a gap. `HEALTHY_REPORTED` means only that these self-reported, unverified fields
met the advisory classifier. A valid reporter can fabricate enums and counters. No heartbeat
attests loaded code, enforcement, model safety or graph membership. Advisory alerts derive from
no/stale reports and gaps/failures; there is no score,
pager delivery, guaranteed kill switch or claim of independently verified fleet protection.

API body cap 128 KiB, 10-second body timeout, 1,000 records per collection/org and bounded reports,
100-row pages, bounded compilation dimensions; SQLite timeout 2 seconds. Admission/concurrency
limits are configured at the ASGI server. CLI binds loopback only and refuses nonloopback even
behind a claimed proxy; public reverse-proxy/TLS deployment is deliberately deferred. For a future
proxy deployment require authenticated HTTPS, trusted forwarding configuration, body/time/rate
limits and protected storage. Local-only HTTP is for synthetic fixtures. No telemetry is sent by
default. Outage, absent IdP/network, corrupt DB and malformed remote responses fail team operations;
existing local contracts, approvals, gateway and graph continue autonomously. CLI/JSON replaces
frontend dashboard, SSO login UX and hosted alerts. No cloud provisioning is included.
