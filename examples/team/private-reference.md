# Private single-node POSIX recipe

This recipe is a loopback reference for a dedicated **nonroot** account, Python 3.12+ and a
controlled local wheel. No production deployment, public proxy or container boundary is claimed.
The synthetic demo creates only temporary data and uses publicly known test keys:

```sh
.venv/bin/python examples/team/enterprise_demo.py
```

For a separately provisioned operator environment, use a private parent directory on a local
filesystem supporting SQLite WAL, hard links and fsync. Protect the entire path against other
writers. The following is a template, not an unattended installer; use explicitly reviewed paths
and separately issued tokens/public issuer configuration, never the demo issuer for real users.

```sh
umask 077
mkdir -m 700 private-agentsec
python3.12 -m venv private-agentsec/venv
private-agentsec/venv/bin/pip install '/reviewed/wheel.whl[control-plane]'
# Provision config.json and owner.json with the generated team schemas and independent public keys.
private-agentsec/venv/bin/agentsec team init private-agentsec/team.db private-agentsec/config.json private-agentsec/owner.json alpha
private-agentsec/venv/bin/agentsec team serve private-agentsec/team.db private-agentsec/config.json
```

`serve` binds 127.0.0.1:8765, disables access logs and forwarding headers, caps concurrency at 16,
and refuses nonloopback. Do not expose it through an untested public proxy. Network/OS containment,
issuer/key distribution, package integrity and account protection remain operator responsibilities.
There is no automatic outbound telemetry or dependency on enterprise availability in RuntimeGateway.

Signing keys belong to an **offline account/location outside the server directory**. Use separate
keys/pins per purpose in production. Independently deliver the public federation/export pins;
never copy an included sender key into trust without verifying its owner and exact scope. Trust
files must be private regular files. Remove/revoke a pin to disable it; key rotation preserves the
peer/policy replay high water. Do not delete federation records to make an old sequence work.

Offline CLI examples (replace each uppercase argument explicitly):

```sh
agentsec team enterprise request DB CONFIG TOKEN_FILE alpha case-open --request-file CASE_JSON
agentsec team enterprise request DB CONFIG TOKEN_FILE alpha case-transition --target CASE_ID --request-file TRANSITION_JSON
agentsec team enterprise request DB CONFIG TOKEN_FILE alpha risk-request --request-file RISK_JSON
agentsec team enterprise request DB CONFIG TOKEN_FILE alpha risk-transition --target RISK_ID --request-file DECISION_JSON
agentsec team enterprise request DB CONFIG TOKEN_FILE alpha simulate --request-file SIMULATION_JSON
agentsec team enterprise federation-export DB CONFIG TOKEN_FILE alpha REVISION beta LOCAL_POLICY SEQUENCE KEY_ID OFFLINE_KEY OUTPUT_JSON
agentsec team enterprise verify-federation BUNDLE_JSON PROTECTED_TRUST_JSON
agentsec team enterprise request DB CONFIG TOKEN_FILE beta federation-import --request-file IMPORT_JSON --trust PROTECTED_TRUST_JSON
agentsec team enterprise export-siem DB CONFIG TOKEN_FILE alpha KEY_ID OFFLINE_KEY OUTPUT_JSONL MANIFEST_JSON --after 0
agentsec team enterprise verify-export OUTPUT_JSONL MANIFEST_JSON PROTECTED_EXPORT_TRUST_JSON
```

Import JSON contains the signed bundle, explicit new local revision ID and expected publication
generation. It produces DRAFT only; ordinary submit/independent review/publish follows. Verify
commands authenticate bytes/source identities, never activate policy. Report counters remain
REPORTED_UNVERIFIED even when the export origin is verified. The cursor returned by export binds
org/format/last tenant sequence. Each page has its own consistent high water; subsequent pages may
observe newer facts. Consumers dedupe by fingerprint and retain original signed snapshots.

Recovery drill, performed **while stopped**, without overwriting the original:

```sh
agentsec team enterprise backup private-agentsec/team.db private-agentsec/backup.db
cp -p private-agentsec/backup.db private-agentsec/restored.db
chmod 600 private-agentsec/restored.db
agentsec team posture private-agentsec/restored.db private-agentsec/config.json PROTECTED_TOKEN alpha
```

Measure elapsed backup, restore and successful synthetic read/deny time; record file size,
Python/SQLite/package versions and error codes. Exercise the independent offline graph demo while
the service is stopped. Retain original DB and pins for rollback. Reopening refuses unsafe owner,
mode, symlink, DB/WAL/SHM or schema version. Never chmod an untrusted live path as implicit admission;
repair an offline copy in the private directory. Consistent backups must include records/audit and
federation high water; an old backup can re-enable historical peer sequences. Lost replay state
requires independently reviewed peer/key recovery, not blind restoration. No schema migration is
needed for Phase 11: user_version=1 generic records are retained. Unknown versions remain refused.
Backup integrity is tested; power-loss safety across all filesystems is not claimed.

Export writes JSONL first, then the separate signed manifest. If interrupted, treat an unmatched
JSONL as unsigned, quarantine it and retry with new output names and the same cursor. Existing
files/symlinks are never overwritten. Manifest verification detects byte edits/reordering/truncation.
Do not ingest a pair that fails verification. SIEM ingestion is offline at-least-once; no connector
or remote delivery promise is provided.

Support/SLO worksheet: record build/version, opaque org, safe code, operation and timestamp;
measure loopback request success fraction and p95 latency, export lag, backup age, actual restore
latency and signature failures. Set environment-specific targets and a measurement window. During
an incident revoke affected membership/pin, stop the reference if storage/key integrity is suspect,
preserve a private backup and escalate to the operator with synthetic reproduction steps. Do not
attach tokens, private keys, policy source, tool arguments or raw events to support records. This
is a measurement/support template, not an SLA, staffed service or compliance certification.
