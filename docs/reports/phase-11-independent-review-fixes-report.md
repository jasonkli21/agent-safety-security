# Phase 11 independent review fixes report

## Baseline and status

- Review handoff: `agent-safety-security-phase-11-independent-review-luna-handoff.md`.
- Fix baseline: `06134c6` (`feat: implement phase 11 bounded enterprise security reference`).
- User request: address the six Phase 11 findings and commit the fixes as one commit.
- Scope: Phase 11 bounded local enterprise reference. No runtime authority, federation admission,
  hosted service, live migration, or production deployment behavior was added.
- Readiness: **READY FOR FRESH INDEPENDENT RE-REVIEW**. This report is not release acceptance.

## Finding dispositions

| Finding | Disposition | Correction and evidence |
| --- | --- | --- |
| F11-01 | FIXED | `ACCEPTED_RISK` requires a risk ID and accepts only an active approved risk scoped to the exact case and current version. Pending/stale/wrong target fails. Runtime, CI and posture remain independent. |
| F11-02 | FIXED | Every new case transition appends finite metadata history in the same transaction as case state, retry receipt and audit. Authorized `GET .../cases/{id}/history` exposes it. Legacy cases report a completeness starting version and receive no fabricated history. |
| F11-03 | FIXED | The shared candidate assessment runs once outside the lock; its declared identity, environment and principal are checked against each protected inventory agent. Per-agent `COMPARED` also requires protected published baseline plan alignment. Candidate binding mismatch returns `UNKNOWN / CANDIDATE_BINDING_MISMATCH`; synthetic identity-change fixture covers this. |
| F11-04 | SAFELY RE-SCOPED | Current verification remains unchanged. Export-only `--archival` requires a retained enabled pin, explicit `archive_until`, issue time within original key validity, and no effective `revoked_at` at/before asserted issuance. Caller cannot set verification time. Signature output labels the time `ISSUE_TIME_ASSERTED`; absent a trusted timestamp service, this is not proof of creation time. Federation import never uses archival mode. |
| F11-05 | FIXED | Post-link write failure compares destination and temporary device/inode, unlinks only this invocation's destination, and syncs cleanup. Uncertain ownership/cleanup produces `PUBLICATION_UNCERTAIN`. Two-file JSONL/manifest semantics remain fail-closed: a data-only orphan is unsigned and must be quarantined. |
| F11-06 | SAFELY RE-SCOPED | SQLite v1 and its tenant-relative cursor semantics remain unchanged. A hard 10,000-row **global** audit ceiling bounds count/page/append scans; append fails closed with `AUDIT_CAPACITY`, and export rejects over-cap legacy stores before count/paging. This is intentionally availability-coupled across tenants and requires a separately reviewed schema/index migration before larger use. No large-data latency target is claimed. |

## Compatibility and retained limits

- `user_version=1` is unchanged; no automatic DDL, migration, audit rewrite, or sequence/cursor
  reinterpretation is performed.
- New optional Pin fields are backward-compatible in `enterprise-v1`: `archive_until` and
  `revoked_at` are only required for archival export verification, never federation admission.
- New case transitions add records using the existing generic records table. Historical case
  transitions before this change are unavailable; new history explicitly records its starting
  version. The existing 1,000-record-per-kind cap bounds history.
- Per-agent comparison proves finite policy and identity applicability only. It does not attest
  loaded bytes, dispatch, model behavior, or future effects.
- Directory fsync and hard-link durability remain filesystem/OS dependent. On a failed manifest
  write, a JSONL data file may exist without a manifest and is never a verified pair.
- The global audit cap is a finite reference boundary, not a capacity/SLO claim. Full 10k/100k
  benchmark and concurrent-writer latency target were not established.
- Inherited Phase 7–10 independent acceptance remains open. The Phase 11 fix run does not imply
  release acceptance; the reviewer-reported Linux/OpenSSL ambient-CA TLS failures remain a separate
  inherited environment gate pending supported-host verification.

## Verification

Environment: Python 3.12.13, macOS 27.0.1 arm64, SQLite 3.50.4, Pydantic 2.14.1,
cryptography 50.0.2, PyJWT 2.15.1, Starlette 1.8.0, pytest 9.1.1, Ruff 0.17.1, mypy 2.4.0,
build 1.6.1.

| Exact command | Result |
| --- | --- |
| `.venv/bin/pytest -q tests/integration/test_enterprise.py tests/unit/test_enterprise_imports.py tests/integration/test_team_control_plane.py tests/unit/test_control_plane_projection.py` | PASS — 175 tests (baseline before edits: 170) |
| `.venv/bin/python -m pytest -q` | PASS — 1,057 tests, 2 inherited `ssl.PROTOCOL_TLS` deprecation warnings. Initial sandbox attempt could not bind local fixture servers; rerun with loopback access passed. |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS — 233 files |
| `.venv/bin/mypy src` | PASS — 139 source files |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS — generated from typed models |
| `.venv/bin/agentsec schema export --out /tmp/agentsec-phase11-fixes-schema` | PASS |
| `diff -ru --exclude=.gitkeep schemas/generated /tmp/agentsec-phase11-fixes-schema` | PASS — no drift |
| `.venv/bin/agentsec examples validate` | PASS — 3 contracts, 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS — 6 expected outcomes matched |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS — 2 ACTIVE passes, 1 DRAFT |
| `.venv/bin/agentsec graph validate --config examples/multi_agent/graph.json` | PASS — structurally valid, not authenticated |
| `.venv/bin/agentsec graph replay --config examples/multi_agent/replay.json` | PASS — 2 requests, 0 deliveries, no blockers, `SECURITY_SEMANTIC` |
| `.venv/bin/agentsec graph regression --case examples/multi_agent/regression.json --source examples/multi_agent/replay.json` | PASS |
| `.venv/bin/python examples/team/enterprise_demo.py` | PASS — signed federation draft, identity applicability, risk expiry, SIEM tamper rejection, backup, local graph |
| `.venv/bin/python -m build --no-isolation --outdir /tmp/agentsec-phase11-fixes-build` | PASS — wheel and sdist |
| `.venv/bin/python -I examples/team/package_smoke.py /tmp/agentsec-phase11-fixes-build` | PASS — wheel with optional integrations |
| `.venv/bin/python -I examples/team/package_smoke.py /tmp/agentsec-phase11-fixes-build --without-extras` | PASS — wheel with optional imports blocked |
| `.venv/bin/python -I examples/team/package_smoke.py /tmp/agentsec-phase11-fixes-build --sdist` | PASS — sdist with optional integrations |
| `.venv/bin/python -I examples/team/package_smoke.py /tmp/agentsec-phase11-fixes-build --sdist --without-extras` | PASS — sdist with optional imports blocked |
| `git diff --check` | PASS |

The full suite's TLS tests passed on this macOS environment. The independent handoff also records
an inherited Linux/OpenSSL ambient-CA test gate; that cross-platform result was not reproduced here.
No 10k/100k latency benchmark, competing-tenant timing target, power-loss test across filesystems,
or production deployment test was performed.

## Changed files

Included: `docs/enterprise-security.md`, `docs/reports/README.md`,
`examples/team/enterprise_demo.py`, `examples/team/private-reference.md`, four generated enterprise
schemas, `src/agentsec/cli/enterprise.py`, `src/agentsec/control_plane/{api,errors,store}.py`,
`src/agentsec/enterprise/{exports,files,models,service,signatures}.py`, and
`tests/integration/test_enterprise.py`.

This report is also included. The unrelated pre-existing `PHASE-0-SOL-MEDIUM-PROMPT.md` remains
untracked and is not part of the fix commit.
