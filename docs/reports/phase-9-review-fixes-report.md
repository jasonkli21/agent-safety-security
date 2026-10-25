# Phase 9 Independent Review Fixes Report

## 1. Baseline and scope

Review target: `6c1a1854c843a3cedf7413a89ad6c8e2498b454f` (`feat: implement phase 9 local multi-agent security`), parent `1619ac45da9edd54425f116f70acc5d3e72825e8`. The attached 2026-10-24 review handoff reported two P1 and three P2 findings. The fixes below are scoped to those findings and the handoff's additional exact-route replay check; no Phase 10 or hosted services were added.

The reviewed target was clean at preflight. The unrelated untracked `PHASE-0-SOL-MEDIUM-PROMPT.md` was present during this fix session, left untouched, and excluded from the changes. Generated schemas and historical contracts were not changed. Phase 7 and Phase 8 independent acceptance remain unconfirmed; this report does not close those gates or mark Phase 9 independently accepted.

## 2. Findings and disposition

| Finding | Disposition | Remaining limit |
| --- | --- | --- |
| F9-01 — replay accepts message import after recipient/ancestor revocation | Graph replay now tracks run identity and participant admission/retirement, requires both endpoint paths to be live at send and import, and blocks imports after revocation or run finish. Retired nodes cannot be readmitted. A rejected reordered import is not counted as a verified delivery, and graph promotion stays DRAFT / regression is BLOCKED. | Replay is still an offline reconstruction of one recorded graph epoch; it does not authenticate evidence storage or prove model ingestion. |
| F9-02 — inherited TLS trust store may include ambient roots | HTTPS context creation now checks the effective trust anchors against the exact configured PEM certificates. It uses an empty generic TLS context when the client context is preloaded and fails closed if it cannot obtain an exclusive store. Tests cover exact custom-CA success, wrong CA/hostname rejection, a simulated preloaded client-context fallback, and fail-closed behavior when both construction paths carry ambient roots. | The reviewer’s Python 3.12.14 / OpenSSL 3.5.8 environment was not available here. Local verification used Python 3.12.13 / OpenSSL 3.5.6; the ambient-root cases were simulated, not reproduced on that exact runtime. The generic TLS fallback emits Python’s `PROTOCOL_TLS` deprecation warning. |
| F9-03 — stale pending approval reserves shared quota after revocation/replacement | The hierarchical coordinator eagerly invalidates pending receipts whose ancestry or graph binding is no longer live when a node is revoked or the graph is replaced. Late broker completion cannot dispatch with the stale receipt; invalidation and later gateway cleanup are idempotent. Committed/entered effects remain charged. | Cross-process quota coordination and model/cost budgets remain unsupported. |
| F9-04 — one `RuntimeEvents` recorder can be shared across participants | A recorder binds to one graph participant and its run/trace identity is immutable. Session activation rejects recorder reuse and colliding participant run/trace IDs before emitting the second `RUN_STARTED`. Separate recorders may continue to share an event sink. | The recorder identity is a protected in-process wiring invariant, not cryptographic evidence authentication. |
| F9-05 — replay accepts impossible request/dispatch timestamps | Replay enforces nondecreasing per-run event time and causal ordering across request, decision, approval, dispatch, return, and exposure evidence. Approval decisions must lie within the recorded approval window. Contradictions return an incomplete replay with a temporal blocker. | Timestamps are interpreted as one local session clock; replay does not establish trusted wall-clock time or cross-host clock consistency. |
| Additional route-identity check — source dispatch does not prove the fixed message route | Replay now checks the exact `message/{sender}/{recipient}` route identity and its source request/dispatch binding, along with sender run/trace identity. | This remains a source-evidence consistency check, not attestation that the protected route code was running. |

No historical Phase 4/6 meanings, compiled policy hashes, or omitted optional event fields were redefined. No schema field changed, so generated schemas remain unchanged.

## 3. Documentation changes

Updated the multi-agent, replay, evidence, architecture, and TLS isolation documentation to describe lifecycle and causal replay checks, pending-receipt invalidation, single-owner event recorder identity, exact route replay matching, and the fail-closed TLS trust-store rule. Current status pages retain the Phase 7–8 and fresh Phase 9 review gates.

## 4. Verification

Commands ran from the repository root. The full suite used approved loopback access for local HTTPS fixtures.

| Command | Result |
| --- | --- |
| `.venv/bin/pytest -q` | PASS — 882 passed in 24.05s; 2 expected `ssl.PROTOCOL_TLS` deprecation warnings in simulated fallback tests |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS — 197 files already formatted |
| `.venv/bin/mypy src` | PASS — 121 source files |
| `.venv/bin/agentsec schema export --out /tmp/agentsec_phase9_review_fix_schema_20261024` | PASS — schema export completed |
| `diff -ru --exclude=.gitkeep schemas/generated /tmp/agentsec_phase9_review_fix_schema_20261024` | PASS — generated schemas unchanged |
| `.venv/bin/agentsec examples validate` | PASS — 3 contracts, 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS — all 6 expected outcomes matched |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS — 2 ACTIVE passes, 1 DRAFT |
| `.venv/bin/python examples/multi_agent/local_session.py` | PASS — protected gateway scenario assertions passed |
| `.venv/bin/agentsec graph validate --config examples/multi_agent/graph.json` | PASS — structurally valid; authentication is not claimed |
| `.venv/bin/agentsec graph replay --config examples/multi_agent/replay.json` | PASS — SECURITY_SEMANTIC, 2 checked requests, 0 deliveries, no blockers |
| `.venv/bin/agentsec graph regression --case examples/multi_agent/regression.json --source examples/multi_agent/replay.json` | PASS |
| `.venv/bin/python -m build --no-isolation --outdir /tmp/agentsec_phase9_review_fix_build_20261024` | PASS — wheel and sdist built |
| `git diff --check` | PASS |

Runtime observation: Python `3.12.13`, OpenSSL `3.5.6`; a fresh `PROTOCOL_TLS_CLIENT` context reported zero CA certificates before configured material was loaded. The reviewer’s reported `3.12.14` / OpenSSL `3.5.8` ambient-root setup was not reproduced on this host. The fallback and fail-closed behavior were exercised using simulated context construction, while the local HTTPS tests exercised the configured private CA, a different CA, and a hostname mismatch. No external endpoint, real credential, model, remote registry, Docker daemon, or hosted service participated.

## 5. Deviations and remaining limitations

The exact reviewer runtime was unavailable, so F9-02 has targeted implementation and simulation coverage but still needs reproduction on each supported deployment runtime, especially the reported Python 3.12.14 / OpenSSL 3.5.8 combination. The fallback uses the stdlib generic TLS protocol constructor, which is deprecated; it remains a fail-closed compatibility path and emits two test warnings. There was no schema change. Docker/gVisor smoke testing, remote authentication, distributed quotas, model-internal taint, semantic secret detection, and running-code attestation remain outside this review-fix scope.

## 6. Readiness

The five findings have code or documentation dispositions and the local verification gates pass. These changes are ready for a fresh independent Phase 9 review. They do not constitute independent acceptance. Phase 7 and Phase 8 acceptance remain open, and the exact TLS runtime reproduction remains an explicit environment-specific review item.
