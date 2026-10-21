# Phase 7 independent review fixes report

## 1. Baseline and scope

Applied the findings from `phase-7-sol-high-review-handoff.md` against reviewed implementation
SHA `9f81a491a5388854be896b2cbe40e4bd01f7dab0` (Phase 6 review-fix parent
`4dd82ea844638c536792cdb0efef206f6cacd6e9`). This report records corrections to the Phase 7
implementation; the original implementation report remains an historical record.

The unrelated untracked root file `PHASE-0-SOL-MEDIUM-PROMPT.md` was present before this work and
is intentionally excluded from the changes.

## 2. Findings addressed

### P1-01 — Bind policy resources to configured effect targets

Added `trusted_effect_resource` to protected tool metadata and the fixed HTTP/process action
configurations. Resource-scoped ENFORCE registration now fails if a new adapter has no fixed
effect-resource mapping. If an exact argument extractor is configured, its value must match the
trusted route target before the gateway is entered. The selected resource then flows through
policy, task/delegation scope, approvals, and action identity. Changing the configured target
changes the execution binding. MCP retains its discovery-bound resource semantics.

This supports fixed targets only. The setting is a reviewed operator assertion about the remote
service or executable; AgentSec cannot establish the semantics of a remote API or arbitrary
program from configuration alone. Dynamic target mappings without an established correspondence
fail closed in ENFORCE.

### P1-02 — Own and observe subprocess/container cleanup

Subprocess acquisition now waits for a cancelled spawn to resolve before terminating and reaping
the acquired process group. Docker no longer uses `--rm`; its protected random name remains
available for an explicit `docker rm -f` cleanup. Teardown runs as an owned, bounded task and
survives repeated cancellation while the caller waits. An unconfirmed cleanup raises
`ISOLATION_CLEANUP_UNCONFIRMED`, records a trace-integrity signal, and leaves cleanup ownership
visible through `pending_cleanup_count` and `drain_cleanup()`. No host fallback was added.

The Docker route identity was versioned for the lifecycle change. A later successful drain does
not alter evidence already recorded as unknown.

### P2-01 — State the LangChain callback boundary

Documented that callbacks, tracing, and LangSmith can observe inputs before gateway authorization,
including for denied calls. The API documents the same boundary. Added tests for callback ordering,
`.ainvoke()` and `.arun()` support, and the unsupported synchronous `.invoke()` / `.run()` paths.
Applications must apply a separate egress policy to framework callbacks and tracing; arbitrary
callbacks are not sandboxed.

### P2-02 — Pin HTTPS trust and disable ambient key logging

HTTPS now requires a protected PEM CA bundle. The adapter creates an explicit TLS 1.2+ client
context with certificate and hostname verification and does not consult `SSL_CERT_FILE`,
`SSL_CERT_DIR`, or `SSLKEYLOGFILE`. Added a local HTTPS server fixture signed by a controlled test
CA and verified a successful handshake with hostile ambient CA/key-log variables set. The
test-only server key is not used outside the local fixture.

### P2-03 — Preflight transport-specific inputs

HTTP method/body-size checks and process slot/name/NUL/argv-size checks now run before the gateway.
They perform no network, filesystem, or process effects. Invalid calls therefore cannot request
approval, commit a budget, or emit dispatch evidence. The mutable backend identity check remains
after approval and immediately before process execution.

### P2-04 — Separate event replay from candidate route fidelity

Added the versioned, content-free `CandidateRouteManifest` and separate `ReplayResult.route_comparison`
statuses. The ordinary trace diff remains a comparison of scripted policy/evidence events. Route
comparison is `UNKNOWN` without candidate metadata, `CHANGED` for an observed source route missing
from the candidate, and `INCOMPLETE` when historical source route facts are missing. Matching
routes report `UNCHANGED`. Replay still performs no live adapter/model calls. The API accepts the
candidate manifest; callers without one, including the CLI path, receive `UNKNOWN`.

### P2-05 — Redact resources in approval presentations by default

Approval presentations now show a digest for extracted resources unless trusted configuration
sets `approval_display_resource=true`. Explicit display remains bounded and sanitized. Added
broker-presentation tests for default redaction and reviewed opt-in, while confirming that the
resource remains absent from canonical evidence.

### P3-01 — Correct current and historical documentation

Updated the adapter guide, architecture, README, identity/delegation guide, replay guide, and
report index. Phase 6 boundary statements are labeled as historical, the `phase4-v1` replay note
is qualified inline, and the Phase 7 implementation and review-fixes reports are linked. Refreshed
generated schemas from canonical models, including the candidate route manifest.

## 3. Verification

| Command | Result |
| --- | --- |
| `.venv/bin/pytest -q` | PASS — 735 tests |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS — 164 files |
| `.venv/bin/mypy src` | PASS — 102 source files |
| `.venv/bin/agentsec examples validate` | PASS — 3 contracts, 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS — all 6 expected outcomes |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS — 2 ACTIVE, 1 DRAFT |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS — exported from canonical models |
| `.venv/bin/python -m build --no-isolation` | PASS — wheel and source archive |
| `git diff --check` | PASS |

The HTTP and HTTPS fixtures bind only to loopback. The full suite was run with the sandbox's
approved elevated socket access because the default workspace sandbox denies local socket bind.

## 4. Deviations and rationale

- Fixed-resource assertions are the only new HTTP/process resource mapping. General semantic
  analysis of server behavior or executable code would overstate what Phase 7 can prove; other
  mappings fail closed in ENFORCE.
- LangChain callbacks are not intercepted. They run outside the wrapped coroutine and can have
  their own egress effects, so the supported trust boundary is documented and tested instead of
  claiming callback containment.
- Candidate route comparison is exposed through the replay API. The CLI does not accept a route
  manifest and therefore reports route comparison as `UNKNOWN`.
- No compiler or authored contract semantics changed. Historical Phase 5/6 artifacts remain
  readable and retain their original identities.

## 5. Remaining limitations and open questions

- Fixed HTTP target and process target declarations remain trusted operator configuration; they
  do not attest remote service semantics, executable behavior, DNS results, code identity, image
  contents, Docker daemon behavior, or successful gVisor enforcement.
- A Docker daemon that cannot confirm cleanup leaves effect/cleanup status unknown. The backend
  retains cleanup ownership for a later drain; application shutdown must call `drain_cleanup()`
  for retained work.
- Live Docker/gVisor daemon smoke tests were not run. Unit tests use a fake process port for
  Docker CLI behavior.
- TLS deployments must supply an explicit CA bundle. System CA paths are intentionally not
  inherited; operators must protect and rotate the configured bundle.
- Framework tracing, arbitrary Python callables, trusted binaries, mount contents, and remote
  endpoints remain application/operator trust boundaries.

## 6. Readiness

The reported P1/P2/P3 findings are addressed, regression coverage and generated schemas are
updated, and all local repository gates pass. Phase 7 is ready for independent re-review. Phase 8
remains gated on independent Phase 7 acceptance and a reviewed Phase 8 plan. No Phase 8 supply-chain
service, Phase 9 agent graph, hosted control plane, or new sandbox runtime was added.
