# Phase 8 Independent Review Fixes Report

## 1. Baseline and scope

Review target: `b36bf43fb0b242d0f8ea9566edc87c491a18d460` (`feat: implement phase 8 supply-chain trust admission`).
The attached handoff identified P1-01, P2-01 through P2-05, and P3-01. The worktree also contained
an unrelated untracked `PHASE-0-SOL-MEDIUM-PROMPT.md`; it remains untouched and is excluded from
the commit. Phase 7 independent acceptance remains unconfirmed and is not implied by this report.

## 2. Findings and disposition

| Finding | Change | Remaining limit |
| --- | --- | --- |
| P1-01 startup before admission | Trust-enabled ENFORCE stdio now refuses to connect unless protected config declares `launch_boundary: operator_managed`; the check is before the SDK can spawn the process. Runtime and operator docs describe the boundary and pre-discovery ordering. | This is an external deployment prerequisite, not executable verification. Agentsec still cannot verify that the OS boundary controls the executable. No broad pre-execution/server-integrity claim is made. HTTP contact also precedes tool admission. |
| P2-01 unrelated file as implementation proof | `require_artifact` now rejects with `TRUST_ARTIFACT_ASSOCIATION_UNVERIFIABLE`, whether or not candidate-mapped local bytes match. `LOCAL_BYTES` remains only an observation of bytes at an operator-selected path. | No current adapter proves a generic Python callable or process is executing those bytes. |
| P2-02 incomplete inventory succeeds | Versioned `TrustLock.required_candidates` expresses operator-required presence independently of pins. CLI verify and strict live MCP startup fail on missing required IDs. Empty defaults preserve older locks' allow-if-present behavior. | Required presence is explicit; operators must review the set. It adds no trust pin or authority. |
| P2-03 unbounded pagination | Trust-enabled live discovery enforces 128 pages, 2,048 tools and 8 MiB of serialized tool metadata cumulatively before retaining each page. | The SDK decodes a page before these checks. Per-message decoding/body limits remain SDK/transport-owned and are documented. |
| P2-04 opaque dependency names | Declared manifests now expose normalized package names, extras, registry specifiers, source kind, and stable conflict flags. Direct-reference URLs are digest-only; declaration and marker details remain content-minimized. Same-package declarations aggregate and flag conflicting constraints or sources. | This remains a declared-only inventory, not a resolved dependency graph, installed-byte hash or complete SBOM. Unsupported requirement syntax fails closed. |
| P2-05 baseline diff workflow | Documentation now requires retaining the reviewed full inventory beside its lock and demonstrates comparing that baseline with a fresh capture. The lock remains a compact fingerprint set. | Per-field diagnosis is unavailable if the operator discards the baseline inventory. |
| P3-01 report index | Added Phase 8 implementation and review-fix report links. The PRD links to implementation coverage without changing roadmap scope. | None. |

Generated schemas were regenerated from models. The synthetic MCP inventory and reviewed fixture lock
were refreshed because the explicit launch-boundary configuration is part of the protected route
digest. Historical Phase 6 hashes, old trust fingerprints' meaning, and omitted optional event fields
were not redefined.

## 3. Documentation and architecture updates

Updated the Phase 8 plan, supply-chain guide, MCP runtime guide, architecture, threat model, adapter
isolation, evidence, replay, PRD coverage note and report index. The documents now state that MCP
process startup/endpoint contact precedes tool discovery, a missing dispatch event does not establish
absence of startup effects, launch trust is externally managed, required-set completeness differs
from observed-subset equality, and file observation differs from execution binding.

## 4. Verification

| Command | Result |
| --- | --- |
| `.venv/bin/pytest -q tests/unit/test_supply_chain.py tests/integration/test_mcp_gateway.py` | PASS — 143 tests |
| `.venv/bin/pytest -q` | PASS — 822 tests in 26.34s with loopback test-server permission |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS — 178 files |
| `.venv/bin/mypy src` | PASS — 110 source files |
| `.venv/bin/agentsec examples validate` | PASS — 3 contracts, 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS — all 6 expected outcomes matched |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS — 2 ACTIVE passes, 1 DRAFT |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS — generated schemas updated from models |
| `.venv/bin/python -m build --no-isolation` | PASS — sdist and wheel |
| `git diff --check` | PASS |

The first sandboxed full-suite attempt had 813 passes and 9 setup errors because loopback socket
binding was denied for existing HTTP adapter fixtures. The same full command passed after granting
the required local test-server permission. No external service, live production server, malicious
executable, Docker daemon or remote registry was used.

## 5. Deviations and remaining limitations

P1-01 is resolved at the documented architecture boundary: untrusted stdio launch is a deployment
no-go unless an external operator-managed boundary controls it. This patch does not claim agentsec
independently verifies that boundary. A backend that binds immutable executable identity to process
creation remains future work. Remote MCP identity, loaded Python code, Docker image/daemon state,
complete transitive dependencies and Phase 7 independent acceptance also remain open limits.

## 6. Readiness

The review findings in this handoff have implementation or documentation dispositions, and the full
local suite and quality gates pass. Phase 8 is ready for a fresh independent review of this fix commit.
Combined Phase 7–8 release acceptance remains **NOT CONFIRMED** pending independent Phase 7 review
and review of the external stdio launch prerequisite.
