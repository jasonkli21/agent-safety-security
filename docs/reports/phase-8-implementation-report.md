# Phase 8 implementation report

## 1. Baseline, authority and review gates

Starting HEAD: `939c8582f5cec99b3f77b5d38703d7cf6d5d11e8` (`fix: address phase 7 review findings`).
HEAD matched the supplied plan; there were no newer commits or independent acceptance records.
Phase 7 corrections are implemented, but independent acceptance is **unconfirmed/pending**.
The explicit user request authorizes Phase 8 implementation despite that release gate; it does
not certify Phase 7 acceptance or Phase 8 correctness. Phase 9 remains out of scope.

Initial worktree: untracked `PHASE-0-SOL-MEDIUM-PROMPT.md` and the supplied
`docs/plans/phase-8-implementation-plan.md`. The latter is included as requested; the former is
unrelated and left untouched/untracked. All changes in this implementation are delivered in one
commit. Final HEAD is the single commit containing this report, whose exact SHA is recorded in
the final handoff response (a commit cannot embed its own resulting SHA). No earlier historical
implementation reports were rewritten.

Read the supplied handoff, repository operating contract, PRD/architecture, active Phase 8 plan,
Phase 7 plan and implementation/review-fix reports, focused runtime/adapter/identity/provenance/
evidence/replay/conformance/threat docs, and the relevant implementation/tests. The preproduction
change map identified gateway action/approval/budget/final-dispatch ownership, MCP discovery/list
visibility, protected rebinding, effect boundaries, additive evidence/replay fields and independently
protected trust inputs. Operational trust does not change compiler or authored policy semantics.

Environment: Python 3.12.13, Pydantic 2.14.1, MCP 2.3.0, cryptography 50.0.2,
langchain-core 1.6.12, pytest 9.1.1, Ruff 0.17.1, mypy 2.4.0; existing `.venv` on macOS arm64.
No package installation, download, model API, external network or Docker daemon was needed.

Initial `.venv/bin/pytest -q`: 726 passed, 9 setup errors because the workspace sandbox denied
loopback socket binding. Initial Ruff, format (166 files), mypy (102 source files) and build passed.
An elevated intermediate full run passed 734 tests with one expected generated-schema-current
failure while the new schemas were not yet exported. Later feature runs exposed and corrected
test fixture omissions, an overly broad privacy assertion, and the replay consistency gap below.
No existing authorization, network or isolation safety check was disabled to make tests pass.

## 2. File and API map

| Area | Implementation |
| --- | --- |
| `supply_chain/models.py` | Strict versioned immutable candidate/inventory, manifest, pin/lock/key/signature, assessment/diff/finding and protected input models; sorted and duplicate-rejecting collections |
| `supply_chain/inspection.py` | Qualified versioned observations, bounded no-follow regular-file SHA-256, declared TOML dependencies, proposed locks, differences and seven advisory rules |
| `supply_chain/registration.py` | Shared offline native/finalized protected-route and complete MCP capture builders |
| `supply_chain/verification.py` | Pure restrictive assessment, exact signed-byte envelope, SignatureVerifier port and real optional Ed25519Verifier |
| `supply_chain/guard.py` | Operator-owned lock, detached inputs, local artifact freshness, same-thread replacement epoch, admission/final checks |
| `supply_chain/io.py` | Bounded JSON, duplicate-key/depth rejection, strict safe diagnostics |
| `runtime/gateway.py`, `runtime/bindings.py` | Guard applies to every gateway call and protected registration; action-bound snapshot; final precommit check |
| `adapters/mcp/{discovery,server}.py` | Exact transport/binding/full discovery metadata route, frozen config, bounded trust inspection, strict startup/list/call admission |
| `domain/{approvals,events,replay}.py` | Omitted optional action snapshot, safe assessment/snapshot evidence, separate offline trust comparison |
| `replay/{bundle,engine}.py`, `eval/trajectory.py` | Trust record consistency, source-only trust facts, offline equality and explicit unavailable verification/failure substitution |
| `cli/{trust,protect,main}.py` | Offline inspect/scan/diff/verify/propose; MCP `--trust-lock` and protected `--trust-inputs` |
| Schema exporter and `schemas/generated/` | Eight generated trust schemas and additive embedded historical schemas |
| `examples/trust/` | Static separately reviewed synthetic native/MCP inventories and locks; captured tools; executable native allow/removal demonstration |
| Tests and focused docs | Adversarial pure/real SDK/stdio/adapter/effect-boundary cases and operator workflow |

All production types are local typed Python; no general plugin system, hosted registry, UI,
new sandbox, automatic declassification, policy engine or transitive delegation was added.

## 3. Trust ownership and design choices

Only the protected operator lock supplies expected fingerprints, required signers, pinned public
keys and admission requirements. Candidate metadata cannot supply expected hashes, replace keys,
set its own trusted status, or choose a runtime verifier. Proposals stay PROPOSED until deliberately
reviewed outside the tool interface. No startup discovery-to-auto-lock operation exists.

Qualified candidate IDs bind namespace/server/tool and adapter kind/ID. Fingerprints additionally
commit source kind, metadata/schema/description, route, classification and observed artifact/
dependency material. Schema and description retain their prior hash algorithms; new projections
use explicit v1 domains. Inventories/locks are immutable scalars/tuples rather than nested mutable
JSON, and guards detach every supplied model/mapping. Native/provider/framework routes have
distinct candidate IDs, permitting independent pins without aliasing the same-named tool.

A lock pin matches the entire candidate fingerprint, including metadata, rather than merely the
schema hash. Assessments separately state pin match, LOCAL_BYTES/UNOBSERVED and signature status.
COMPLETE_FOR_REQUIREMENTS means only the selected requirements were met. It is never complete
implementation assurance. Declared dependency provenance remains declared, and absent observations
remain INCOMPLETE in differences. Runtime registrations reconstruct candidates from protected
facts rather than trusting an inventory supplied in tool arguments.

Alternative rejected: metadata/publisher signature as code authorization or attestation. A trusted
candidate still goes through the original PDP. Alternative rejected: per-adapter enforcement;
all routes enter the shared gateway, including direct gateway calls omitting route metadata.
Rebinding requires another independently pinned route. MCP startup rejects partial strict coverage;
listing and invocation independently recheck the current lock.

## 4. Runtime modes and effect boundary

| Mode | Trust rejects | Contract deny | Broker | Dispatch |
| --- | --- | --- | --- | --- |
| ENFORCE | Blocks registration/preapproval; final drift invalidates pending approval | Still blocks admitted candidate | Only existing REQUIRE_APPROVAL, after successful admission | Only after all existing controls and final trust freshness |
| SHADOW | Reports would-reject; final drift signals without claiming enforcement | Recorded, can forward under existing semantics | Never invoked | May proceed with truthful failed assessment/signals |
| DISABLED | Skips trust observation/checks | Existing disabled policy behavior | Never invoked | Transport/isolation invariants remain enforced |

Malformed supplied lock/input configuration never silently removes the guard. Strict unknown,
changed, unreviewed or unsupported mandatory evidence fails before broker/reservation/commit/
dispatch. Final snapshot checking runs after approval and authority freshness and immediately
before budget commit, critical dispatch evidence and dispatcher entry, without intervening await.
Final failure releases the reservation and invalidates the one-shot approval. A replacement epoch
prevents away-and-back lock changes from preserving an outstanding approval. Cross-thread guard
inspection/replacement rejects; concurrent event-loop callers retain ordinary gateway ordering.

Cancellation, budget refunds, evidence failure, authority expiry, protected data exposure,
DISPATCH_CANCELLED_EFFECT_UNKNOWN, ISOLATION_CLEANUP_UNCONFIRMED, drain_cleanup, TLS CA selection,
Docker process ownership and no-host-fallback remain unchanged and covered by the full old suite.
Trusted in-process application code, evidence sinks and dispatch wiring remain in the TCB.

## 5. Cryptography and exact subject

The shipped optional verifier actually verifies **Ed25519** using cryptography. The `trust` extra
allows cryptography >=44,<51; installed/tested version is 50.0.2. Public keys are independently
pinned raw 32-byte hex values; no remote fetch, issuer certificate or candidate trust root is used.

The exact UTF-8 canonical JSON signed envelope contains domain
`agentsec.supply-chain-signature.v1`, schema_version `0.1`, candidate_id, subject_digest
(the complete candidate fingerprint), key_id, algorithm `Ed25519`, issued_at and expires_at.
The signature bytes are excluded. Validity is issued_at <= now < expires_at. Wrong key, candidate,
subject, domain or payload fails. Downgrade/malformed signatures fail strict parsing; unavailable
cryptography returns UNSUPPORTED and required proof rejects. No boolean signature substitute,
production private key, key generation service, remote revocation or runtime attestation is shipped.
Tests generate ephemeral test keys, sign the real envelope and verify actual signatures.

## 6. Cross-adapter and negative evidence

The final focused command below passed **138 tests**, including existing MCP protocol cases.
Phase 8 adds **82** tests to the 735-test inspected baseline, for **817 total**.
Coverage includes:

- ordering permutations, detached metadata, schema/description/revision/classification/route
  changes, server reuse, complete SDK metadata drift, same-name qualification and signature drift;
- strict versions/types/unknown fields/duplicate IDs/keys, input bounds/depth, malformed signatures,
  symlink components, FIFO/oversized file refusal, raw-byte versus JSON hashing and file substitution;
- independent roots, PROPOSED rejection, real Ed25519, wrong key/subject/domain/expiry/signer,
  algorithm downgrade, absent verifier, unsupported attestation/dependency coverage and privacy;
- strict registration and direct gateway omission rejection; trusted but policy-denied call;
  same/different lock generation or local-file substitution during approval with no dispatch and
  no committed budget; concurrent pending calls invalidated with reservations released;
- native success/evidence, all three provider shapes with independently pinned rebound routes,
  LangChain accepted/rejected routes, HTTP/process/Docker pre-effect rejection after pin removal;
- real MCP SDK allowed search, policy-denied write, unknown/substituted/unsupported startup,
  removed-pin hidden listing and denied invocation before broker, approval race with zero upstream
  effects, and the exact committed MCP fixture via two-process stdio host/gateway/upstream;
- historical full-suite behavior, replay with the live guard/file observer patched to fail if
  invoked, independent trust/route comparison and tampered trust-record refusal;
- deterministic CLI observe/propose/review/verify/scan/diff workflow and minimized diagnostics.

## 7. Raw-byte, dependency, endpoint and image proof limits

Local inspection is regular-file, nonblocking/no-follow and at most 1 MiB, with size/mtime stability
checks. A digest means observed bytes, not executing or loaded code. Parent-directory replacement
by a privileged process and file replacement after the final hash are not atomic hash-and-exec.
MCP/HTTP remote implementations, Python callable revision strings, Docker tags, image bytes,
daemon behavior and actual runsc containment remain unverified. No Docker/image download or
inspection is performed. Runtime-attestation requirements reject on every surface.

`pyproject.toml` ingestion includes declared optional dependencies and minimizes private URLs to
declaration digests. No resolution, package import, installed distribution hashing or complete
SBOM is claimed. `require_dependencies` explicitly rejects coverage-incomplete, even if a manifest
digest is pinned. `require_artifact` can require configured matching inspected local bytes; it does
not prove the route executes those bytes. Captured CLI inventory verification compares recorded
observations to reviewed expectations; only runtime configured artifact wiring rehashes local bytes.

## 8. Historical compatibility and offline replay

No compiler, authored contract semantics, phase6-v1 identity, effective-policy projection, prior
schema/description digest algorithm, historical bundle or regression fixture was modified.
Absent trust action/request/dispatch fields are omitted. Generated schemas add optional fields
and explicit 0.1 trust artifacts; source definitions, never hand edits, produced every schema.

Replay never reads files, discovers tools, verifies live keys or executes an adapter. It preserves
recorded trust facts as source facts, adds TRUST_NOT_REVERIFIED, and compares candidate observation
equality separately from route fidelity. No candidate yields UNKNOWN; missing historical source
facts yield INCOMPLETE. Source trust failure signals block substitution pending offline review.
Request/dispatch trust records must agree. No equality result is fresh signature/code attestation.
Historical evaluation/replay/regression/golden tests pass unchanged.

## 9. Exact verification commands and results

| Command | Final result |
| --- | --- |
| `git rev-parse HEAD` | Starting baseline above; final commit identity in handoff |
| `git status --short` | Starting untracked files above; unrelated Phase 0 file preserved |
| `.venv/bin/python --version` | Python 3.12.13 |
| `.venv/bin/pytest -q tests/unit/test_supply_chain.py tests/integration/test_mcp_gateway.py` | PASS, 138 tests |
| `.venv/bin/pytest -q` | PASS, 817 tests, 30.88 seconds; approved elevated loopback socket access |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 178 files |
| `.venv/bin/mypy src` | PASS, 110 source files |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts, 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS, all 6 expected outcomes |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS, 2 ACTIVE passes, 1 DRAFT |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS, generated from models |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel; build log in temporary local workspace |
| `.venv/bin/python examples/trust/pinned_native.py` | PASS, synthetic success then TRUST_ADMISSION_REJECTED after operator removal |
| `.venv/bin/agentsec trust inspect --mcp-config examples/mcp/gateway.yaml --mcp-tools examples/trust/mcp-tools.json > /private/tmp/phase8-observed-mcp.json` | PASS, offline capture inspection |
| `.venv/bin/agentsec trust verify /private/tmp/phase8-observed-mcp.json --lock examples/trust/mcp-lock.json` | PASS, all three fixture candidates admitted, artifact UNOBSERVED/signature NOT_CHECKED truthfully |
| `git diff --check` | PASS |

Additional inspection was initially redirected to `/tmp`, which is a macOS symlink; its subsequent
read correctly failed TRUST_PATH_INVALID. Reran using canonical `/private/tmp` as documented.
Initial missing fixture fields/privacy assertions were fixed without weakening production checks.
One full run found 812 passes and a replay mutation negative-test failure; the missing ENFORCE
consistency validation was fixed and the full suite rerun successfully. No live Docker/gVisor,
production signing key, remote implementation attestation, package index, paid service or model
robustness test was run or implied.

## 10. Self-review and traced cases

1. **Correct pin, allowed native/MCP call:** independently stored reviewed fixture lock; candidate
   matches; action binds snapshot/lock/epoch; policy allows; final check agrees; one dispatch and
   minimized assessment evidence. Residual risk: metadata/config equivalence is not code safety.
2. **Correct pin, policy deny:** the original contract deny remains authoritative; no broker,
   reservation commit or dispatcher call. A real verified Ed25519 signature does not change it.
3. **Substituted route/tool:** runtime rebuilds observations; unknown/mismatch fails registration
   or preapproval call; MCP visibility cannot expose it; fake effect counters stay zero. No agent
   expected digest/key/label or provider rebind can replace the protected lock.
4. **Approval then changed trust:** broker mutates operator generation, same-lock epoch or local
   file; final synchronous check fails TRUST_REGISTRY_STALE; approved identity cannot migrate,
   reservation releases and no dispatch evidence/effect occurs. Concurrent callers are also covered.

Actively searched alternate entry points, for_adapter omission, mutable SDK/config aliasing,
source/candidate key substitution, local file symlinks/oversize/FIFO, exception leaks, optional
verifier downgrade, exact action identity, cross-thread mutation and replay laundering. Fixed
qualified IDs to distinguish wrapper routes; froze MCP configuration; bound full SDK metadata;
rejected partial discovery captures; enforced request/dispatch assessment/snapshot consistency
in replay/trajectory validation; added explicit source trust failure blockers. Retained the
supported no-await boundary, protected root ownership and unsupported attestation rejection.

## 11. Deviations, remaining risks and next-phase readiness

- No remote/running-code attestation or complete dependency proof is implemented; requirements
  for those capabilities reject explicitly. These are documented proof limits, not mocked success.
- Docker image identity/bytes inspection is deferred; configuration drift is observed, mutable tag
  retargeting is not. No daemon/runsc operational proof is claimed.
- Offline CLI uses bounded JSON captures and protected registration snapshots rather than executing
  discovery or tools. Proposed lock review/promotion is deliberately manual and independent.
- Runtime signature/artifact/manifest replacement requires protected re-wiring/restart; only lock
  replacement is an explicit same-thread operation. There is no hosted rotation/watch service.
- Replay candidate trust comparison is an API option; the CLI honestly returns UNKNOWN without
  that candidate input. Observation equality is separate from signature/admission verification.
- Static scan is intentionally small and advisory; it does not detect arbitrary semantic injection,
  analyze implementation safety, infer declassification or grant policy permission.
- The plan's prerequisite independent Phase 7 acceptance is preserved as a release limitation.
  The user authorized implementation; neither supplied planning nor this report closes that gate.

Production runtime trust restriction is functional and tested in **MCP and non-MCP routes**.
The mandatory artifact/CLI/document/schema deliverables are present. Phase 8 is ready for
independent security review within the stated proof boundaries; this report does not self-certify
correctness or release acceptance. Phase 9 requires independent review/fixes and its own reviewed
plan. No agent graphs, hosted registry service or new sandbox infrastructure were implemented.
