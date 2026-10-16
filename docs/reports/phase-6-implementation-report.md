# Phase 6 implementation report

## 1. Baseline and implementation commit

Baseline: `c84b03ff4e221d998f20e18589c85dd594a6a5a5`, the Phase 5 independent-review
correction commit inspected by the plan. There were no newer commits to reconcile. The existing
untracked Phase 6 plan is included in this implementation commit; the unrelated untracked
`PHASE-0-SOL-MEDIUM-PROMPT.md` remains untouched and excluded.

Final implementation commit: the single commit containing this report. Resolve its exact SHA
with `git log -1 --format=%H -- docs/reports/phase-6-implementation-report.md`; a commit cannot
contain its own SHA. The completion response also supplies the SHA.

## 2. Phase 5 preflight and reconciliation

Before code changes, `.venv/bin/pytest -q` passed all 595 baseline tests, including the focused
replay/runtime checks for exact legacy approval binding, ordinary approval denial/expiry,
per-basis incident severity and truthful SHADOW/DISABLED source interpretation. HEAD contained
the reviewed fixes. This local verification is not independent review or independent
re-verification of those fixes. The user explicitly authorized Phase 6 under the supplied
implementation prompt and implementation-ready plan; no Phase 7 work was performed.

## 3. Scope implemented

Implemented trusted runtime actor binding, executable OBO, finite one-hop delegation, capability/
task/resource intersections, optional credential capability ceilings, authority freshness,
authority-bound action approvals, minimized evidence, pinned signed-JWT authentication, protected
credential ingress, historical compiler compatibility, authority-aware offline replay/regression,
synthetic conformance probes, generated schemas, examples and focused documentation.

## 4. Identity and authority trust model

The protocol-independent IdentityProvider returns versioned VerifiedCredential facts. Static
identity is explicitly STATIC_TRUSTED_CONFIG, not remote authentication. The default remains
protected contract-principal static configuration for credential-free local use. SIGNED_JWT
means a pinned-key proof verified under protected issuer/audience/principal/scope configuration.
Neither assurance creates contract grants. Model/tool fields cannot select identity or grants.

AuthorityContext has frozen credential facts and a strictly parsed canonical Delegation JSON
string. This avoids sharing TaskScope's mutable resource dictionary while preserving the
existing Delegation model and validation. Access returns a fresh typed Delegation. The context
and its digest are immutable across concurrent calls. Its serialized delegation is bounded to
8192 characters. Authored contract hashes remain independent of operational authority state.

## 5. Delegation, task, capability and resource semantics

The actor must match contract.identity.principal. OBO requires a direct delegation with exact
delegator/OBO and delegate/actor equality, issue time, finite expiry and no parent chain. A grant
without configured OBO is invalid. Ownership supplies no authority. Active grant task capabilities
must be a subset of its capability_scope; resource keys must respect both delegated capability
and requested-task ceilings. Historical Delegation parsing remains compatible; these stronger
checks apply at activation rather than rejecting all older serialized domain artifacts.

The shared pure intersection function retains one-sided restrictions and intersects two-sided
capability/resource restrictions exactly. Null means unspecified; explicit empty capability or
resource sets remain empty. Missing resource keys and an empty resource map add no per-capability
restriction, matching existing contract semantics. Task IDs must match when both sources name a
task. Credential ceilings and delegated capability scope add restrictive membership checks.
Contract denies/default deny, REQUIRE_APPROVAL and restrictive data rules retain their authority.

## 6. Static and signed-JWT providers

StaticIdentityProvider supports an optional explicit capability ceiling. The optional PyJWT
adapter supports pinned RS256/RSA >=2048, ES256/P-256 and EdDSA public keys. Each kid has exactly
one configured algorithm. It verifies signatures, issuer, audience, required sub/exp and explicit
subject mapping, and rejects unknown/disallowed keys or algorithms, unsigned/wrong-signature
proofs, remote key headers, arbitrary extra header semantics and oversized input. Unknown external
scopes contribute no capabilities; null scope mapping means identity only, empty mapping means
an empty capability ceiling. Duplicate key/subject mappings and private or mismatched keys fail.

Finite numeric exp/nbf are checked without coercion against an injected clock after cryptographic
verification. Skew is bounded to 0–60 seconds; the bound credential retains that accepted window.
Self-review corrected the optional-nbf/recent-expiry skew edge case and tested the exact boundary.
No discovery, issuance, refresh, introspection, revocation or network key resolution is present.

## 7. Compiler, versions and hashes

Current compile_contract emits phase6-v1 with executable OBO and an explicit authority semantic
atom. Historical compilation is explicit, retains phase4-v1 unsupported-OBO meaning and omits
the added OBO field from historical serialization. Absent additive request/action/event/program
fields are omitted, preserving old canonical hashes and checked-in bundle digests. Source compiler
selection follows recorded identity; unbound legacy input remains explicitly inferred and has no
historically proven source identity. An additive authority summary can identify a Phase 6 producer
without claiming exact source-plan binding.

No authored field or document/effective-policy hash projection changed. authority_digest is a
computed content identity, separate from the authored effective_policy_hash. Semantic diff emits
explicit OBO and compiler-semantics changes. Schema version remains additive pre-1.0 `0.1`;
strict consumers must regenerate schemas for new fields.

## 8. Runtime, approvals and evidence

Runtime binds a defensive authority snapshot at startup. Shared native policy checks freshness
for each call; ENFORCE repeats identity/scope/freshness immediately before dispatch after approval,
without an intervening await. NormalizedAction binds authority_digest in addition to existing
complete action fields. Changed scope under the same grant ID cannot reuse an approval. Expiry
while awaiting APPROVE blocks dispatch. Existing budgets, provenance release and exactly-one-
dispatch behavior remain intact.

RUN_STARTED adds typed AuthoritySummary (actor, assurance, OBO, delegation identity/digest,
authority digest, earliest expiry, error and enforcement status). Requests bind complete authority
into policy_input_digest. Resource-bearing delegation context is explicitly redacted with its
authority digest. Raw credentials and external claims are absent from evidence and presentation.
SHADOW records failures and can forward protocol-valid calls; failed proof has no authenticated
actor/assurance. DISABLED reports enforcement off. Static assurance is never labeled JWT proof.

## 9. Replay and regression compatibility

Replay uses recorded canonical authority facts and event timestamps, never raw tokens, live
providers, credential files or current-wall-clock source authentication. It reuses shared native
authority checks and rechecks freshness at recorded dispatch after approvals. Exact approval
reuse requires the exact source plan and unchanged request/authority. Source session authority
commitments are validated. A supplied protected authority artifact must match explicit redaction
digests; remaining material resource/task redaction is still a blocker.

Historical phase4-v1 bundles remain readable and replay with their historical identities and
semantics. Comparing an old source lacking authority facts with a new phase6-v1 candidate is
INCOMPLETE / MISSING_AUTHORITY_CONTEXT, and corresponding promotion stays DRAFT. This changes
the historical-source/new-candidate public workflow deliberately; tests and docs now state it.
No principal or credential fact is synthesized to make that comparison pass.

The new ACTIVE read-only delegation regression executes offline from source facts. The public
corpus has two ACTIVE PASS cases and one DRAFT. Historical cases remain unchanged on disk.

## 10. Schemas, documentation and CLI

Added identity-delegation.md, this report, a local read/write demonstration and an ACTIVE delegated
regression. Updated architecture, contract/runtime/conformance/replay/evidence guides, indexes,
README and AGENTS phase boundaries. Regenerated schemas from models, including AuthorityContext
and VerifiedCredential; generated files were not manually edited.

MCP gateway config adds identity/provider/key/mapping configuration and a protected Delegation.
`protect mcp --check` validates provider setup and identity/delegation coverage without reading
a live credential or connecting. Serving accepts `--credential-file`, using bounded regular-file
reads, owner-only permissions, ownership checks, no-follow and nonblocking flags. The secret is
never inherited or forwarded upstream. Diagnostics use safe codes and stdout remains MCP-owned.
`replay bundle create --authority PATH` accepts explicitly trusted replay-safe facts, not a JWT.

## 11. Deliberate deviations

- AuthorityContext stores canonical, validated Delegation JSON rather than a second immutable
  grant hierarchy; this keeps historical TaskScope/Delegation semantics and prevents aliasing.
- Protected delegation is nested in gateway configuration rather than requiring another live
  delegation-provider service or separate file option. It remains outside the security contract.
- Historical-to-current replay without verified facts is deliberately incomplete, even for direct
  identity. Historical source replay is preserved rather than silently upgraded.
- Resource/task reconstruction remains Phase 5's explicit incomplete boundary. Supplying authority
  can resolve authority redaction only; it does not invent other redacted material.
- Generic authority conformance uses one permitted discriminating partition for common binding/
  freshness negatives; existing tool/data-flow partitions continue independently. Plans with no
  permitted witness retain NOT_RUN coverage. Grouped identity/task coverage remains unclaimed.

## 12. Dependencies

Added optional `identity = ["PyJWT[crypto]>=2.10,<3"]` for mature JOSE signature verification and
cryptography key handling; no hand-written JWS crypto or mandatory core dependency was added.
CI installs `.[dev,mcp,identity]`. The existing uv-created environment had no pip module; the
initial `python -m pip install` attempt reported that absence. The equivalent offline uv install
succeeded with all extras and only rebuilt/reinstalled the editable project (55 packages resolved).

## 13. Verification commands and results

All final checks use the repository environment, local synthetic tools and ephemeral test keys.

| Exact command | Result |
| --- | --- |
| `.venv/bin/pytest -q` before implementation | PASS, 595 baseline tests |
| `UV_CACHE_DIR=/tmp/agentsec-phase6-uv uv pip install --offline --no-build-isolation --python .venv/bin/python -e '.[dev,mcp,identity]'` | PASS |
| `.venv/bin/pytest -q tests/unit/test_identity_authority.py tests/unit/test_replay.py tests/unit/test_runtime_state.py tests/unit/test_compiler.py` | PASS, 158 tests |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS, 146 files |
| `.venv/bin/mypy src` | PASS, 90 source files |
| `.venv/bin/pytest -q` after final schema generation | PASS, 646 tests |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts / 3 scenarios |
| `.venv/bin/agentsec eval examples` | PASS, all 6 expected outcomes |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS |
| `.venv/bin/agentsec regression run --root examples/regressions` | PASS, 2 ACTIVE PASS / 1 DRAFT |
| `.venv/bin/python examples/identity/least_privilege.py` | PASS, read ALLOW / write DENY |
| `.venv/bin/agentsec contract test examples/identity/contract.yaml --format json` | PASS, 15 probes / 15 evaluation cases |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel |
| `git diff --check` | PASS |

The focused tests exercise local signed-JWT verification for all three supported asymmetric
algorithm families and reject algorithm/key confusion, issuer/audience/subject/time/key/header
errors and oversized input. They also verify credential secrecy in CLI/evidence/bundle output,
strict schemas/unknown fields, scope intersections, exact approval authority binding, post-approval
expiry, immutable concurrent authority, mode truthfulness, historical/current replay and ACTIVE
regression promotion. Full-suite results include Phase 0–5 tests after the compatibility updates.

## 14. Mandatory security self-review

Inspected the shared intersection and policy path: no union-based grant or identity-derived allow;
contract DENY/default deny survive broad authority and narrow authority blocks contract ALLOW.
Reviewed OBO requirements, exact delegator/delegate binding, unsupported parent chains, finite
expiry, null/empty distinction, task mismatch and exact resource narrowing. Checked startup,
per-call and post-approval expiry and full authority content in action digests. Concurrent calls
share frozen facts rather than mutable resource maps. Self-review also corrected conformance
evidence so synthetic authority is bound before request/action evidence emission; policy receives
that exact recorded input rather than replacing identity facts only inside the evaluator.

Inspected verifier signature/algorithm/key pinning, issuer/audience/subject mapping and explicit
scope mapping. There is no unsigned/decode-without-signature fallback or remote key selection.
Reviewed bounded secret input, safe diagnostics and minimized evidence/replay/regression output.
Reviewed static assurance and SHADOW/DISABLED status for overclaims. Tests prove local JWT proof
is not relabeled static trust and failed verification records no authenticated actor.

Inspected historical model serializers, historical source compiler selection, exact plan comparison,
missing-authority blockers and recorded-time dispatch checks. No replay path calls a provider or
reads a bearer token. Native policy, conformance and replay share authority logic. Existing negative
policy/data-flow/evidence/budget/approval/regression tests pass. No Phase 7–9 feature was introduced.
This is implementation self-review, not independent approval.

## 15. Known limitations

Source/configuration storage must be protected; content hashes are integrity identities, not
signatures. Static identity does not authenticate a remote caller. Identity binds the current
stdio session, not an arbitrary downstream network user. No online revocation, token refresh,
automatic key rotation or OIDC service exists. Historical material without verified facts or with
unrecoverable resource/task inputs remains incomplete. Resource strings are opaque and exact.
The canonical delegation snapshot has an 8192-character limit. General inherited user/model
context tracking, semantic detection and model-internal taint remain outside existing guarantees.
Parent delegation chains and delegated-agent budgets are unsupported. Synthetic conformance
proves policy behavior over trusted fixtures, not workload authentication or model robustness.

## 16. Independent Phase 6 review readiness

Phase 6 is implemented and ready for independent review with the plan, focused guide, generated
schemas, examples, negative tests and verification recorded here. It is not independently approved.

## 17. Phase 7 readiness

Phase 7 has not started. Independent Phase 6 review/corrections and a reviewed Phase 7 plan are
required before adding further adapters. Phase 8 supply-chain and Phase 9 multi-agent graphs
remain explicitly outside this implementation.
