# Supply-chain inventory and restrictive trust

Phase 8 adds local, offline observation and operator-reviewed admission. The security contract
still decides authority. A matching pin or signature never grants a capability, bypasses approval,
or proves that a tool implementation is safe. Phase 7 independent acceptance remains pending.

## Observe, review, pin, verify, protect

Run from the repository root. No tool is invoked by `trust inspect`, `scan`, `diff`, `propose`
or `verify`. MCP inspection consumes a previously captured **complete** `ListToolsResult` JSON;
it does not connect to a server. A capture with a pagination cursor is rejected. Obtain complete
observations using your operator-controlled discovery process; runtime startup already traverses
MCP pagination. When trust is enabled, runtime bounds discovery to 128 pages, 2,048 tools and 8 MiB
of serialized tool metadata. The SDK decodes a page before agentsec can measure it, so a single
message body limit remains the SDK/transport's responsibility. Installing `.[mcp,trust]` enables
MCP and the optional cryptographic verifier.

```bash
.venv/bin/agentsec trust inspect --protected-tool examples/trust/native-tool.json
.venv/bin/agentsec trust inspect --mcp-config examples/mcp/gateway.yaml \
  --mcp-tools examples/trust/mcp-tools.json
.venv/bin/agentsec trust scan examples/trust/mcp-inventory.json \
  --lock examples/trust/mcp-lock.json
.venv/bin/agentsec trust inspect --mcp-config examples/mcp/gateway.yaml \
  --mcp-tools examples/trust/mcp-tools.json > /private/tmp/mcp-current.json
.venv/bin/agentsec trust diff examples/trust/mcp-inventory.json \
  /private/tmp/mcp-current.json --format text
.venv/bin/agentsec trust propose examples/trust/native-inventory.json --generation review-2
.venv/bin/agentsec trust verify examples/trust/native-inventory.json \
  --lock examples/trust/native-lock.json
.venv/bin/python examples/trust/pinned_native.py
.venv/bin/agentsec protect mcp --contract examples/mcp/contract.yaml \
  --config examples/mcp/gateway.yaml --trust-lock examples/trust/mcp-lock.json
```

The last command serves the synthetic MCP gateway on stdio; configure it as your host's server
command. Trust-enabled ENFORCE stdio configs require `upstream.launch_boundary: operator_managed`.
This is an operator assertion that an external deployment boundary controls the executable before
launch. Agentsec checks it before the SDK starts the process; it does not hash, authenticate or bind
executable bytes to the process. Without an external OS/deployment control, do not launch an
untrusted stdio program in this mode. Tool admission occurs only after process initialization and
discovery. HTTP similarly contacts its endpoint before tool admission, without proving server
identity. The example native program dispatches a synthetic search, removes its reviewed pin,
and shows rejection on the next call. The committed example locks are deliberately reviewed
**synthetic fixtures**, not a production trust recommendation. They never update themselves.
Changed command paths, transport, metadata or configuration require fresh observations and review.
The CLI stdio integration test exercises this exact MCP example with a normal SDK host.

Save inspection/proposal output to **new** local files when reviewing a real integration. Compare
against an independently provisioned baseline. Review the source registration, endpoint and actual
implementation separately; a content-free inventory cannot explain arbitrary implementation
semantics. Only an operator may change `status` from `PROPOSED` to `REVIEWED` and provision the
resulting lock out of the agent's write scope. There is deliberately no automatic promotion
command or discovery-to-admission path. `verify` exits nonzero on failed admission, no candidates,
or absence of a candidate in the lock's optional `required_candidates` set. Pins are allowed-if-
present by default for compatibility. Strict live MCP startup enforces this set before serving;
required presence never adds a pin or grants authority.
CLI verification compares captured observations with reviewed expectations; it does not rehash
files named by an earlier capture or establish new running-code proof. Runtime configured artifact
wiring rehashes the actual local file. JSON output is deterministic within the same signature
validity window. `diff --format text`
provides safe field names and digest identities without exposing raw metadata.
Retain the full approved inventory beside the lock. The lock stores fingerprints rather than
per-field baselines, so compare that retained inventory with a fresh capture to diagnose schema,
description, route, artifact or classification drift.

## Protected Python wiring and adapter routes

`RuntimeGateway(..., trust_guard=TrustGuard(reviewed_lock))` opts the gateway into trust checks.
The guard is operator-owned wiring, not an agent argument or an authored contract grant. Every
`RuntimeGateway.call` on that gateway is checked, including callers omitting route metadata.
`ProtectedCall` additionally checks registration. Provider and LangChain wrapping calls
`for_adapter`; each distinct native/provider/framework route needs its own pin. Use
`inspect_protected(call.tool, finalized=True)` to observe an already registered route, or
`inspect_protected(authored_tool)` for the initial native registration. Inspect with a separate
operator-owned unguarded construction process; never generate and apply a lock in production
startup. A finalized tool must not be fed back as an authored tool, which would hash the binding
again. HTTP/process factories bind their exact configuration before registration; their final
snapshots are inspected with `finalized=True`.

MCP binds qualified namespace/server/tool/adapter identity, full observed SDK metadata and the
protected upstream/binding configuration. Strict startup rejects an inventory containing any
unlisted or mismatched candidate. `tools/list` rechecks admission; a removed pin hides the tool,
and invocation still checks independently. This checks the captured session metadata, **not**
remote code freshness or a second network discovery. Native, OpenAI/Anthropic/Gemini shapes,
LangChain, fixed HTTP, host process and Docker process use the same gateway restrictions.
LangChain callbacks/tracing execute outside this gateway and need separate egress controls.

| Runtime mode | Trust behavior | Ordinary policy behavior |
| --- | --- | --- |
| ENFORCE | Registration/admission rejects before broker, reservation/commit and dispatch; final mismatch releases reservation | Existing deny, authority, approval, budget and flow restrictions apply |
| SHADOW | Records would-reject reason codes/assessment; dispatch can proceed; final drift signals without claiming a block | Existing policy decisions recorded; approval not requested |
| DISABLED | Trust observation/admission skipped, no trust assurance | Existing disabled policy behavior; transport/isolation checks remain active |

Invalid supplied JSON, keys/requirements or duplicate lock identities fail setup rather than
silently removing the guard in any mode. A valid proposed lock is never admitted in ENFORCE.
`protect mcp --check` validates supplied lock/input structure and ordinary coverage offline; it
cannot establish candidate admission without discovery and does not claim to do so.

## Exact bindings and freshness

Candidate fingerprints use `agentsec.candidate.v1`; qualified IDs, metadata, routes,
classifications, signed subjects and runtime snapshots have distinct versioned domain envelopes.
Tool schema and description digests keep their historical definitions. A candidate contains only
safe digests, source kind, static risk facts and explicit proof availability, with no nested mutable
JSON. Candidate and lock arrays are sorted with duplicate identities rejected. Different servers,
namespaces and adapter routes cannot alias merely because tools have the same name.

The action/approval digest binds a trust snapshot consisting of the complete assessment, lock
digest, signature envelope and operator replacement epoch. The gateway rechecks synchronously
after approval and authority freshness, before budget commit/dispatch evidence/dispatcher entry.
No await occurs across that final boundary. Changing a lock even away and back invalidates
outstanding approvals; no reapproval or fallback is attempted. The one-shot approval is invalidated
and the reservation released. Concurrent calls share this behavior. Guards enforce ownership by
the constructing event-loop thread; cross-thread inspection or replacement is rejected. Protected
sinks and dispatch wiring remain trusted application code, as in earlier phases.

The supported freshness is exact immutable registration/session metadata, current lock/epoch,
signature validity at the injected clock, and optionally bounded local file bytes. It does not
promise atomic hash-and-exec. Other processes can replace a file after inspection. Requiring
`require_runtime_attestation=true` therefore always rejects, including for local callables,
processes, Docker and remote MCP/HTTP. Restart/rebind for different signature or artifact wiring;
`replace_lock` is a protected operator operation, never a tool.

## Local byte inspection and dependencies

`trust inspect --protected-tool ... --artifact /absolute/file` adds a raw-file SHA-256 observation;
it is **not** `content_digest(JSON(bytes))`. Reads are limited to 1 MiB, regular files only, no
symlink components or traversal, nonblocking/no-follow open, and checked for size/mtime changes.
On macOS, use canonical `/private/tmp/...` rather than the `/tmp` symlink. A privileged concurrent
parent-directory replacement is outside the guarantee. Reads never execute files, import packages,
start shells, install/download packages, resolve references or contact a registry.

`trust inspect --pyproject /absolute/pyproject.toml` emits a `DECLARED_ONLY` manifest with
normalized package names, extras, version specifiers and source kind. Private direct-reference URLs
are not printed; only their digest is included. Declarations for one package are aggregated and
marked when their constraints or sources differ. Markers and complete declaration text remain
digest-only. It performs no resolution and hashes no installed distributions. Use
`--dependencies manifest.json` with tool inspection to bind the reviewed manifest digest. Declared,
resolved and artifact-hashed facts have distinct schema fields; this importer emits only declared
facts. Missing observations appear as INCOMPLETE in diffs, even for identical metadata. A manifest
digest is not complete SBOM coverage: `require_dependencies=true` always rejects with an explicit
coverage-incomplete reason until a complete proof mechanism exists.

For runtime local observations, `--trust-inputs inputs.json` accepts a protected versioned
`TrustInputs` object containing `artifacts` (candidate ID and absolute path), optional dependency
manifest, and signatures. Python wiring accepts the equivalent immutable signature tuple,
operator artifact mapping and manifest. The guard rehashes configured files at registration,
preapproval and final dispatch checks. Paths never enter inventories, assessments or evidence.
`artifact_digest` and `LOCAL_BYTES` retain their historical meanings: bytes at an operator-selected
path were observed and rechecked. A candidate-ID-to-path mapping does not prove those bytes belong
to the route or callable. Accordingly `require_artifact=true` rejects with
`TRUST_ARTIFACT_ASSOCIATION_UNVERIFIABLE` even when bytes match. It cannot satisfy implementation
provenance. An operator cannot satisfy running-code attestation by attaching an unrelated file,
revision string or Docker tag.

Docker image tags and configured runtime flags remain configuration observations. No Docker
image/daemon interrogation, image download, image byte verification or runsc attestation is added.
Image changes in configuration change the route digest; retargeting the same mutable tag is
unobserved and cannot satisfy attestation. TLS CA pinning, isolation identity, no-host-fallback,
`drain_cleanup()` and unknown-effect cancellation semantics remain unchanged.

## Real signature evidence

Install the optional `trust` extra (`cryptography`) for the concrete `Ed25519Verifier`. The pure
`SignatureVerifier` interface accepts raw public key, exact subject bytes and signature bytes.
The runtime always uses the concrete verifier; candidate metadata cannot choose an implementation.
A `TrustLock.keys` entry independently pins a key ID and 32-byte public key encoded in hex.
A pin's `required_signer` selects that key. No private key, candidate key, certificate, issuer label,
remote key URL, OIDC lifecycle or package-index lookup is accepted as a root.

A versioned `Signature` has candidate ID, full candidate fingerprint as `subject_digest`, key ID,
algorithm exactly `Ed25519`, aware issue/expiry timestamps, and a 64-byte signature encoded in hex.
`verification.signed_bytes(proof)` is UTF-8 `canonical_json` of precisely:

```text
domain="agentsec.supply-chain-signature.v1", schema_version="0.1",
candidate_id, subject_digest, key_id, algorithm, issued_at, expires_at
```

The signature field itself is excluded. The subject binds metadata, route, classification,
artifact and dependency observations. Issue time must be at or before verification time and
expiry strictly after it. Wrong key, subject, domain, bytes or signer fails; malformed/downgraded
algorithms fail parsing; unavailable cryptography reports UNSUPPORTED and rejects a required
signature. Verification distinguishes pin match, LOCAL_BYTES/UNOBSERVED and VERIFIED/INVALID/
UNSUPPORTED/NOT_CHECKED signature status. `COMPLETE_FOR_REQUIREMENTS` describes only the explicitly
selected checks, not universal implementation coverage. Unsigned metadata-only pins can admit if
that is the operator's explicit policy. Supplied but unrequired signatures are never labeled verified.
Use inventory `signatures`, `verify --signature proof.json`, or protected runtime `TrustInputs`.
Signing/private-key storage is outside this verifier; tests generate ephemeral local keys only.

## Scanning, evidence and offline replay

SC001 privileged actions, SC002 incomplete classifications, SC003 unobserved implementations,
SC004 unobserved dependencies and SC005 three narrow description markers are advisory rules.
With `scan --lock`, SC006 flags unlisted candidates and SC007 reviewed-material drift. Findings
include stable rule/severity/field/rationale and digest evidence, never description excerpts.
This is not semantic injection detection or assurance that a low-risk candidate is safe.

Request/dispatch evidence contains optional safe assessment and snapshot fields. Failures emit
safe supply-chain reason codes. No paths, raw manifests/descriptions, keys, credentials, headers,
environment values or arguments are added. Hashes reveal equality and may permit guessing small
known inputs, so evidence still needs access control. Assessment/snapshot pairs and request/dispatch
consistency are validated; a source evidence file is still an operator-protected input, not an
independently authenticated execution record.

Legacy paths omit all new action/event fields. `phase6-v1`, effective-policy hashes, prior tool
fingerprints and historical bundles/regressions retain their definitions. Generated schemas are
additive, versioned `0.1`; supply-chain domain projections are explicitly v1.

`replay(bundle, candidate_trust=inventory)` compares recorded candidate fingerprints separately
from route fidelity. It reports UNKNOWN without candidate observations, INCOMPLETE without source
trust facts, CHANGED or UNCHANGED for observation equality. It never verifies keys, signatures,
files, discovery or code. New trusted source facts carry `TRUST_NOT_REVERIFIED`; recorded trust
failure signals block substitution pending offline review. Source facts are preserved as source
facts, never converted into fresh runtime attestation. CLI replay without a candidate inventory
reports UNKNOWN. Historical replay remains available without claiming any trust assurance.


## Phase 9 local graph composition

Explicit `phase9-v1` operator-created ENFORCE sessions now add bounded single-parent graphs,
all-ancestor authority/approval/data ceilings, atomic recursive budgets and protected adjacent
messages. Standalone `phase6-v1` behavior and historical digests retain their existing meaning.
The gateway guard applies to direct calls and adapter rebinding. Phase 8 pins restrict tools;
they do not authenticate peers or approve delegation. See [local multi-agent security](multi-agent-security.md)
for ownership, evidence-before-import, finality, source replay blockers, DRAFT graph promotion,
unsupported modes and exact limitations. Earlier one-hop/future-graph statements describe their
original phase boundary. Independent Phase 7–8 acceptance remains unconfirmed.
