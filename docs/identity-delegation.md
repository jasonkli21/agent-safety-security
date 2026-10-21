# Identity, delegation and least privilege

Phase 6 binds an MCP session to protected identity facts and supports one direct delegation.
Identity never supplies a tool-policy grant. Effective authority is the intersection of contract
policy, contract task/resource ceilings, an optional credential capability ceiling, and the
required direct OBO delegation. Existing DENY > REQUIRE_APPROVAL > ALLOW > default DENY remains.

## Trust boundary

The contract names the protected actor and optional `identity.acts_on_behalf_of` (OBO) principal.
Gateway configuration selects the identity provider and contains the protected delegation.
An operational credential file supplies secret proof. Tool arguments, model text, MCP metadata,
agent owner and inherited environment cannot select the actor, delegation or verifier.

Without provider configuration the gateway explicitly uses the protected contract principal as
`STATIC_TRUSTED_CONFIG`. This is suitable for local configuration and tests; it does not
authenticate a remote MCP host. An explicit static configuration may specify another principal
(which must match the contract) and an optional `capability_ceiling`.

`VerifiedCredential` stores only the mapped principal, assurance, validity interval and capability
ceiling. `AuthorityContext` freezes those facts and a strictly parsed canonical `Delegation` JSON
string. The string prevents aliasing through the existing mutable TaskScope resource map; each
access returns a fresh typed Delegation. It is bounded to 8192 characters. It contains no JWT,
key, external subject, arbitrary external claims or credential fingerprint. The computed
`authority_digest` binds the complete canonical context, independently of the authored policy
hash. No runtime credential/delegation fact changes `effective_policy_hash`.

## Direct delegation and scope

Every `phase6-v1` native policy decision requires a non-null trusted `AuthorityContext`; a
matching caller-supplied principal is not identity proof. Missing authority returns
`AUTHORITY_REQUIRED` for direct principals and `DELEGATION_REQUIRED` when OBO is configured.
For ENFORCE the credential principal must equal `contract.identity.principal`. If OBO is present,
a direct grant is required with `delegator == acts_on_behalf_of` and `delegate == actor`.
It must be issued, unexpired and have a finite expiry. Parent chains fail closed. If OBO is
absent, an unrelated grant is rejected. Agent ownership never supplies delegation.

The shared pure authority module validates activation and intersects task scopes. When both
sources name a task, IDs must match. Null capability ceilings add no restriction; explicit empty
sets authorize no capability. Delegation task capabilities must be subsets of its capability
scope. Resource keys must be within the delegated capability/task ceiling. Per-capability
resource restrictions intersect exactly; one-sided restrictions survive, empty intersections
stay empty and missing keys add no restriction. An empty resource map adds no per-capability
restriction, preserving the existing contract semantics. No path, URL or alias interpretation is
introduced. A broad delegation cannot override an explicit or default contract denial.

Authority is checked at startup, each policy decision and immediately before dispatch after
approval. Effective expiry is the earlier credential/delegation expiry. The final check uses the
injected clock and has no intervening await before dispatch. NormalizedAction includes the
computed authority digest, so changing scope under the same delegation ID changes the exact
approval binding. Each call still has at most one upstream dispatch.

## Protected provider configuration

Install the optional verifier and the MCP runtime:

```bash
python -m pip install -e '.[dev,mcp,identity]'
```

The gateway's optional `identity` object is one of:

```yaml
identity:
  provider: static
  principal: {principal_id: local-agent, principal_type: AGENT}
  capability_ceiling: [filesystem.read]
```

```yaml
identity:
  provider: signed_jwt
  issuer: https://issuer.example.invalid
  audience: agentsec-local
  clock_skew_seconds: 0  # strict integer, maximum 60
  keys:
    - kid: workload-key
      algorithm: RS256
      public_key_pem: |
        -----BEGIN PUBLIC KEY-----
        ...operator-pinned public key...
        -----END PUBLIC KEY-----
  subjects:
    - subject: protected-workload-subject
      principal: {principal_id: local-agent, principal_type: AGENT}
  scope_mapping:
    read: filesystem.read
```

`delegation` is an optional complete versioned Delegation object in the protected gateway
configuration. It is separate from contract intent and must not be writable by the agent.
Use the generated delegation schema for its exact fields. No signing private key is needed.

The adapter uses [PyJWT's signature/issuer/audience verifier](https://pyjwt.readthedocs.io/en/stable/usage.html).
Each pinned key selects exactly one asymmetric algorithm (RS256 with RSA >=2048 bits, ES256
with P-256, or EdDSA). Duplicate kids/subject mappings, invalid keys, private keys and excessive
skew fail configuration. The verifier rejects unknown kids, algorithm mismatch, unsigned tokens,
wrong signatures, wrong issuer/audience, missing subject/expiry, unmapped subjects, non-finite or
coerced timestamps, expired tokens, future nbf, oversized input and unsupported headers including
remote key URLs. It never fetches a key. Issuer is fixed per provider; subject mapping is therefore
an explicit (issuer, subject) binding. Unknown scopes contribute no capabilities. Null
`scope_mapping` means identity only; an empty mapping yields an empty capability ceiling.

Time claims are checked explicitly against the injected runtime clock after PyJWT verifies the
signature and issuer/audience. Configured skew shifts the accepted validity window by at most
60 seconds. Missing nbf starts the bound credential at verification time. No online revocation,
introspection, issuance, refresh, OIDC discovery or automatic key rotation is provided. Restart
and rebind to adopt changed credentials, keys or protected grants.

## Credential ingress and modes

```bash
agentsec protect mcp --contract contract.yaml --config gateway.yaml --check
agentsec protect mcp --contract contract.yaml --config gateway.yaml \
  --credential-file /protected/workload.jwt --evidence-out /protected/new-evidence.jsonl
```

`--check` validates provider keys/mappings, principal/delegation coverage and normal tool coverage
without reading a token or connecting upstream. Runtime credential reads require a regular file
owned by the current uid with no group/world permissions; symlinks are rejected. Reads are bounded
to 16 KiB and use nonblocking/no-follow flags. The credential is never forwarded upstream.
Diagnostics use safe codes, never verifier exception text or token/claim values. Stdout remains
owned by MCP. Keep public configuration and credential input in protected storage.

ENFORCE blocks authentication/authority failures. SHADOW records the setup error or authority
decision but can forward protocol-valid calls; it never substitutes a successfully authenticated
principal after verification failure. DISABLED records that enforcement is off, and makes no
protection claim. A failed provider yields no authenticated actor/assurance in startup evidence.
Static assurance is never labeled SIGNED_JWT.

## Evidence, replay and compatibility

RUN_STARTED additively records AuthoritySummary: actor, assurance, OBO, delegation ID/digest,
authority digest, earliest expiry, setup error and enforcement status. PolicyRequest binds the
replay-safe authority facts into its complete policy-input digest. Resource-bearing delegation
context is redacted in JSONL with explicit authority redaction/digest metadata; tool resource
and task-scope redaction remain unchanged. No bearer token or external claim dictionary enters
evidence, approval presentation, bundles or regression cases.

Current compilation emits `phase6-v1`. Historical `phase4-v1` plans retain their original shape,
digest and semantics, including unsupported OBO. Absent additive fields are omitted during
serialization to preserve historical evidence/action/bundle digests. Historical compilation is
explicit and used for historical source interpretation, never current runtime startup.

Replay uses recorded canonical facts and recorded timestamps, without reading credential files,
authenticating a workload, contacting a provider or checking a source token against today's clock.
A resource-bearing redacted authority may be supplied as a protected AuthorityContext artifact:

```bash
agentsec replay bundle create --evidence trace.jsonl --contract contract.yaml \
  --authority protected-authority.json --out new-bundle.json
```

Its digest must match the source commitment. Missing authority yields MISSING_AUTHORITY_CONTEXT;
other material redactions remain blockers. Historical-to-current comparisons lacking verified
facts are INCOMPLETE rather than inventing static or JWT assurance. This also leaves historical
promotion with a Phase 6 candidate DRAFT. Historical non-approval replay remains supported.
Approval replay requires exact source plan, unchanged request/authority and freshness at the
recorded dispatch time. Evidence hashes provide integrity, not authentication of source storage.

Conformance uses trusted synthetic authority fixtures and the same native authority logic. It
checks valid authority, credential ceilings and freshness, and OBO-specific missing/mismatched/
expired/narrower delegations. Existing policy/data-flow probes run with valid synthetic authority,
so contract denials and approvals remain discriminating. It authenticates no external workload.
Grouped identity/task coverage remains unclaimed; `identity.authority` has separate probes.

## Local demonstration and boundaries

```bash
.venv/bin/python examples/identity/least_privilege.py
.venv/bin/pytest -q tests/unit/test_identity_authority.py
```

The demonstration has contract read/write permission and a five-minute read-only delegation:
read succeeds and write is denied. The focused tests also exercise locally generated RSA keys,
signed JWT proof, negative verifier cases, approval expiry, concurrency, replay and promotion.
There is no production token issuer in this package.

Phase 6 supports only a direct one-hop grant. Parent chains and `max_delegated_agents` remain
unsupported. This paragraph records the Phase 6 scope: Phase 7 adapters, Phase 8 supply-chain
expansion and Phase 9 agent graphs were then outside scope, and Phase 7 depended on independent
Phase 6 review and a reviewed plan. Phase 7 is now implemented; its independent review corrections
are recorded in the [Phase 7 review-fixes report](reports/phase-7-review-fixes-report.md). Phase 8 is now implemented under the explicit user request; independent Phase 7 acceptance remains
unconfirmed and Phase 8 remains pending independent review.

## Phase 8 trust composition

The optional operator-owned supply-chain guard restricts protected implementations through
RuntimeGateway; it never grants contract or delegated authority. Metadata pins and Ed25519
signatures do not attest runtime code. Existing approval, evidence, provenance, TLS and isolation
boundaries remain active. See [supply-chain trust](supply-chain-trust.md) for exact mode behavior,
route identities, offline replay limits and commands. Independent Phase 7 acceptance is still
unconfirmed; Phase 8 implementation is awaiting independent review.
