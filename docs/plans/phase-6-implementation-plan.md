# Agent Safety & Security Platform — Phase 6 Detailed Implementation Plan

**Phase:** 6 — Identity, Delegation & Least Privilege
**Status:** Implementation-ready plan
**Repository:** `jasonkli21/agent-safety-security`
**Repository baseline inspected:** `c84b03ff4e221d998f20e18589c85dd594a6a5a5` (`fix: address phase 5 independent review findings`)
**Depends on:** Phases 0–5, including the Phase 5 independent-review correction pass
**Primary goal:** turn identity, on-behalf-of relationships, task scope, short-lived credentials, and delegated capability limits from mostly descriptive metadata into a trusted, runtime-enforced authority ceiling that is shared by policy, approvals, evidence, replay, regression, and contract conformance—without building a new IAM provider or pulling Phase 9 multi-agent delegation graphs forward.

---

## 1. Current repository baseline

Phase 6 begins from the post-Phase-5 correction state, not from the original roadmap in isolation.

At the inspected baseline, `main` already provides:

1. **Strict canonical contracts and schemas**
   - strict YAML/JSON parsing and unknown-field rejection;
   - canonical serialization and document/effective-policy identities;
   - versioned domain types and generated JSON Schemas.

2. **A compiled security contract**
   - `CompiledSecurityPlan` as the immutable executable policy snapshot;
   - source-linked semantic atoms and explicit unsupported coverage;
   - native policy, runtime, coverage, conformance, and semantic diff sharing the compiled representation.

3. **A real enforcement boundary**
   - MCP runtime gateway with ENFORCE/SHADOW/DISABLED modes;
   - fail-closed behavior for unsupported active semantics in ENFORCE;
   - exact-action approvals, budgets, schema validation, and protected runtime-owned state;
   - tool discovery/binding coverage separated from authority.

4. **Tracked provenance and restrictive data-flow policy**
   - content-free artifact references and monotonic labels;
   - request-time provenance snapshots;
   - source/sink coverage proof and restrictive data rules;
   - evidence before release where ENFORCE makes a security claim.

5. **Incident replay and regression**
   - strict replay bundles;
   - exact versus legacy source-plan binding;
   - no-live-side-effect replay;
   - source/current plan identities kept distinct;
   - semantic trace diff, evidence-backed incident classification, and regression promotion.

6. **Phase 5 review corrections**
   - approval-dependent legacy replay requires exact source binding;
   - ordinary approval denial/expiry is no longer misclassified as bypass;
   - incident classification preserves basis severity;
   - SHADOW/DISABLED source evidence is represented truthfully but not relabeled as enforcing replay;
   - the correction report records 595 passing tests plus lint, format, mypy, schemas, examples, regression checks, and package build.

### 1.1 Existing Phase 6 hooks

The current code intentionally contains several Phase 6 placeholders:

- `PrincipalRef`, `AgentIdentity`, `TaskScope`, and `Delegation` already exist in `src/agentsec/domain/identity.py`.
- `Delegation` already contains:
  - `delegator`;
  - `delegate`;
  - `task_scope`;
  - `capability_scope`;
  - issue/expiry timestamps;
  - optional `parent_delegation_id`.
- `AgentSecurityContract.identity` already contains:
  - the protected `principal`;
  - optional `acts_on_behalf_of`.
- `PolicyRequest` already carries `principal`, `task_scope`, and an optional `delegation_id`.
- `NormalizedAction` already has delegation-aware identity fields suitable for approval binding.
- the taxonomy already has `DELEGATION_ESCALATION`.
- `max_delegated_agents` already exists as an intentionally unsupported future budget.

Those hooks should be evolved rather than replaced with a parallel identity model.

### 1.2 Important current limitation to remove

The current compiler explicitly marks `identity.acts_on_behalf_of` unsupported, and the native policy rejects any request whose `delegation_id` is non-null. The runtime therefore protects a configured principal but does **not** authenticate the MCP host or enforce real delegated authority.

Phase 6 should remove that limitation honestly, not merely stop reporting it as a coverage gap.

### 1.3 Phase 5 compatibility constraint

Phase 5 introduced exact compiled-plan identity into replay and approval-sensitive historical interpretation. The current compiler version is `phase4-v1`, and replay bundles serialize `CompiledSecurityPlan`.

Therefore Phase 6 must not simply change the plan schema to a new shape that makes historical Phase 5 bundles unreadable.

A Phase 6 compiler/version change is justified because identity/delegation become executable semantics. The implementation must:

- emit a new current compiler identity, recommended `phase6-v1`;
- retain strict parsing/interpretation of historical `phase4-v1` plans where needed by replay/regression;
- never silently reinterpret a historical plan as if it had Phase 6 identity semantics;
- preserve `source_identity` versus `current_identity`;
- report incompatibility/incomplete comparison explicitly when a historical artifact lacks authority information needed for a Phase 6 claim.

### 1.4 Baseline reconciliation rule

Before implementation, inspect the then-current HEAD and reconcile this plan with newer commits. At minimum read:

1. `AGENTS.md`
2. `docs/prd.md`
3. `docs/architecture.md`
4. this Phase 6 plan
5. `docs/security-contract.md`
6. `docs/runtime-mcp.md`
7. `docs/contract-conformance.md`
8. `docs/evidence-model.md`
9. `docs/provenance-data-flow.md`
10. `docs/replay-incidents.md`
11. `docs/reports/phase-5-implementation-report.md`
12. `docs/reports/phase-5-review-fixes-report.md`
13. current compiler/policy/runtime/identity/replay/evidence/CLI code
14. current tests and generated schemas

Do not force stale filenames or APIs if the repository has advanced.

`AGENTS.md` at the inspected baseline still says Phase 5 is awaiting independent review. Before implementing Phase 6, verify the Phase 5 correction baseline and any newer independent re-verification. If the current branch contains the reviewed fixes and no unresolved P0/P1 issue, proceed and update the phase boundary as part of Phase 6. A local preflight is verification, not a substitute for an independent review.

---

## 2. Phase 6 objective

The PRD defines Phase 6 as **Identity, Delegation & Least Privilege**:

- agent principals;
- on-behalf-of relationships;
- short-lived credentials;
- capability-scoped tokens;
- task-scoped authority;
- delegated permissions;
- workload identity/OAuth/OIDC integrations.

The architecture already establishes the long-term authorization shape:

```text
principal
+ delegated authority
+ task scope
+ action/resource
+ arguments/data/provenance
+ trajectory/environment
+ budgets
→ policy decision
```

The concrete Phase 6 objective is:

> **Bind each protected runtime session to a trusted principal, optionally bind that principal to a one-hop on-behalf-of delegation, derive an immutable effective authority ceiling by intersecting credential/delegation/task constraints with the contract, enforce freshness and scope at every privileged action, bind approvals/evidence/replay to that authority, and do so without allowing identity metadata or tokens to become implicit permission grants.**

The core invariant is:

```text
effective runtime authority
    = intersection(
        explicit contract tool policy,
        contract task/resource ceiling,
        verified credential capability ceiling when present,
        verified direct delegation when required
      )

therefore effective runtime authority is a subset of every active ceiling
```

More precisely, each source is a **ceiling**, never an additive grant. A permissive delegation cannot override contract deny. A permissive contract cannot override a narrower delegation.

---

## 3. Phase boundary

### 3.1 In scope

Phase 6 should implement:

- trusted runtime principal binding;
- explicit distinction between identity proof and authorization;
- executable `acts_on_behalf_of` semantics;
- one-hop delegation validation and enforcement;
- task/capability/resource intersection;
- short-lived authority/freshness enforcement;
- capability ceilings derived from verified credential scopes where configured;
- a protocol-independent identity/authority provider port;
- a local protected/static provider for credential-free development and tests, clearly labeled as trusted configuration rather than remote authentication;
- one narrow standards-oriented signed-JWT workload identity adapter using a mature JOSE/JWT implementation;
- pinned issuer/audience/key material and explicit principal/scope mapping;
- no automatic network discovery required for the core path;
- runtime authority binding in MCP without accepting identity from tool arguments;
- exact authority binding into approvals and policy-input identity;
- authority-aware evidence without storing raw bearer credentials;
- authority-aware replay/regression with historical compatibility;
- contract conformance probes for delegation/least-privilege semantics;
- generated schema updates;
- focused examples/docs;
- Phase 6 implementation report;
- documentation/phase-boundary updates.

### 3.2 Explicitly out of scope

Do **not** pull later phases or an IAM product into Phase 6:

- OAuth authorization server;
- token issuance service;
- refresh-token service;
- hosted login UI;
- hosted identity control plane;
- dynamic OIDC discovery as a mandatory dependency;
- online introspection/revocation service;
- general certificate PKI;
- secrets manager;
- SSO administration;
- multi-agent delegation graphs;
- recursive/transitive delegation evaluation;
- authority laundering detection across agent graphs;
- recursive delegated-agent budgets;
- child-agent spawning;
- agent-to-agent protocol support;
- Phase 7 generic provider/function/HTTP/coding-agent adapters;
- Phase 8 supply-chain signing/registry expansion;
- Phase 9 multi-agent trust semantics;
- new general-purpose policy language;
- Cedar/OPA migration;
- automatic task-scope inference from prompts;
- LLM-based authorization;
- model-generated identity/delegation;
- real production claims that a static local provider authenticates a remote caller.

`parent_delegation_id` remains serializable for compatibility, but an active parent chain must be rejected/unsupported in Phase 6 rather than silently ignored.

`max_delegated_agents` remains unsupported because Phase 6 does not create child agents.

---

## 4. Core security semantics

### 4.1 Identity is not permission

A verified principal answers:

> “Who is presenting this workload/session credential?”

It does not answer:

> “What may this agent do?”

Permission remains bounded by the security contract, task scope, delegation, data-flow policy, approval policy, budgets, and runtime context.

No token claim, principal type, trust level, owner, framework, model provider, or model name grants a capability merely by existing.

### 4.2 Contract policy remains the authority ceiling

The existing tool-rule precedence stays authoritative:

```text
explicit DENY
  >
REQUIRE_APPROVAL
  >
explicit ALLOW
  >
default DENY
```

Phase 6 adds restrictive checks before an ALLOW/REQUIRE_APPROVAL can survive.

A delegation or token scope can turn a base ALLOW into DENY. It can never turn a contract DENY/default DENY into ALLOW.

### 4.3 Principal roles

Use explicit terms to avoid overloaded “user” semantics:

- **protected principal / actor** — the canonical `identity.principal` expected to run the agent;
- **authenticated principal** — the principal established by the runtime identity provider;
- **on-behalf-of principal** — optional `identity.acts_on_behalf_of`;
- **delegator** — the principal that grants a direct delegation;
- **delegate** — the principal receiving that delegation.

For Phase 6 ENFORCE:

```text
authenticated principal == contract.identity.principal
```

If `acts_on_behalf_of` is configured:

```text
delegation.delegator == contract.identity.acts_on_behalf_of
delegation.delegate  == authenticated principal
```

Do not infer `agent.owner` as on-behalf-of authority. `owner` remains contextual identity metadata unless a future explicit semantic decision changes that.

### 4.4 Direct/self authority

If the contract has no `acts_on_behalf_of`:

- the principal acts under its own contract authority;
- a verified credential may impose an additional capability ceiling;
- a delegation should not be silently accepted and ignored;
- existing local/static behavior should remain available for credential-free development, with evidence/docs explicitly stating that it is trusted configuration rather than caller authentication.

### 4.5 One-hop on-behalf-of authority

If the contract has `acts_on_behalf_of`:

- ENFORCE requires a trusted direct delegation;
- missing delegation is not equivalent to direct authority;
- delegator/delegate mismatch fails closed;
- active `parent_delegation_id` is unsupported in Phase 6;
- the delegation must be active for the current call;
- active runtime delegation should require a finite `expires_at`;
- the delegation may only narrow authority.

This creates the Phase 6 invariant:

```text
effective capability
∈ contract authorization
∩ credential capability ceiling (if present)
∩ delegation capability scope (if OBO)
∩ task requested-capability ceilings (if present)
```

### 4.6 Task-scope intersection

The contract task scope and delegation task scope are separate security inputs.

Define and test one canonical intersection function rather than reimplementing scope logic in policy, runtime, replay, and tests.

Recommended semantics:

- if only one side specifies a task scope, that side provides the ceiling;
- if both specify a task scope, their `task_id` values must agree;
- `requested_capabilities: null` means “unspecified by this source,” not all-powerful authority;
- explicit empty capability collection means no capabilities;
- where both sources specify capability sets, intersect them;
- where only one specifies a capability set, use that set as the ceiling;
- resource scopes use exact opaque identifiers, preserving existing runtime semantics;
- for a capability whose resource set is specified by both sources, intersect sets;
- if only one source constrains that capability’s resources, retain that restriction;
- an explicit empty resource set means no matching resource;
- absence of a resource key remains “this source adds no resource restriction for that capability,” consistent with the existing exact-resource model;
- do not introduce path/URL/email/Unicode alias semantics in this phase.

If the intersection is empty, it is a legitimate least-privilege result, not a fallback to a broader source.

### 4.7 Delegation internal consistency

Add semantic checks appropriate to an active delegation:

- `expires_at > issued_at` remains required when expiry exists;
- runtime activation for OBO requires finite expiry;
- if delegation `task_scope.requested_capabilities` is non-null, it must not exceed `delegation.capability_scope`;
- resource scopes must only describe capabilities consistent with the delegated capability/task ceiling;
- invalid or contradictory delegation content fails before tool dispatch;
- `parent_delegation_id` must not be treated as proof that a parent was checked.

Do not over-constrain the serialized domain model in ways that make historical artifacts unreadable if the check is specifically a Phase 6 runtime-activation rule.

### 4.8 Credential capability ceilings

A verified workload credential may optionally carry scopes mapped by trusted configuration to canonical `CapabilityId` values.

Requirements:

- the mapping is controlled outside agent context;
- unknown token scopes do not grant anything;
- wildcard interpretation is forbidden unless a future explicit capability language adds it;
- mapping from external scope string to internal capability is explicit and deterministic;
- a credential with a configured capability ceiling can only narrow authority;
- an identity-only provider may explicitly return no capability ceiling; this must be distinguishable from “empty ceiling”;
- empty ceiling means no capability authority through that credential.

### 4.9 Freshness

Authority freshness is checked at least:

1. when the runtime session is established;
2. before policy evaluation for each call;
3. after a potentially long human approval wait and immediately before dispatch.

Effective expiration should be the earliest applicable expiry among:

- verified workload credential;
- direct delegation.

An approval created under valid authority must not dispatch after that authority expires.

No wall-clock check should be hard-coded in a way that makes tests/replay nondeterministic; inject a clock.

### 4.10 No silent revocation claim

Phase 6 short-lived credentials reduce exposure but do not provide full revocation.

Unless a real introspection/revocation mechanism is implemented, docs/evidence must state:

- no online revocation check;
- no automatic JWKS/network refresh if the adapter uses pinned key material;
- restarting/rebinding is required to adopt changed credentials/keys;
- expiry is enforced, but “not expired” is not equivalent to “not revoked.”

---

## 5. Canonical authority models

Exact class names may adapt, but preserve one protocol-independent representation.

### 5.1 `VerifiedCredential`

Recommended semantic shape:

```text
VerifiedCredential
- schema_version
- provider_id
- principal
- assurance: STATIC_CONFIG | VERIFIED_JWT
- credential_id?              # content-minimized stable ID, not raw token
- issued_at?
- not_before?
- expires_at?
- capability_scope?           # null = identity-only; empty = no capabilities
- issuer?                     # safe configured identifier
- audience?                   # safe configured identifier/set
```

Requirements:

- never store the raw bearer credential;
- do not copy arbitrary token claims into the canonical object;
- only security-relevant, explicitly mapped claims enter the model;
- configured identifiers must not contain secrets.

A static provider may omit credential expiry and must be labeled `STATIC_CONFIG`; it must never be represented as cryptographic verification.

A signed-JWT provider should require finite expiry.

### 5.2 `AuthorityContext`

Recommended semantic shape:

```text
AuthorityContext
- schema_version
- actor                      # authenticated principal
- acts_on_behalf_of?
- credential                # verified or trusted-static identity facts
- delegation?               # direct one-hop delegation
- effective_task_scope?
- effective_capability_scope?
- valid_until?
- authority_digest
```

`authority_digest` should be derived canonically over the security-relevant context excluding the digest field itself. It is an integrity/binding identity, not a signature.

The effective scope is derived; callers must not supply an arbitrary “effective authority” that bypasses source validation.

### 5.3 Avoid duplicate sources of truth

Do not maintain:

- one delegation interpretation in the identity adapter;
- another in `NativePolicyEngine`;
- another in replay;
- another in conformance.

Create focused reusable pure functions/services for:

- delegation activation/validation;
- task/resource intersection;
- credential/delegation capability intersection;
- authority freshness.

Runtime/adapters may decide where trusted inputs come from, but the canonical authority semantics must be shared.

---

## 6. Identity provider architecture

### 6.1 Port

Add a narrow protocol-independent port, for example:

```python
class IdentityProvider(Protocol):
    def verify(self, credential: bytes | str, *, now: datetime) -> VerifiedCredential: ...
```

The exact signature may use a secret wrapper or adapter-specific input, but the core result must be canonical and must not expose provider/JWT library types.

Do not place MCP types, Typer, filesystem paths, JWT classes, or HTTP clients in core domain models.

### 6.2 Static protected provider

Provide a static/trusted-config implementation for:

- local development;
- deterministic tests;
- credential-free examples where appropriate.

It binds an explicitly configured `PrincipalRef` and optional capability ceiling.

It is **not remote authentication**. Documentation, events, and naming must make that clear.

This preserves the local-first product while allowing the same authority pipeline to run without cloud infrastructure.

### 6.3 Signed-JWT workload identity adapter

Implement one contained adapter for a signed JWT supplied out of band to the MCP stdio session.

Use a mature JOSE/JWT library. Do not hand-roll JWS/JWT cryptography.

Keep the dependency isolated, preferably behind an optional package extra such as `identity`, and update CI to exercise it if it becomes a supported public path.

Minimum verification requirements:

- explicit allowed asymmetric algorithms;
- reject `alg=none`;
- avoid symmetric/asymmetric key confusion;
- exact configured issuer verification;
- explicit expected audience verification;
- signature verification against protected/pinned key material;
- required `sub`;
- required finite `exp`;
- `nbf` when present;
- `iat` when relied upon;
- bounded, explicit clock skew;
- reject unknown/untrusted key references;
- do not follow token-controlled `jku`, `x5u`, or other remote key URLs;
- no dynamic code or object deserialization;
- bounded token/input size;
- map `(issuer, subject)` to a canonical principal through protected configuration rather than automatically treating arbitrary `sub` as an internal principal ID;
- map external scopes to internal capabilities through an explicit allowlisted mapping.

A locally pinned JWKS/JWK set is sufficient for Phase 6. OIDC discovery, key-refresh daemons, token exchange, and issuance are out of scope.

### 6.4 Credential ingress

Do not accept identity credentials from tool arguments, model content, or untrusted MCP payload fields.

For the current stdio deployment, a practical contained interface is a protected credential file supplied explicitly to the CLI/runtime. Exact CLI naming may adapt.

Requirements:

- bounded read;
- no raw token in logs, exceptions, events, approval UI, reports, or generated regression artifacts;
- no copying token into upstream process environment;
- no protocol stdout leakage;
- no persistence of the token in replay bundles.

`--check` should validate configured identity/delegation coverage without needing to prove a live credential unless an explicit credential is supplied for a dedicated verification operation.

---

## 7. Delegation provider / source of grant

Phase 6 does not need a hosted delegation service.

A direct `Delegation` artifact may be supplied as protected local security configuration and validated by the canonical authority resolver.

Treat the artifact as trusted configuration because it is outside the agent’s write scope. Do not call it cryptographically authenticated unless it actually is.

The runtime should bind:

```text
delegation_id
delegation canonical digest
delegator
delegate
task/capability scope
expiry
```

into the authority context.

A future managed/signature-backed delegation provider can implement the same port without changing policy semantics.

If a generic `DelegationProvider` port improves separation cleanly, add it; do not create a broad plugin framework.

---

## 8. Compiler and contract semantics

### 8.1 Make `acts_on_behalf_of` executable

`identity.acts_on_behalf_of` should no longer be an unconditional unsupported semantic atom.

Compile it into the current plan and mark it as requiring runtime authority proof where appropriate.

The compiled plan should retain enough identity intent to validate:

- expected actor principal;
- expected on-behalf-of principal;
- environment;
- agent binding.

### 8.2 Compiler version

Because Phase 6 changes executable identity semantics and the compiled plan shape, a new compiler version is appropriate.

Recommended current compiler version:

```text
phase6-v1
```

Do not relabel old `phase4-v1` serialized plans as `phase6-v1`.

### 8.3 Backward-compatible plan parsing

The replay/regression model currently embeds `CompiledSecurityPlan`.

Choose a design that preserves strict historical parsing, for example:

- one versioned plan model that can parse both versions with explicit optional fields and validators; or
- a discriminated union of legacy/current compiled plan shapes plus a narrow compatibility projection.

Whichever approach is used:

- current `compile_contract()` emits only the current Phase 6 version;
- legacy plan fields are never defaulted into stronger authority claims;
- source plan identity/digest remains stable;
- candidate/current replay uses current compiler semantics;
- semantic diff reports identity/authority changes explicitly.

### 8.4 Effective policy hash

The existing effective-policy hash already includes identity bindings/task scope. Do not casually change its projection.

If a new authored contract field is introduced, make an explicit projection decision and add hash tests.

Runtime credentials/delegation supplied outside the authored contract should **not** mutate the contract’s `effective_policy_hash`; they get their own `authority_digest`.

This distinction is important:

```text
effective_policy_hash = reviewed contract semantics
authority_digest       = runtime identity/delegation context
```

### 8.5 No token material in contract

Do not add bearer tokens, private keys, or secret credentials to `AgentSecurityContract`.

Provider configuration/key references belong to trusted runtime configuration/adapters, not declarative agent policy intent.

---

## 9. Policy engine changes

### 9.1 Replace blanket delegation rejection

The current native engine rejects every non-null `delegation_id`. Replace this with explicit authority validation.

The policy decision must be able to distinguish at least:

- principal/agent/environment mismatch;
- missing required delegation;
- unverified/mismatched delegation;
- expired authority;
- outside delegated capability;
- outside delegated task/resource scope;
- outside contract task scope;
- ordinary explicit/default tool policy denial;
- data-flow denial.

Prefer stable reason codes over generic `INVALID_REQUEST` where that improves audit/replay without exploding the taxonomy.

Possible additions, subject to exact implementation naming:

```text
IDENTITY_MISMATCH
DELEGATION_REQUIRED
DELEGATION_INVALID
DELEGATION_EXPIRED
OUTSIDE_DELEGATED_SCOPE
AUTHORITY_EXPIRED
```

Do not use `ReasonCode` for filesystem/JWT parser/setup errors that are not policy decisions.

### 9.2 Decision ordering

Identity/delegation checks are ceilings, not authored rule precedence.

Recommended logical ordering:

1. validate canonical request/plan/authority bindings;
2. verify authority is current;
3. enforce effective delegated/task/capability/resource ceiling;
4. evaluate contract tool rules with existing deny/approval/allow precedence;
5. apply restrictive data-flow rules;
6. return deterministic reason/rule provenance.

A contract explicit deny must still be reflected correctly if reached. Do not create a path where delegation validation can accidentally convert a denied capability to allow.

### 9.3 Request binding

The policy input should bind authority semantics strongly enough that:

- two requests with different delegation content do not have the same full policy-input identity;
- changing capability scope/resource ceiling changes authority/policy-input digest;
- changing only raw credential bytes while verified security claims are identical need not change authorization semantics;
- untrusted callers cannot populate a trusted authority context through a model/tool request.

A practical approach is to add a canonical `AuthorityContext` or its replay-safe equivalent to `PolicyRequest`, while retaining/validating `delegation_id` for compatibility if needed.

Avoid contradictory duplicate fields. If both an ID and authority object exist, validate they agree.

---

## 10. Runtime/PEP integration

### 10.1 Bind authority once, check freshness repeatedly

At runtime startup:

1. compile contract;
2. load/verify identity provider configuration;
3. authenticate or statically bind the protected principal;
4. load/validate direct delegation when required;
5. derive canonical `AuthorityContext`;
6. prove configured identity/delegation coverage before ENFORCE starts;
7. emit content-minimized run/authority evidence.

For every call:

1. check session not closed;
2. snapshot provenance as today;
3. check authority freshness;
4. construct request from trusted runtime-owned authority, never from MCP arguments;
5. evaluate policy;
6. bind authority into exact action/approval;
7. after approval and immediately before dispatch, re-check authority freshness;
8. dispatch at most once under existing runtime semantics.

### 10.2 Approval binding

`NormalizedAction` already binds principal/task/delegation identity. Phase 6 must ensure it also binds the **effective authority content**, not merely a reusable delegation ID.

Add an `authority_digest` or equivalent to the normalized action/digest.

This prevents:

```text
same delegation_id
+ changed capability/resource scope
→ reuse of an approval for a materially different authority grant
```

Approval remains one-shot and exact.

### 10.3 Expiry during approval

Add a focused test:

```text
authority valid at policy decision
→ approval requested
→ clock advances beyond credential/delegation expiry
→ human approves
→ dispatch is blocked
```

This is a required Phase 6 security invariant.

### 10.4 Runtime failure behavior

In ENFORCE:

- unverifiable/missing required authority fails closed;
- expired authority fails closed;
- authority setup failure prevents protected startup when necessary;
- stale/mismatched authority never falls back to contract principal.

In SHADOW:

- retain truthful “would deny/error” authority semantics;
- do not claim authentication when using expected/static identity only;
- preserve existing property that SHADOW may forward protocol-valid calls while recording the decision that ENFORCE would have made.

In DISABLED:

- do not represent the session as protected/verified merely because identity config exists;
- protocol/schema safety behavior may remain;
- no policy/authority enforcement claim.

### 10.5 Concurrency

Authority context should be immutable for the session unless an explicit safe rebind design is implemented.

Do not allow one concurrent request to mutate another request’s authority.

If credential refresh/rebind is not implemented, fail after expiry and require restart/rebind rather than introducing mutable refresh complexity.

---

## 11. MCP operational configuration

Extend operational configuration narrowly rather than embedding IAM into the contract.

A reasonable shape is:

```text
McpGatewayConfig
- existing fields...
- identity:
    provider: STATIC | JWT
    provider-specific protected configuration
    scope mapping
    principal mapping
- delegation?:
    protected direct grant or reference to protected artifact
```

Exact structure may use separate config files if that produces cleaner secret/key handling.

Requirements:

- tool bindings still grant no permission;
- identity config still grants no tool permission by itself;
- JWT public keys/JWKS are trusted security configuration;
- bearer credentials are passed separately from general config when practical;
- private keys are not required because Phase 6 verifies but does not issue tokens;
- the agent cannot change the active authority through MCP tool arguments.

Update `agentsec protect mcp --check` to include static identity/delegation coverage checks.

Do not add HTTP ingress authentication just to exercise identity; stdio session binding is sufficient for this phase.

---

## 12. Evidence model

### 12.1 What must be observable

Security evidence should make it possible to answer:

- which canonical actor principal was bound?
- was the source `STATIC_CONFIG` or cryptographically verified JWT?
- was the actor acting on behalf of another principal?
- which delegation ID/digest was active?
- which authority digest was used for the request?
- what was the effective authority expiry?
- did policy reject the call due to delegation/authority scope or expiry?
- did an authority change occur before approval/dispatch?

### 12.2 What must not be persisted by default

Do not store:

- raw bearer token;
- token signature bytes solely for audit;
- private keys;
- arbitrary token claims;
- raw secret-bearing resource values merely because they occur in delegation/task scope.

Existing content-minimization rules continue to apply.

### 12.3 Authority event strategy

Prefer the smallest additive event change that preserves canonical facts.

Possible designs:

- add a typed `AUTHORITY_BOUND` event; or
- extend `RUN_STARTED` with a typed content-minimized authority binding.

Whichever is chosen, it must:

- be versioned/typed;
- distinguish static trust from verified JWT;
- carry safe IDs/digests, not raw credentials;
- support replay causality;
- remain parseable for legacy event streams.

Per-request `TOOL_REQUESTED` evidence should bind the `authority_digest` and list any authority fields redacted from persisted policy request content.

### 12.4 Security signals

Use `DELEGATION_ESCALATION` for evidence-backed attempted authority expansion/mismatch where appropriate.

Do not classify every ordinary credential expiry as an attack. Expiry can be a normal operational authorization failure.

Keep signal semantics distinct from policy reason codes.

---

## 13. Replay and regression compatibility

Phase 6 must integrate with the Phase 5 lifecycle instead of bypassing it.

### 13.1 Historical Phase 0–5 artifacts

Valid historical bundles/plans must remain readable where their existing schemas allow.

A historical `phase4-v1` source plan:

- remains historical;
- does not gain an invented authority context;
- may replay under historical semantics;
- may compare against a `phase6-v1` candidate;
- receives an explicit limitation/incomplete status if a Phase 6 authority claim cannot be reconstructed.

### 13.2 Phase 6 replay input

A Phase 6 replay must not revalidate a historical bearer token against wall clock or a live identity provider.

Replay operates on the **recorded verified authority facts**, not the secret credential.

A Phase 6 replay bundle should contain or bind a canonical replay-safe authority context sufficient for policy semantics:

- canonical principal;
- assurance kind;
- delegation;
- capability ceiling;
- task/resource ceiling;
- source-time validity metadata;
- authority digest.

If default evidence redaction omits material delegation resource values, bundle creation should require an explicitly supplied protected authority/delegation artifact or mark replayability incomplete. Do not synthesize redacted values.

### 13.3 Source/current compiler versions

Candidate replay should be able to compare:

```text
historical phase4-v1 plan
vs
current phase6-v1 plan
```

and later:

```text
source phase6-v1 authority/plan
vs
candidate phase6-v1 authority/plan
```

Compiler-version/authority differences are semantic facts, not volatile-ID noise.

### 13.4 Approval replay

Historical approval replay remains exact-bound.

Phase 6 approvals must bind `authority_digest`; replay must reject or mark incomplete an approval path when the exact source authority binding cannot be proven.

### 13.5 Regression promotion

A deterministic delegation/least-privilege incident may be promotable when the expected behavior is explicit, e.g.:

- outside delegated capability must not dispatch;
- delegation mismatch must not dispatch;
- expired authority must not dispatch;
- contract deny remains deny despite broad delegation.

Do not auto-author a broader/narrower delegation as “the fix.”

---

## 14. Contract conformance and evaluation

Phase 3 established policy-derived conformance. Phase 6 should extend that same lifecycle.

Add deterministic authority/conformance probes where expressible:

- direct principal identity match;
- on-behalf-of contract without delegation;
- delegator mismatch;
- delegate mismatch;
- delegation expired;
- capability inside contract but outside delegation;
- capability inside delegation but denied by contract;
- resource allowed by contract but outside delegated resource scope;
- delegated scope narrower than contract task scope;
- credential capability ceiling narrower than both;
- valid intersection preserving REQUIRE_APPROVAL;
- valid intersection preserving data-flow denial.

Conformance must use the same native policy/authority semantics as runtime.

Do not claim that synthetic conformance authenticates a real external workload. It verifies policy semantics over trusted test authority fixtures.

The existing scripted evaluation engine does not need to become an identity provider. Reuse canonical authority fixtures when evaluation/replay needs identity-aware scenarios.

---

## 15. Suggested package ownership

Exact filenames may adapt to HEAD, but preserve dependency direction.

```text
src/agentsec/
├── domain/
│   ├── identity.py              # Principal/TaskScope/Delegation + canonical authority facts
│   ├── policy.py                # authority-aware PolicyRequest
│   ├── approvals.py             # authority-bound NormalizedAction
│   ├── events.py                # typed authority evidence
│   └── taxonomy.py              # stable reason/assurance identifiers
├── identity/
│   ├── ports.py                 # IdentityProvider / optional DelegationProvider
│   ├── authority.py             # activation, intersection, freshness
│   └── static.py                # trusted-config provider
├── adapters/
│   ├── identity/
│   │   └── jwt.py               # contained signed-JWT verifier
│   └── mcp/
│       └── config.py            # operational provider/delegation configuration
├── compiler/
│   ├── models.py                # phase6 plan + legacy compatibility
│   └── compile.py
├── policy/
│   └── native.py                # authority ceiling enforcement
├── runtime/
│   └── gateway.py               # bind/recheck trusted authority
├── replay/
│   └── ...                      # authority-aware replay compatibility
└── cli/
    └── protect.py               # credential/delegation ingress
```

Avoid generic helper dumping grounds and avoid a dynamic plugin framework.

---

## 16. Schema and serialization strategy

Public serialized Phase 6 artifacts likely include:

- `Delegation` if changed;
- `VerifiedCredential`;
- `AuthorityContext` or equivalent;
- authority-aware `PolicyRequest`;
- authority-aware `NormalizedAction`;
- authority-aware `SecurityEvent`;
- current compiled security plan;
- MCP gateway identity configuration if public;
- replay/result/regression models affected by plan/authority changes.

Requirements:

- generated schemas are regenerated, never manually edited;
- unknown fields remain rejected;
- canonical set ordering remains stable;
- timestamps remain timezone-aware;
- `null` versus empty capability/resource sets retain distinct semantics;
- new digest fields are computed, not caller-trusted;
- legacy replay artifacts remain explicit about source version.

Use the repository’s existing pre-1.0 versioning policy deliberately. Do not bump `schema_version` mechanically if current project conventions support additive `0.1` evolution, but document compatibility impact in the implementation report.

---

## 17. JWT/workload identity security checklist

The implementation must explicitly defend against common verifier failures.

At minimum test or prove:

- unsigned token rejected;
- disallowed algorithm rejected;
- symmetric/asymmetric confusion impossible in configured path;
- wrong signature rejected;
- unknown `kid` rejected;
- token-controlled remote key URL not followed;
- wrong issuer rejected;
- wrong audience rejected;
- missing subject rejected;
- missing expiry rejected;
- expired token rejected;
- not-yet-valid token rejected;
- excessive token/input size rejected;
- unmapped subject cannot invent a principal;
- unknown scope cannot invent a capability;
- duplicate/ambiguous mapping config rejected;
- raw token absent from exception/event/report output.

Do not implement a permissive “decode without verify” fallback.

---

## 18. Error handling

Use stable typed errors for setup/verification failures, separate from policy `ReasonCode` where appropriate.

Likely setup/runtime error families:

```text
IDENTITY_PROVIDER_UNAVAILABLE
IDENTITY_CREDENTIAL_MISSING
IDENTITY_CREDENTIAL_INVALID
IDENTITY_PRINCIPAL_UNMAPPED
AUTHORITY_BINDING_MISMATCH
DELEGATION_REQUIRED
DELEGATION_INVALID
DELEGATION_CHAIN_UNSUPPORTED
AUTHORITY_EXPIRED
AUTHORITY_COVERAGE_MISSING
```

Exact naming can adapt.

Requirements:

- no raw credential content in messages;
- no untrusted claim echo;
- no secret resource echo;
- ENFORCE fails closed;
- SHADOW remains truthful;
- operational parser/crypto errors do not masquerade as authored policy reason codes.

---

## 19. Focused testing strategy

Testing should be security-focused and proportional. Test count is not a target.

### 19.1 Domain/intersection tests

Cover:

- null vs empty capability scopes;
- task ID mismatch;
- capability intersection;
- resource intersection;
- one-sided resource restriction;
- empty intersection;
- delegation task capabilities exceeding delegation capability scope;
- finite expiry activation requirement;
- parent delegation unsupported at runtime;
- canonical authority digest stability;
- changed delegation scope changes authority digest.

### 19.2 Policy tests

Cover:

- direct principal valid/invalid;
- missing required delegation;
- delegator/delegate mismatch;
- delegation valid/expired;
- contract allow + delegation deny-by-absence => deny;
- delegation allow + contract explicit deny => deny;
- delegation allow + contract default deny => deny;
- REQUIRE_APPROVAL survives valid narrower authority;
- contract task + delegation task intersection;
- credential capability ceiling;
- data-flow deny still clamps valid authority;
- no authority path can grant a capability not already authorized by contract.

### 19.3 Approval/runtime tests

Cover:

- exact authority digest included in action binding;
- same delegation ID with changed scope cannot reuse approval;
- expiry while waiting for approval blocks dispatch;
- identity/delegation cannot come from tool arguments;
- concurrent calls share immutable authority safely;
- no request dispatches after authority expiry;
- SHADOW records authority denial/error but preserves its non-enforcing semantics;
- DISABLED does not claim verified enforcement;
- existing budgets/provenance/evidence invariants remain intact.

### 19.4 JWT adapter tests

Use local ephemeral test keys/fixtures; no real external credentials or network.

Cover the security checklist in Section 17.

### 19.5 Replay/regression tests

Cover:

- legacy Phase 5 bundle with `phase4-v1` source remains readable;
- source identity remains historical;
- candidate `phase6-v1` plan is distinct;
- Phase 6 authority context can replay without raw JWT;
- material missing authority context yields explicit blocker/incomplete result;
- approval replay requires exact authority binding;
- delegation-scope regression can become an ACTIVE deterministic case when expectation is explicit;
- no replay path loads credential file or invokes identity network calls.

### 19.6 End-to-end local flow

Provide at least one focused credential-free/static example:

```text
contract acts_on_behalf_of user
+ protected direct delegation user -> agent
+ contract allows read/write
+ delegation allows read only
→ read allowed
→ write denied as outside delegated authority
```

Also exercise one local signed-JWT verification path using generated test keys without external services.

---

## 20. Verification gates

Preserve all existing gates.

Run at minimum:

```bash
ruff check .
ruff format --check .
mypy src
pytest -q
agentsec examples validate
agentsec eval examples
agentsec schema export --out schemas/generated
agentsec regression run --root examples/regressions
python -m build --no-isolation
git diff --check
```

If an identity optional extra is added, CI and local verification must install/exercise it, for example:

```bash
python -m pip install -e ".[dev,mcp,identity]"
```

Also run focused Phase 6 identity/delegation/runtime/replay tests and a no-network JWT fixture flow.

Do not report only focused tests if the full suite was not run.

---

## 21. Documentation requirements

Add or update focused documentation covering:

- identity versus authorization;
- protected principal versus on-behalf-of principal;
- one-hop delegation semantics;
- task/capability/resource intersection;
- credential capability ceilings;
- authority freshness and expiry;
- static provider trust boundary;
- signed-JWT verification trust/configuration;
- what OAuth/OIDC functionality is and is not implemented;
- credential secrecy/evidence minimization;
- replay behavior without raw credentials;
- legacy compiled-plan compatibility;
- SHADOW/DISABLED identity semantics;
- absence of revocation/introspection;
- Phase 9 boundary for transitive/multi-agent delegation.

Recommended new focused doc:

```text
docs/identity-delegation.md
```

Update at least:

- `docs/architecture.md` — enduring Phase 6 authority architecture;
- `docs/security-contract.md` — executable identity/OBO semantics;
- `docs/runtime-mcp.md` — operational credential/delegation behavior;
- `docs/contract-conformance.md` — authority probes/coverage;
- `docs/replay-incidents.md` — authority replay/legacy compatibility;
- `docs/evidence-model.md` if event semantics change;
- `docs/README.md`;
- `AGENTS.md`;
- `README.md` only where public usage/status actually changed.

Do not rewrite the PRD for implementation convenience.

---

## 22. `AGENTS.md` phase-boundary update

At Phase 6 completion, `AGENTS.md` should state the actual boundary, including:

- Phase 6 identity/delegation implemented and awaiting independent review;
- direct one-hop delegation only;
- identity proof never grants beyond contract;
- static config is not remote authentication;
- signed JWT validation uses pinned trusted configuration;
- raw credentials never belong in policy/evidence;
- authority expires and is rechecked before dispatch;
- `parent_delegation_id`/transitive delegation remains unsupported;
- `max_delegated_agents` remains unsupported;
- Phase 7+ scope is not yet implemented.

Remove stale language that says all OAuth/OIDC work is forbidden once the narrow Phase 6 adapter exists, but do not imply a complete OAuth/OIDC stack.

---

## 23. Implementation report

Create:

```text
docs/reports/phase-6-implementation-report.md
```

Required sections:

1. baseline and final implementation commit;
2. Phase 5 preflight/reconciliation;
3. scope implemented;
4. identity/authority trust model;
5. delegation/task/capability/resource semantics;
6. static and signed-JWT provider behavior;
7. compiler/version/hash compatibility;
8. runtime/approval/evidence binding;
9. replay/regression compatibility;
10. schema/docs/CLI changes;
11. deliberate deviations from this plan;
12. dependency changes and rationale;
13. exact verification commands/results;
14. mandatory self-review;
15. known limitations;
16. readiness for independent Phase 6 review;
17. readiness/not-readiness for Phase 7.

Do not call implementation self-review independent approval.

---

## 24. Mandatory implementation self-review

Before declaring Phase 6 complete, explicitly check:

- Can a token/principal claim grant authority absent a contract allow?
- Can a broad delegation override a contract deny/default deny?
- Can a contract allow bypass a narrower delegation?
- Can token scopes be treated as capabilities without explicit mapping?
- Can an unknown subject become an internal principal automatically?
- Can `acts_on_behalf_of` run without a valid direct delegation in ENFORCE?
- Can a delegation for another delegate be reused?
- Can a delegation from another delegator satisfy the contract?
- Can an expired delegation/token authorize a call?
- Can authority expire during approval and still dispatch?
- Can the same delegation ID with different content reuse an approval?
- Can a parent delegation ID be ignored while still claiming transitive verification?
- Can resource-scope intersection accidentally widen authority?
- Are null and empty scope semantics preserved?
- Can tool/model arguments modify identity/delegation?
- Can raw bearer credentials reach stdout/stderr/evidence/replay/regression files?
- Can a JWT verifier accept `none`, wrong algorithms, wrong issuer/audience, unknown keys, or token-controlled key URLs?
- Can SHADOW/DISABLED be mislabeled as enforcing identity?
- Can static trusted config be mislabeled as remote authentication?
- Can old `phase4-v1` replay bundles still be parsed truthfully?
- Can a historical plan be silently upgraded to `phase6-v1` semantics?
- Can Phase 6 replay require/revalidate a raw historical bearer token?
- Are authority-sensitive changes visible in semantic diff?
- Are Phase 0–5 approval, data-flow, evidence, and replay invariants intact?
- Are conformance and runtime using the same authority semantics?
- Are docs/schemas/examples synchronized with code?
- Did implementation accidentally pull Phase 9 delegation graphs forward?

Any unresolved issue must be documented explicitly.

---

## 25. Exit criteria

Phase 6 is complete when all of the following are true:

1. ENFORCE can bind a runtime to a canonical principal through trusted static config or a real signed-JWT verification path.
2. Identity verification never grants a capability absent contract authority.
3. `acts_on_behalf_of` is executable rather than an unconditional unsupported gap.
4. Required direct delegation is validated for delegator, delegate, task/capability/resource scope, issue/expiry, and Phase 6 chain constraints.
5. Effective authority is the restrictive intersection of contract, credential ceiling, delegation, and task/resource ceilings.
6. Broad delegation cannot override contract deny/default deny.
7. Broad contract policy cannot override a narrower delegation.
8. Authority freshness is checked at startup, per call, and immediately before dispatch after approval.
9. Approvals bind exact authority content through an authority digest or equivalent.
10. Raw credentials are not persisted or exposed in normal diagnostics/evidence/replay.
11. The signed-JWT adapter verifies signature, issuer, audience, time, subject mapping, algorithm/key policy, and explicit scope mapping without unsafe fallback.
12. Phase 6 does not claim token issuance, revocation/introspection, full OIDC lifecycle, or transitive delegation.
13. policy/runtime/conformance share one canonical delegation/authority interpretation.
14. authority-aware evidence is typed, content-minimized, and truthful across ENFORCE/SHADOW/DISABLED.
15. Phase 6 replay works from recorded verified authority facts, not raw tokens.
16. historical Phase 5/`phase4-v1` bundles remain readable or fail with explicit typed compatibility limitations, never silent reinterpretation.
17. compiler/version/hash changes are explicit and tested.
18. generated schemas, examples, focused docs, architecture, and `AGENTS.md` are synchronized.
19. existing Phase 0–5 tests and quality gates continue to pass.
20. a focused end-to-end local example demonstrates least-privilege narrowing.
21. the implementation report records exact behavior, verification, deviations, and limitations.

Phase 7 should begin only after an independent Phase 6 review and correction pass.
