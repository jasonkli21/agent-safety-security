# Executable contract conformance (Phase 3)

One validated contract compiles into an immutable native exact-match plan. Compilation owns
normalization and the unsupported inventory. Native policy owns execution. The probe oracle
independently states obligations from compiled facts and the explicit DENY > REQUIRE_APPROVAL >
ALLOW > DEFAULT_DENY table. Task scope always limits authority.

```bash
agentsec contract compile examples/mcp/contract.yaml
agentsec contract test examples/mcp/contract.yaml --format json
agentsec contract coverage examples/mcp/contract.yaml
agentsec contract coverage examples/mcp/contract.yaml --run
agentsec contract diff examples/mcp/contract.yaml examples/mcp/contract.yaml
```

All four commands support `--format text|json`. JSON uses canonical ordering. Text uses stable
summaries. `test` exits 0 for passing generated cases, 1 for failed conformance, 4 for execution
errors (ERROR takes precedence). CLI usage errors use 2; existing input-validation errors use 1.
Inspection and diff exit 0 on a valid report, including a report containing gaps or expansions.
No command activates policy, calls a tool/model or uses credentials. An unsupported contract can
pass its generated supported obligations: inspect coverage before interpreting a PASS.

## Compiled meaning

The versioned plan contains contract/schema/compiler identity, effective policy hash, protected
principal/agent/environment, exact rules with original IDs, immutable task ceiling, supported
budget configuration and approval timeout. Source paths identify rules as `tools.rules/RULE_ID`.
Configured unsupported semantics are individual atoms with intent digests; they are never
reported as compiled/enforced. Mutable budget/approval state is absent from this artifact.

`compile` exposes authored policy values, including exact resources; handle its output like the
source contract. The other reports contain IDs, semantic digests, outcomes and status, not runtime
argument/response content. The JSON schemas are exported from the public Pydantic definitions.
Compiled manifests are inspection artifacts, not a trusted activation format. Runtime checks any
supplied plan against its own compilation, including contract ID and effective policy identity.

## Generated obligations and coverage

The generator uses capabilities referenced by rules/scope, each capability's exact resources,
`None`, a collision-free other-resource sentinel, and a collision-free unknown capability.
This compact partition exercises exact rules, overlaps, default deny and task exclusions.
A protected task ceiling may make a rule or default-deny branch unreachable; coverage then
leaves that atom without generated tests. A shadowed rule may participate in an overlap probe;
coverage means represented in a checked obligation, not independently influential on its outcome.

Each coverage row separates compiled intent, runtime support, adapter requirement/proof,
generated probe IDs, generated evaluation IDs and execution status. Without `--run`, execution
is NOT_RUN. Budget/timeout atoms are runtime-supported but have no generated policy cases;
stateful behavior remains verified by the runtime tests. Unsupported atoms have no tests.
An offline command has no discovery proof: adapter requirements remain UNPROVEN. The MCP adapter
can supply COVERED/UNCOVERED proof from discovered bindings; no applicable tool leaves it unproven.
There is no generic security percentage.

The evaluation bridge uses the native evaluator's actual decision to emit canonical evidence;
Phase 1 causality/assertions check it. Approval cases contain a matching request and exact bound
approval before synthetic dispatch. Missing/contradictory evidence and wrong outcomes fail or
error. The synthetic approver is a deterministic local test actor, not approver authentication.
Generated conformance is not model robustness or a prompt-injection evaluation.

## Semantic diff boundary

Diff evaluates both compiled plans over the union of referenced capabilities/resources, scope
resources, `None`, one OTHER resource per capability and an unknown capability. It includes
resource exceptions beneath broad rules and the remaining default space. Request identity/scope
is adapted to each protected plan; identity/environment and scope configuration changes are
reported separately. Authority is ordered DENY < REQUIRE_APPROVAL < ALLOW, so approval-to-allow
is an expansion and allow-to-approval a reduction; both also flag approval-boundary changes.
Scope widening/narrowing is reported even when rules still deny the representative action.

Supported budget changes treat an absent limit as unbounded. Approval timeout changes are
reported without asserting a universal safety ordering. Unsupported intent changes are detected
by atom digests and labeled unsupported; their behavior is not simulated. Representative resource
values are digested; capability names remain visible. This is finite comparison of the native
subset, not formal equivalence, arbitrary argument analysis, deployment or general data policy.
Phase 4 data/provenance enforcement and all later adapters/identity services remain out of scope.
