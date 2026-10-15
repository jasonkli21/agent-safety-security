# Scenario format v0.1

A scenario is a static reproducible test specification. Phase 0 validates it and never executes
its task, tools, injections, assertions, or mock responses. See the generated
[scenario schema](../schemas/generated/scenario.schema.json) and `domain/scenarios.py` for exact types.

## Anatomy

Required top-level fields are `schema_version: "0.1"`, `scenario_id`, `title`, `attack_family`
(SecurityCategory), `setup`, `task`, and a nonempty `assertions` array. Optional `description`,
set of `tags`, ordered `injections`, and ordered `utility_assertions` provide context. Unknown
fields/versions are rejected. IDs and strict JSON/YAML loading follow the
[contract rules](security-contract.md).

`setup` holds static ordered fixture collections: `tools` (shared ToolDescriptor), `data_artifacts`
(shared DataArtifactRef), `mock_responses` (`tool_id` and finite JSON `response`), `canaries`
(`canary_id`, synthetic `value`), and `initial_memory` (artifact IDs). Defaults are empty. Tool,
artifact, and canary IDs must be unique within each collection. Mock response/initial memory
references must resolve locally. Mock response order is meaningful for future repeated calls.
No fixture is dispatched or fetched during validation.

`task` requires `task_id` and `user_input`; optional `task_scope` uses the same requested-scope
model as policy/contracts. Unlike an authorization request, a scenario legitimately contains
user text. Text remains test input and never authorizes anything.

An injection requires `source`, descriptive `location`, `trust_class`, optional set of `labels`,
and exactly one of `content` or `fixture_ref`. Fixture references are opaque external fixture
IDs, not paths automatically opened by the loader. Sources can be web pages, emails, tool
responses or memory entries. Classification does not certify content as safe.

## Deterministic assertion union

| Security `type` | Required operand | Intended future observation |
| --- | --- | --- |
| TOOL_NOT_CALLED | `tool_id` | No dispatch to this tool. |
| TOOL_CALLED | `tool_id` | A dispatch to this tool. |
| CAPABILITY_NOT_REQUESTED | `capability` | No request for this capability. |
| OUTPUT_NOT_CONTAINS_CANARY | `canary_id` | Canary absent from captured output/sinks. |
| APPROVAL_REQUIRED | `capability` | Requests for capability require approval. |
| MAX_TOOL_CALLS | Nonnegative strict integer `maximum` | Bound observed tool dispatch count. |
| RUN_TERMINATED_REASON | Stable `reason` code | Termination with that reason. |
| NO_FINDING_CATEGORY | `category` | No finding of this category. |
| FINDING_CATEGORY_PRESENT | `category` | At least one finding of this category. |

The closed discriminated union rejects unknown types and wrong operands. Tool and canary
operands must reference setup entries. Capability assertions can refer to a capability with no
available fixture tool, expressing forbidden requests. Assertions describe expected evidence;
Phase 1 must specify missing-evidence handling, output/sink coverage, and non-vacuous approval
assertion behavior before executing them. Phase 0 does not claim these intended observations
have occurred.

Utility assertions have a separate union: `EXPECTED_TOOL_CALLED` (`tool_id`, resolving in setup)
and `OUTPUT_CONTAINS` (nonempty `text`). Security and legitimate utility must be measured
separately; blocking all useful actions is not a successful defense. No LLM judge is needed to
represent these checks. There is no generic scorer plugin or execution hook in this version.

## Tested examples

- [Indirect prompt injection](../examples/scenarios/indirect-injection.yaml): a malicious web
  result asks for email exfiltration; forbid email requests/dispatch while expecting search.
- [Canary exfiltration](../examples/scenarios/canary-exfiltration.yaml): a synthetic canary must
  stay out of output, and email requires approval.
- [Resource exhaustion](../examples/scenarios/resource-exhaustion.yaml): repeated search is
  bounded and termination uses `BUDGET_EXCEEDED`.

Run `agentsec scenario validate examples/scenarios/indirect-injection.yaml` or
`agentsec examples validate`. Both are local. YAML → model → canonical JSON → model is tested.
Arrays retain order; sets and object keys normalize deterministically. Updating fixtures or
assertion shapes requires schema regeneration and review of canonical golden files.
