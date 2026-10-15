# Canonical terminology and taxonomy

`src/agentsec/domain/taxonomy.py` is the wire-value authority. Enum values are case-sensitive
uppercase strings except ordered Severity, which uses explicit integer values. Unknown values
are rejected, never mapped to an approximate synonym. The generated
[schemas](../schemas/generated/) embed these enum definitions.

| Concept | Meaning |
| --- | --- |
| Principal | User, agent, or service identity capable of requesting/delegating authority; identity alone conveys no permission. |
| Agent | Logical protected agent identity and contextual runtime metadata, separate from its principal binding. |
| Delegation | Explicit principal-to-principal capability/task scope with issue/expiry and optional parent reference. Subset enforcement is deferred. |
| Task | Requested user work. TaskScope expresses requested capabilities/resources and grants nothing by itself. |
| Capability | Protocol-independent action ID such as `email.send`; not a fixed global registry. |
| Tool | Stable callable identity with separately mutable schema/description, capability set and risk metadata. |
| Resource | Opaque action target/scope string; v0.1 implements no selector language. |
| Policy request | Structured identity/action/resource/context input to the authorization boundary. |
| Policy decision | Explainable allow, deny, approval-required or error result with policy identity and reason codes. |
| Approval | An approver decision bound through an approval request to an exact normalized action and request. |
| Security signal | Observed indicator, such as suspicious untrusted content; not independently an authorization grant. |
| Security event | Typed factual record of one stage of a run; not an interpreted finding. |
| Finding | Interpreted security result with severity and exact evidence references. |
| Incident | Investigation/case derived from findings/events; deferred beyond Phase 0. |
| Data artifact | Content-free ID, provenance origin/parents, labels, optional content digest/time. |
| Scenario | Reproducible static setup, task, injections and deterministic assertion specification. |
| Assertion | Expected observable security or utility property, represented but not executed in Phase 0. |
| Run | One execution context with its own monotonically increasing event sequence. |
| Trace | Correlation identity associated with a run; does not imply global distributed ordering. |

## Stable enums

- PrincipalType: `USER`, `AGENT`, `SERVICE` identify the kind of principal, without privilege.
- PolicyOutcome: `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `ERROR`. RuleDecision contains the first
  three only: a contract cannot author an engine error as permission.
- EnforcementMode: `ENFORCE`, `SHADOW`, `DISABLED` are vocabulary only; no enforcement exists.
- ApprovalOutcome: `APPROVE`, `DENY`; ApprovalScope: `ONE_SHOT` only.
- Severity: `INFO=0`, `LOW=1`, `MEDIUM=2`, `HIGH=3`, `CRITICAL=4`. Values serialize as integers
  and compare in that order. They describe importance, not numerical confidence.

SideEffectClass identifies the kind of action:

| Value | Meaning |
| --- | --- |
| NONE | No declared data access or side effect. |
| READ | Read existing data. |
| INTERNAL_WRITE | Write within the internal trust domain. |
| EXTERNAL_WRITE | Write/send outside that domain. |
| DESTRUCTIVE | Delete or irreversibly damage state. |
| CODE_EXECUTION | Execute supplied/generated code. |
| IDENTITY_PRIVILEGE | Change identity or privilege state. |
| FINANCIAL | Transfer financial value or make financial commitments. |
| INFRASTRUCTURE | Change deployed infrastructure. |

TrustClass indicates source context, not a proof of trust:

| Value | Meaning |
| --- | --- |
| TRUSTED_CONFIG | Configuration controlled outside protected agent context. |
| USER_INPUT | User-supplied contextual content. |
| UNTRUSTED_EXTERNAL | Retrieved or externally authored content. |
| TOOL_OUTPUT | Data returned by a tool, potentially adversarial. |
| MODEL_OUTPUT | Probabilistic generated content. |
| GENERATED_POLICY_SUGGESTION | Advisory policy text that has not acquired authority. |

DataLabel is a simple nonexclusive set; no ordering/lattice or automatic propagation exists:
`PUBLIC` (public content), `INTERNAL` (internal content), `SENSITIVE` (restricted content),
`SECRET` (secret content), `PII` (personal information), `CREDENTIAL` (authentication material),
`UNTRUSTED_CONTENT` (untrusted authorship), `USER_PROVIDED` (user source), `TOOL_OUTPUT` (tool source).

## Security categories

| Value | Threat/result meaning |
| --- | --- |
| PROMPT_INJECTION | Instruction-like adversarial content attempts to cross an authority boundary. |
| GOAL_HIJACKING | Agent pursues an attacker-selected goal instead of the legitimate task. |
| UNAUTHORIZED_TOOL_USE | A tool/capability outside explicit authority is requested or dispatched. |
| EXCESSIVE_AGENCY | Agent performs more work/side effects than the task requires. |
| ARGUMENT_VIOLATION | A tool request targets forbidden parameters or resources. |
| APPROVAL_BYPASS | Action proceeds without a valid required exact-action approval. |
| SECRET_EXFILTRATION | Secret/credential data reaches an unauthorized output or sink. |
| PII_EXPOSURE | Personal data crosses its permitted disclosure boundary. |
| MEMORY_POISONING | Untrusted content is persisted/reused as trusted memory. |
| TOOL_POISONING | Malicious tool metadata/output manipulates agent behavior. |
| SUPPLY_CHAIN_CHANGE | Tool/schema/description/dependency mutation changes a reviewed trust assumption. |
| RESOURCE_EXHAUSTION | Retry/loop/delegation/cost consumption exceeds intended bounds. |
| DELEGATION_ESCALATION | Child/delegate authority exceeds valid parent/task authority. |
| POLICY_BYPASS | An action avoids the trusted policy boundary or overrides its result. |
| TRACE_INTEGRITY_FAILURE | Evidence is missing, reordered, duplicated, forged or otherwise untrustworthy. |

EventType values and their exact evidentiary meanings are listed in the
[evidence model](evidence-model.md): `RUN_STARTED`, `RUN_FINISHED`, `TOOL_REQUESTED`,
`POLICY_EVALUATED`, `APPROVAL_REQUESTED`, `APPROVAL_DECIDED`, `TOOL_DISPATCHED`, `TOOL_RETURNED`,
`SECURITY_SIGNAL`, `RUN_TERMINATED`, `EFFECT_VERIFIED`.

ReasonCode gives deterministic explanations: `EXPLICIT_ALLOW`, `EXPLICIT_DENY`, `DEFAULT_DENY`,
`APPROVAL_REQUIRED`, `UNKNOWN_CAPABILITY`, `OUTSIDE_TASK_SCOPE`, `BUDGET_EXCEEDED`, `DATA_FLOW_DENIED`,
`INVALID_REQUEST`, `POLICY_ENGINE_ERROR`. These are result vocabulary, not implemented checks.
Validation errors use a separate ErrorCode enum in `contracts/errors.py`; they report invalid
artifacts rather than authorizing actions.
