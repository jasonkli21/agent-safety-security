# Phase 7 implementation report

## 1. Baseline and preflight

Started at `4dd82ea844638c536792cdb0efef206f6cacd6e9`, the Phase 6 review-fix baseline.
The supplied Phase 7 plan was already untracked in the workspace and is included with this
implementation (trailing Markdown whitespace normalized for the staged diff gate). The unrelated untracked root `PHASE-0-SOL-MEDIUM-PROMPT.md` is left untouched.
Read the PRD, architecture, Phase 7/6 plans, Phase 6 implementation/review-fix reports and focused
runtime, identity, provenance, evidence, replay and conformance docs before implementation.

Initial `.venv/bin/pytest -q`: **24 failed, 624 passed**. Phase 6 now correctly requires trusted
facts on direct requests, but two older policy/data-flow test helpers omitted them. Those helpers
now explicitly supply synthetic trusted authority. A generated missing-authority OBO probe
incorrectly expected AUTHORITY_REQUIRED instead of DELEGATION_REQUIRED; corrected only its oracle.
No production authority checks were relaxed. Ruff additionally found two lint errors and three
unformatted files from Phase 6 fixes. Applied narrow formatting/import corrections. The corrected
baseline passed **648 tests** before Phase 7 feature work; Ruff and format checks also passed.

Initial mypy, example validation/evaluation, regressions, build and diff checks passed. These
prerequisite corrections are distinct from the Phase 7 features and intentionally share the
single commit requested for the implementation.

## 2. Reconciliation with newer HEAD

HEAD exactly matched the plan's inspected baseline; no newer changes needed reconciliation.
Phase 6 review fixes exist despite stale AGENTS/README readiness language. The user's explicit
Phase 7 implementation request and supplied implementation-ready plan establish this phase's
scope. Updated current-state docs; preserved historical Phase 6 reports as historical records.
The prohibition on creating sandbox infrastructure is read narrowly: compose with existing Docker
and optional runsc, without implementing a sandbox runtime or service.

## 3. Common adapter architecture

Added versioned `ExecutionBinding` and `ProtectedTool`, with async `ProtectedCall.invoke` as the
shared adapter surface. Private dispatch follows RuntimeGateway, never a duplicate policy engine.
Validated snapshots include descriptor schemas/hashes, exact resource extraction/opaque semantics,
approval display paths and output/sink classification. Shared argument/schema validation and
resource/data coverage moved into protocol-independent runtime modules. Coverage gaps fail ENFORCE
registration; SHADOW/DISABLED continue under existing truthful gateway behavior.

A route digest commits the complete protected tool snapshot plus transport/native revision and
isolation identity. Provider/framework rebinding changes adapter identity while retaining private
protected dispatch. Tool/config access returns defensive copies. No dynamic registry/plugin
framework, mutable authority grant, framework-specific core type or compiler expansion was added.

## 4. Native adapter

`protect_native` accepts one explicitly classified async callable receiving a JSON argument object.
Supported results are ToolResponse or strict finite JSON; unsupported Python values fail through
safe gateway error handling. Names confer no capabilities. Operator-supplied implementation
revision identifies local callable wiring; this is not code attestation. The executable local
example demonstrates native, provider and explicit host-process calls.

## 5. Provider adapters

`ProviderTools` exports OpenAI function tools, Anthropic tools and Gemini function declarations
from protected snapshots and strictly parses their respective call shapes. Duplicate tool names,
unknown fields/names, malformed/duplicate-key/non-finite JSON, wrong argument shapes and malformed
IDs fail. IDs supply no authority or evidence identity. Provider selection is read-only after
construction and participates in route identity. No vendor SDK/model network/API key is used.

## 6. LangChain/LangGraph

Optional `as_langchain_tool` creates a real async StructuredTool around a protected call, with
snapshotted metadata and a coroutine entering the gateway. This is consumable by LangGraph's
ordinary tool boundary; no graph runtime/checkpointer/model wrapper is added. Existing callable
behavior can first be registered natively with explicit protected metadata. Tested against installed
`langchain-core==1.6.12`, including deny/no-dispatch behavior. Framework config/callbacks never
select canonical identity or grants. The adapter changes execution-route identity.

## 7. HTTP

Protected fixed HTTP(S) origin, method, path, headers, deadline/socket timeout, body/response bounds
and sink category. Arguments become JSON body values; GET rejects arguments. There are no variable
URLs, redirects, retries, cookies, environment proxies or automatic auth. Reject userinfo/fragments,
unsafe paths, header injection/duplicates and host/proxy/framing overrides. Response streaming is
bounded. Tests use only a synthetic exact-loopback endpoint, explicitly permitted by its fixture
while the suite's external-network ban remains active. Header/body canaries remain absent from
evidence. Cancellation can leave an in-flight bounded worker; unknown effect is reported.

## 8. Process/coding actions

Protected absolute executable/cwd, literal argv and fixed ordered append slots, explicit env,
DEVNULL stdin, aggregate bounded output and timeout. No shell=True, shell interpolation, parent
environment, executable/cwd/backend argument selection or retry. POSIX process groups are killed
on completion/cancellation/timeout/overflow, and pipes are drained/cancelled with bounds. Tests
verify literal shell metacharacters, exact cwd/env, absent parent canary, timeout/output bounds
and that a cancelled child no longer exists. This protects coding-harness process actions; it
implements no coding agent or terminal.

## 9. Isolation/Docker/gVisor composition

IsolationBackend has real HostBackend (explicitly unisolated) and DockerBackend implementations.
Docker constructs and executes a real CLI command with network none, read-only rootfs by default,
dropped capabilities, no-new-privileges, numeric non-root user, CPU/memory/PID/time/output limits,
explicit env/cwd/mounts and pull=never. Protected runtime selection supports runsc composition.
No privileged/host namespace/socket option or automatic fallback exists. Mount validators reject
root/system/direct socket mounts, traversal and mount-option injection; contents remain trusted.

The Docker client uses empty env and a private empty config directory to avoid ambient daemon,
context or credential configuration. Random container names support rm -f cleanup after dispatcher
entry/cancellation. Interrupted-run cleanup failure is explicit; no inaccessible-daemon cleanup
proof is claimed. Tests exercise deterministic secure command construction and the concrete backend
through a fake process port, success/cleanup and unavailability/no-host-fallback in all modes.
No live Docker/gVisor smoke test was run; no daemon or runsc is required by default tests.

## 10. MCP convergence

MCP now imports shared exact argument validation, schema-reference checks and binding coverage.
Kept discovery pagination/snapshots/pins, request-ID hardening, SDK transport, stdio ownership,
SHADOW behavior and exact discovery-bound semantic proofs in MCP. Its existing gateway compatibility
calls omit new route metadata deliberately, preserving historical paths. All MCP regression tests
remain in the full passing suite. This is a focused extraction, not wholesale adapter replacement.

## 11. Evidence/replay/regression/conformance

NormalizedAction additively binds execution_binding_digest; TOOL_DISPATCHED adds safe versioned
route facts (adapter kind/ID/version and config/isolation digests). No env/header/body/credential
values are serialized. Full config hashes may disclose equality, as existing digests do.
Replay substitutes recorded route metadata and has no live adapter/backend execution. A new runtime
→ bundle → replay test requires UNCHANGED and patches live adapter invocation to fail if called.
Existing historical bundles, regressions and full evidence/trajectory tests remain green.

Focused shared conformance covers authority/policy/approval/budget/data-flow failure without dispatch,
resource coverage/extraction, mode truthfulness, cancellation ambiguity, route/approval invalidation,
strict provider normalization, safe secret minimization and historical action serialization. It
reuses gateway semantics rather than copying the policy suite for every adapter. Generated schemas
are exported from canonical models, including five new operational config/model schemas.

## 12. Compatibility/version/hash decisions

No authored contract semantics changed; compiler remains phase6-v1 and effective-policy/document
hash projections are unchanged. Additive schema 0.1 fields omit absent values on serialization,
retaining legacy action/event/bundle identities. Strict older readers need refreshed schemas.
New actions bind complete route digests, including isolation and source/sink configuration.
Safe route evidence is operational identity, not a signed execution or image-provenance proof.

## 13. Dependencies

Added only optional `langchain = ["langchain-core>=1,<2"]`, justified by real StructuredTool
interoperability; CI installs it. No mandatory HTTP/provider/container dependency was needed:
stdlib HTTP and async subprocess are sufficient for the deliberately narrow surfaces. Network
installation initially failed inside the sandbox; the approved elevated uv installation succeeded.
The installed LangChain extra brings its own transitive dependencies, including LangSmith, but
AgentSec adds no tracing integration or model client. Default core remains small.

## 14. Exact verification commands/results

Commands run from repository root with its Python 3.12 environment. Local HTTP tests need loopback
socket permission in this execution sandbox; elevated test runs allow that endpoint only. Tests
never use provider credentials, external services, Docker daemon or gVisor.

| Command | Result |
| --- | --- |
| `.venv/bin/pytest -q` initial baseline | 24 failed / 624 passed; prerequisite fixture/oracle fixes above |
| `.venv/bin/pytest -q` corrected baseline | PASS, 648 tests |
| `.venv/bin/ruff check .` initial | Two existing errors; corrected imports/formatting |
| `.venv/bin/ruff format --check .` initial | Three existing unformatted files; corrected |
| `.venv/bin/mypy src` initial | PASS, 90 source files |
| `.venv/bin/agentsec examples validate` initial | PASS, 3 contracts / 3 scenarios |
| `.venv/bin/agentsec eval examples` initial | PASS, all 6 expected outcomes |
| `.venv/bin/agentsec regression run --root examples/regressions` initial | PASS, 2 ACTIVE PASS / 1 DRAFT |
| `.venv/bin/python -m build --no-isolation` initial | PASS, wheel and sdist |
| `git diff --check` initial | PASS |
| `UV_CACHE_DIR=/tmp/agentsec-p7-uv uv pip install --python .venv/bin/python 'langchain-core>=1,<2'` | PASS after network elevation, installed 1.6.12 |
| `.venv/bin/pytest -q tests/unit/test_adapters_isolation.py` | PASS, 66 tests before final 3 coverage cases; all 69 included in full suite |
| `.venv/bin/pytest -q tests/unit/test_adapters_isolation.py -k 'provider or adapter_and_classification'` | PASS, 10 tests after provider selection immutability change |
| `.venv/bin/pytest -q` final | PASS, 717 tests |
| `.venv/bin/ruff check .` final | PASS |
| `.venv/bin/ruff format --check .` final | PASS, 164 files |
| `.venv/bin/mypy src` final | PASS, 102 source files |
| `.venv/bin/agentsec examples validate` final | PASS, 3 contracts / 3 scenarios in indexed corpus |
| `.venv/bin/agentsec eval examples` final | PASS, all 6 expected outcomes |
| `.venv/bin/agentsec regression run --root examples/regressions` final | PASS, 2 ACTIVE PASS / 1 DRAFT |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS, regenerated from models |
| `.venv/bin/python examples/adapters/local_tools.py` | PASS, native/provider echo and process stdout |
| `.venv/bin/python -m build --no-isolation` final | PASS, wheel and sdist |
| `git diff --check` final | PASS |

## 15. Deviations

- HTTP implements exact protected paths, not templates/query slots. JSON body arguments provide
  a real bounded action without introducing a second resource/URL interpretation language.
- Provider declarations are generated from protected snapshots, not imported as grants from
  arbitrary external declarations. Representative strict call shapes are intentionally finite.
- LangChain integration wraps existing protected calls into framework tools; original framework
  callables must be explicitly registered with canonical metadata rather than auto-instrumented.
- MCP retains absent route metadata on its compatibility path, while using shared validation and
  coverage. New Phase 7 routes always bind execution identity.
- No separate CLI or adapter conformance percentage was added. The async library API and focused
  common-path tests demonstrate the required harness boundary without another policy/report engine.
- No optional live Docker test is asserted; deterministic backend-port tests exercise actual command
  construction/execution wiring, while daemon/environment interoperability remains a smoke-test task.

## 16. Known limitations/open questions

Python in-process encapsulation is not hostile-code isolation; protect wiring/configuration and
callable revision selection. Mount contents, local executables, image content and DNS remain trusted.
Tags are not image integrity identities. Docker availability/runtime setup is operator-managed.
POSIX host process lifecycle is tested on macOS and targeted at Linux/macOS; Windows is unclaimed.
Cancellation cannot undo HTTP effects or prove container cleanup through an unavailable daemon.
HTTP error details are deliberately generic; body/path/provider shapes are deliberately narrow.
LangGraph graph execution is not tested separately from the real LangChain tool boundary.
Resource semantics remain opaque exact; no URL aliasing, semantic exfiltration detection, complete
model-internal taint, sandbox escape proof or distributed idempotency claim is made.

## 17. Mandatory security self-review

Inspected new dispatchers and surrounding gateway/approval/evidence/replay code, old MCP callers
and complete diff. Every protected invocation enters RuntimeGateway before adapter execution;
no adapter implements policy or receives authority from framework/provider fields. DENY/default
deny, restrictive authority/data flow, one-shot approvals and budgets remain canonical checks.
Configuration snapshots bind exact route and classifications; adapter/isolation changes alter
approval digests. Self-review strengthened route identity to include the whole ProtectedTool and
made provider selection read-only. No raw secret values enter route summaries or evidence.

Inspected fixed origin/path/header construction, direct stdlib transport, no redirect/proxy/retry,
request/response bounds and safe exceptions. Inspected absolute argv/cwd, explicit environment,
DEVNULL stdin, process group termination and output limits. No shell=True or command interpolation.
Reviewed Docker flags, non-root/read-only/network-none/capability/resource limits, explicit mounts,
private client config and interrupted cleanup. Self-review added empty Docker config isolation,
stronger system/socket mount validation and explicit cleanup-failure handling. Isolation failure
never invokes HostBackend; SHADOW/DISABLED do not override configured containment.

Reviewed exactly-one dispatcher entry, cancellation unknown-effect evidence, response exposure
ordering and replay substitution. Replay never imports a live dispatch backend; old serialization
omits absent fields and existing corpus stays green. All generated schemas came from export.
No Phase 8 supply-chain proof, Phase 9 graph or hosted service was introduced. This is an
implementation self-review, not independent approval.

## 18. Independent-review readiness

Phase 7 is implemented and ready for independent review with focused docs, examples, schemas,
negative tests and full passing gates. Review should particularly inspect route digest completeness,
Docker interruption/cleanup and mutable implementation trust assumptions. Live Docker/runsc smoke
verification is a documented remaining environment check, not a claim established by fakes.

## 19. Phase 8 boundary

Phase 8 has not started. Independent Phase 7 review/fixes and a reviewed Phase 8 plan are required
before supply-chain expansion. No registry/image signing, tool/skill trust marketplace, dependency
provenance or multi-agent graph behavior is added here.
