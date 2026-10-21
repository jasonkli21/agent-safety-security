# Agent Safety & Security

A local-first security lifecycle for tool-using AI agents: define explicit authority, test it adversarially, enforce it at runtime, and turn observed failures into regressions.

> **Current status:** Phase 8 local supply-chain inventory, operator-reviewed pins, optional Ed25519 verification and restrictive runtime trust admission are implemented. See the [trust guide](docs/supply-chain-trust.md) and [implementation report](docs/reports/phase-8-implementation-report.md). Phase 7 fixes still await independent acceptance; Phase 8 awaits independent review.

## Product thesis

The project is built around a closed loop:

```text
security contract
   ├──> adversarial evaluation
   └──> runtime policy
            ↓
      evidence/provenance
            ↓
      incident analysis
       ├──> policy change
       └──> regression test
```

The long-term differentiator is not “another MCP firewall.” Existing projects already cover meaningful pieces of authorization, approvals, identity, audit, isolation, scanning, and red teaming. This project aims to unify **specification, verification, enforcement, evidence, and regression** around one canonical security model.

## Start here

For current state and implementation work, read:

1. [`AGENTS.md`](AGENTS.md) — current repository operating contract and phase boundary.
2. [`docs/prd.md`](docs/prd.md) — product vision, competitive positioning, and phased roadmap.
3. [`docs/architecture.md`](docs/architecture.md) — enduring system boundaries and architectural invariants.
4. [`docs/reports/phase-0-implementation-report.md`](docs/reports/phase-0-implementation-report.md) — original Phase 0 implementation and verification record.
5. The active plan under `docs/plans/`, when one exists. The [Phase 0 plan](docs/plans/phase-0-implementation-plan.md) is completed historical scope, not an active implementation request.
6. Relevant focused docs under `docs/` and the latest review-fixes report.

The [Phase 0 implementation prompt](docs/prompts/phase-0-sol-medium-implementation-prompt.md) is historical provenance for the completed bootstrap, not active instructions.

## Phase 0 foundation (complete)

Phase 0 established one shared language for:

- principals, agents, tasks, and delegation;
- tools and capabilities;
- security contracts;
- policy requests/decisions;
- approvals;
- data/provenance primitives;
- security events and findings;
- evaluation scenarios;
- strict validation, canonicalization, and schema export.

The Phase 0 foundation is implemented and documented in the [implementation report](docs/reports/phase-0-implementation-report.md). Phase 1 is implemented under the [reviewed plan](docs/plans/phase-1-implementation-plan.md); see the [evaluation guide](docs/evaluation.md) and [implementation report](docs/reports/phase-1-implementation-report.md). Phase 2 follows the [implementation plan](docs/plans/phase-2-implementation-plan.md); Phase 3 follows the [implementation plan](docs/plans/phase-3-implementation-plan.md).

## Repository layout

```text
src/agentsec/                 canonical Python domain, validation, and CLI
tests/                        local deterministic tests
docs/                         product, architecture, plans, decisions, reports
docs/prompts/                 implementation/review handoff prompts
examples/                     public contract/scenario fixtures
schemas/generated/            generated JSON Schemas
```

## Development philosophy

- deterministic security controls before probabilistic ones;
- explicit authority outside model context;
- fail closed when enforcement is actually promised;
- local-first and no mandatory paid APIs;
- no speculative microservices or generic framework abstraction;
- one domain model shared by evaluation and runtime;
- evidence must distinguish requested, allowed, approved, dispatched, returned, and effect-verified states;
- document deliberate deviations from phase plans.

## Local setup and validation

Python 3.12+ is required. From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,mcp]"
agentsec version
agentsec contract validate examples/contracts/research.yaml
agentsec scenario validate examples/scenarios/indirect-injection.yaml
agentsec examples validate
agentsec eval examples
agentsec eval run --contract examples/contracts/research.yaml --scenario examples/scenarios/indirect-injection.yaml --fixture examples/eval-fixtures/indirect-injection-safe.yaml
agentsec schema export --out schemas/generated
ruff check .
ruff format --check .
mypy src
pytest
python -m build
```

Validation is local and requires no API keys. `examples validate` reads `./examples` by default;
use `--root /path/to/examples` outside this checkout. `eval run` supports text/JSON reports and optional JSONL evidence; see the
[evaluation guide](docs/evaluation.md). `agentsec protect mcp` runs the gateway; `agentsec replay` supports offline security replay (see the [guide](docs/replay-incidents.md)). See the [contract reference](docs/security-contract.md),
[scenario format](docs/scenario-format.md), [evidence model](docs/evidence-model.md),
[threat model](docs/threat-model.md), and
[implementation report](docs/reports/phase-0-implementation-report.md).

## Protect MCP tools

```bash
agentsec protect mcp --contract examples/mcp/contract.yaml --config examples/mcp/gateway.yaml --check
agentsec protect mcp --contract examples/mcp/contract.yaml --config examples/mcp/gateway.yaml --evidence-out /tmp/agentsec-runtime-new.jsonl
```

Configure the second command as your MCP host's server command. The synthetic tools have no
external effects. Email simulation requires approval through a separate controlling terminal;
file-write simulation is denied. Evidence paths must be new. Install the optional `mcp` extra
for runtime use; validation/evaluation work without it. Full development checks require
`dev`, `mcp` and `identity`. See [runtime setup and coverage](docs/runtime-mcp.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Unified contract workflow

```bash
agentsec contract compile examples/mcp/contract.yaml
agentsec contract test examples/mcp/contract.yaml
agentsec contract coverage examples/mcp/contract.yaml --run
agentsec contract diff examples/mcp/contract.yaml examples/mcp/contract.yaml --format json
```

These commands run locally without tool dispatch, models or credentials. Coverage keeps
unsupported intent, adapter proof and generated/executed tests separate. Synthetic conformance
is not a prompt-injection robustness claim. See [the guide](docs/contract-conformance.md).


Phase 4 adds [tracked provenance and data-flow restrictions](docs/provenance-data-flow.md),
including labeled tool-output → external-sink and untrusted-output → memory-tool protection.
Use `examples/mcp/flow-contract.yaml` with `examples/mcp/flow-gateway.yaml` and the existing
synthetic server. This tracks released tool outputs conservatively; it does not classify arbitrary
user/model text or provide complete DLP. The Phase 4 review fixes are included in the baseline. Phase 5 review fixes are included; Phase 6 review fixes are included.

## Incident replay and regression

```bash
agentsec replay run --bundle examples/replay/bundle.json
agentsec regression validate --root examples/regressions
agentsec regression run --root examples/regressions
```

Replay uses structured source evidence and deterministic substitutes without calling live tools.
The public regression corpus reports two ACTIVE passes and one DRAFT requiring review. See
[the workflow and fidelity limits](docs/replay-incidents.md) and
[the Phase 5 implementation report](docs/reports/phase-5-implementation-report.md).

## Identity and delegation

Phase 6 adds protected static identity and optional pinned signed-JWT verification, direct
OBO delegation, intersected credential/task/resource ceilings, and authority-bound approvals
and replay. Identity never grants beyond the contract.

```bash
python -m pip install -e '.[dev,mcp,identity]'
.venv/bin/python examples/identity/least_privilege.py
```

See [identity setup, trust boundaries and limitations](docs/identity-delegation.md). Historical
Phase 5 source can replay under its historical plan; comparison to a new Phase 6 candidate
without recorded authority facts is explicitly INCOMPLETE. Phase 6 review fixes are included; Phase 7 is ready for independent
review. Phase 8 trust admission is now implemented and awaiting independent review.

## Phase 7 adapters and isolation

Run `.venv/bin/python examples/adapters/local_tools.py` for native/provider/process dispatch.
Install `.[langchain]` for the async StructuredTool integration. LangChain callbacks and
LangSmith/other tracing run outside the AgentSec gateway and can observe raw inputs before a later
DENY; apply a separate egress policy. HTTPS actions require protected `tls_ca_pem` configuration.
Fixed-endpoint HTTP and explicit Docker/gVisor composition use the same runtime policy, approval
and evidence boundary. See [adapters and isolation](docs/adapters-isolation.md) for APIs and trust
assumptions.

## Supply-chain trust

```bash
.venv/bin/agentsec trust verify examples/trust/native-inventory.json --lock examples/trust/native-lock.json
.venv/bin/python examples/trust/pinned_native.py
```

Opt into MCP admission with `agentsec protect mcp ... --trust-lock reviewed-lock.json`.
Inventory inspection/scanning/diffs are offline; locks remain protected operator inputs. Signatures
use pinned Ed25519 public keys with the optional `trust` extra. Metadata pins, inspected file bytes
and publisher signatures do not prove loaded or remote running code. See the
[observe/review/pin/protect workflow and precise limits](docs/supply-chain-trust.md).
