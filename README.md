# Agent Safety & Security

A local-first security lifecycle for tool-using AI agents: define explicit authority, test it adversarially, enforce it at runtime, and turn observed failures into regressions.

> **Current status:** Phase 3 unified contract compilation is implemented and awaiting independent review. Native runtime authorization, generated conformance, semantic coverage and policy diff share compiled intent. Phase 2 review fixes remain protected. See the [conformance guide](docs/contract-conformance.md) and [Phase 3 report](docs/reports/phase-3-implementation-report.md).

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
[evaluation guide](docs/evaluation.md). `agentsec protect mcp` runs the gateway; `replay` remains a future phase. See the [contract reference](docs/security-contract.md),
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
for runtime use; validation/evaluation work without it. Full development checks require both
`dev` and `mcp`. See [runtime setup and coverage](docs/runtime-mcp.md).

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
