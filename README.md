# Agent Safety & Security

A local-first security lifecycle for tool-using AI agents: define explicit authority, test it adversarially, enforce it at runtime, and turn observed failures into regressions.

> **Current status:** Phase 0 foundation implemented. Phase 0 defines the canonical security domain, schemas, validation, evidence model, and CLI foundations. It does **not** yet protect a production agent.

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

Read the repository in this order:

1. [`docs/prd.md`](docs/prd.md) — product vision, competitive positioning, and phased roadmap.
2. [`docs/architecture.md`](docs/architecture.md) — enduring system boundaries and architectural invariants.
3. [`docs/plans/phase-0-implementation-plan.md`](docs/plans/phase-0-implementation-plan.md) — current implementation scope and acceptance criteria.
4. [`AGENTS.md`](AGENTS.md) — rules for AI-assisted development in this repository.
5. [`docs/prompts/phase-0-sol-medium-implementation-prompt.md`](docs/prompts/phase-0-sol-medium-implementation-prompt.md) — handoff prompt for the initial implementation session.

## Phase 0 scope

Phase 0 should establish one shared language for:

- principals, agents, tasks, and delegation;
- tools and capabilities;
- security contracts;
- policy requests/decisions;
- approvals;
- data/provenance primitives;
- security events and findings;
- evaluation scenarios;
- strict validation, canonicalization, and schema export.

It should **not** implement the real evaluation engine, MCP gateway, production policy engine, provenance propagation, hosted service, or model-provider integrations.

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
python -m pip install -e ".[dev]"
agentsec version
agentsec contract validate examples/contracts/research.yaml
agentsec scenario validate examples/scenarios/indirect-injection.yaml
agentsec examples validate
agentsec schema export --out schemas/generated
ruff check .
ruff format --check .
mypy src
pytest
python -m build
```

Validation is local and requires no API keys. `examples validate` reads `./examples` by default;
use `--root /path/to/examples` outside this checkout. No `eval`, `protect`, or `replay` command
exists yet. See the [contract reference](docs/security-contract.md),
[scenario format](docs/scenario-format.md), [evidence model](docs/evidence-model.md),
[threat model](docs/threat-model.md), and
[implementation report](docs/reports/phase-0-implementation-report.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
