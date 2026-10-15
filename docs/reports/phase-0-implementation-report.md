# Phase 0 Implementation Report

## Summary

Phase 0 is implemented as a local Python 3.12+ library and CLI, version 0.1.0, with artifact
schema version `0.1`. It establishes one security domain for future evaluation and enforcement.
There is no runtime protection, eval execution, model client, network service or persistence
implementation. Implementation and verification performed on 2026-10-15.

## Commit / branch

The supplied workspace has no `.git` directory or Git history (`git status --short` reported
“not a git repository”). Changes are files in the supplied workspace; no commit, branch, remote,
PR or push was created. No pre-existing implementation was replaced beyond scaffold code.

## Implemented deliverables

- Stable identity, policy, approval, data, trust, effect, event, reason and severity taxonomies.
- PrincipalRef, AgentIdentity, TaskScope, Delegation; ToolDescriptor and capability identifiers;
  DataOrigin and DataArtifactRef; PolicyRequest/Decision; exact-action approval models; typed
  events; deterministic scenario/security/utility assertions; Finding.
- Contract v0.1, bounded strict JSON/YAML ingestion, structured issues, semantic validation,
  canonical serialization, document identity and effective policy identity.
- Synchronous PolicyEngine and EventSink protocols, with no production implementations.
- Twelve generated JSON Schemas, schema regeneration tests, three public contracts and three
  public scenarios; 19 invalid contract/parser fixtures, 10 invalid scenarios, two valid event
  streams and three invalid event fixtures; four canonical golden forms.
- Local CLI, package metadata and type marker, source-distribution manifest, CI validation,
  negative/unit/round-trip/golden/property tests, network-disabled test fixture, and focused docs.

## Repository structure

```text
src/agentsec/
  version.py, py.typed
  domain/       base, taxonomy, identity, tools, provenance, policy, approvals,
                events, scenarios, findings, serialization
  contracts/    models, errors, validation, loader, canonical, schema_export
  policy/       ports
  evidence/     ports
  cli/          main
examples/       contracts/{research,support,coding}.yaml
                scenarios/{indirect-injection,canary-exfiltration,resource-exhaustion}.yaml
schemas/generated/   twelve generated schemas
tests/          unit/, fixtures/{contracts,scenarios,events}/, golden/, conftest.py
docs/           architecture, threat-model, evidence-model, security-contract,
                scenario-format, taxonomy, plans/, reports/
```

## Domain model decisions

Pydantic v2 remains the source of schema authority; PyYAML, Typer, Ruff and mypy retain the
scaffold choices. `jsonschema` is the only new runtime dependency: its Draft 2020-12 metaschema
validation rejects malformed tool schemas and enables independent schema checks. Type stubs
are development-only. Standard-library SHA-256/JSON provides canonical identities. Build
metadata uses SPDX licensing supported by setuptools >=77. No agent framework dependency.

Identifiers are bounded ASCII strings, case-sensitive, never stripped. Capabilities are
lowercase dotted components; there is no wildcard/global registry. Models forbid extras and
coercive scalar parsing. Attribute assignment is frozen; tuples/frozensets represent modeled
sequences/sets. JSON-valued fields and resource maps are not deeply immutable; trusted callers
must protect and revalidate them. Direct Python construction expects typed enums/collections;
`validate_data` and loaders use strict JSON wire semantics consistently.

All independently serialized security artifacts, including NormalizedAction, require explicit
string schema version `0.1`. Nested reference/section models inherit their containing version.
Aware timestamps normalize to UTC for canonical JSON; expiry must strictly follow issue/creation.
TaskScope is requested scope only. Unspecified/null and empty requested capability/resource
sets remain distinct. Delegation authority, subset constraints and freshness are not enforced.

Severity is an ordered IntEnum (INFO=0 through CRITICAL=4), serialized as an integer. Other
taxonomies serialize as uppercase strings. Generated schemas and taxonomy docs expose this choice.

## Contract v0.1 decisions

The plan's recommended section layout is implemented with typed principal references and a
shared TaskScope/AgentIdentity rather than shorthand strings. Rules use stable IDs, capability,
uppercase decision, and optional opaque exact resource string. Data rules represent explicit
allowed/denied destination categories and capabilities per label. No argument predicate language.
Budget counts are strict nonnegative integers; finite nonnegative cost accepts JSON numbers;
approval timeout is a positive integer. Zero budgets are valid. Agent/contract environment must
agree. Unknowns, duplicate rule IDs (across tool/data sections), duplicate exact selectors,
repeated data labels, data allow/deny overlap and duplicate invariant IDs are rejected.
Rule/invariant ordering is normalized during validation. External principal references are not
resolved because there is no contained registry. Schema/field reference is in `docs/security-contract.md`.

## Scenario v0.1 decisions

Static setup uses the same ToolDescriptor and DataArtifactRef as the domain. Tasks may contain
raw synthetic user text; policy requests do not require prompts. Injections require exactly one
content/fixture reference. No fixture is executed or fetched. Tool/artifact/canary IDs are unique;
assertion tool/canary, mock tool, and initial-memory references are checked locally.

Nine security assertion types and two utility types form closed discriminated unions. Security
and utility results are separate. Unknown assertion types and malformed operands fail. Assertion
executors, scoring, missing-evidence and non-vacuous approval assertion behavior belong to Phase 1.
The format and public examples are described in `docs/scenario-format.md`.

## Event/evidence model decisions

SecurityEvent uses a typed payload union discriminated by `kind`, checked against envelope
EventType. The exported schema also encodes this equality. All eleven planned event types,
including EFFECT_VERIFIED, are represented. Request, decision, approval, dispatch, return and
verified-effect claims remain distinct. Exact-action digests appear at request and dispatch.
Metadata/artifact/hash references avoid requiring raw sensitive content.

Sequence validation checks globally unique event IDs within the supplied stream, strictly
increasing sequence per run, and stable run/trace association. Interleaving and gaps are valid.
It does not establish causal correctness, lifecycle completeness, trustworthy producers,
authorization validity or real effects. EventSink is synchronous; there is no storage adapter.
See `docs/evidence-model.md` for each payload's evidentiary meaning and limitations.

## Validation and canonicalization

The loader reads at most 1 MiB UTF-8, permits at most 64 nesting levels, and rejects unsafe YAML
tags/aliases/anchors/merges, multiple documents, duplicate keys, non-string map keys, non-finite
numbers, unsupported suffixes, malformed values and unknown fields/versions. Boolean/number
resolution uses JSON spelling instead of YAML's surprising yes/off/leading-zero coercions.
Structured ArtifactValidationError carries JSON-ready issues, codes, paths and severity;
semantic checks run after schema validation, including direct model construction.

Canonical JSON sorts maps/sets and contract rule/invariant collections, retains generic array
order, emits defaults/nulls consistently and normalizes timestamps. It is a project format,
not RFC 8785; Unicode normalization and numeric equivalence of arbitrary JSON arguments are
not promised. Golden fixtures guard intentional changes.

`document_hash` covers the full normalized authored contract. `effective_policy_hash` uses an
explicit security projection excluding contract metadata, agent display/framework/model context,
and task description. Principal/owner/trust binding, task scopes, rule IDs/decisions/resources,
data policy, budgets, approvals, environment and invariant declarations remain included.
Invariant prose is conservatively security-relevant. Both hashes ignore map/set/rule order;
cosmetic contract description changes only document identity. Budget/rule/principal/data changes
alter effective policy identity. No ambiguous generic contract identity API is exposed.

Approval action digests bind version, principal, agent, environment, task/delegation, tool,
capability, resource, **complete arguments**, tool schema/description hashes, and policy hash.
Redacted summaries are never used as the canonical action. Reordering map keys preserves the
digest; changing any bound field or array order changes it. No cryptographic signature,
approver authentication, replay protection, expiry-at-dispatch or redemption is implemented.

## CLI commands

```bash
agentsec version
agentsec contract validate examples/contracts/research.yaml
agentsec scenario validate examples/scenarios/indirect-injection.yaml
agentsec schema export --out schemas/generated
agentsec examples validate
```

Contract success prints VALID, ID, schema version, document_hash and effective_policy_hash.
Errors print structured codes/paths without a traceback and exit 1; Typer usage errors exit 2.
Examples default to checkout `./examples`; `--root` supports another path and rejects an empty
corpus/duplicate IDs. There are no eval/protect/replay placeholders.

## Tests and results

Verification uses Python 3.12.13 on macOS arm64. Installed versions: Pydantic 2.14.1, PyYAML 6.0.3,
jsonschema 4.26.0, Typer 0.27.3, pytest 9.1.1, Hypothesis 6.169.4, Ruff 0.17.1, mypy 2.4.0,
setuptools 84.0.0. Commands are run from the repository root; `.venv/bin/` is explicit below.

| Exact command | Result |
| --- | --- |
| `.venv/bin/ruff check .` | PASS |
| `.venv/bin/ruff format --check .` | PASS |
| `.venv/bin/mypy src` | PASS, 27 source files, strict mode |
| `.venv/bin/pytest -q` | PASS, 250 tests |
| `.venv/bin/pytest --cov=agentsec --cov-report=term-missing -q` | PASS, 250 tests, 99% line coverage |
| `.venv/bin/agentsec version` | PASS, 0.1.0 |
| `.venv/bin/agentsec contract validate examples/contracts/research.yaml` | PASS, both SHA-256 identities printed |
| `.venv/bin/agentsec scenario validate examples/scenarios/indirect-injection.yaml` | PASS |
| `.venv/bin/agentsec examples validate` | PASS, 3 contracts and 3 scenarios |
| `.venv/bin/agentsec schema export --out schemas/generated` | PASS, 12 schemas; pytest compares regeneration byte-for-byte |
| `.venv/bin/python -m build --no-isolation` | PASS, sdist and wheel; archive contents and independent installation verified |

All core tests run without credentials; socket connections are blocked in the default suite.
Property tests target map/set ordering, rather than superficial randomized coverage. Negative
tests cover each custom domain validator, malformed config, discriminator and sequence errors,
strict bool/number/enum/timestamp handling, parser safety, schema freshness and CLI exit codes.
Golden forms cover a contract, descriptor, request event and scenario. Independent jsonschema
checks validate examples/events and reject event/payload mismatches.

Initial tests caught inconsistent model rule ordering after canonical round trips; sorting on
validation fixed it. An initial deep-JSON test expected the wrong error code; parser depth errors
are now consistently represented. Initial lint/type failures were corrected. Dependency install
needed network access because the sandbox could not resolve PyPI. A first no-isolation build
failed because uv's minimal venv lacked setuptools; installing cached setuptools fixed it.
An optional offline universal lock attempt lacked cross-platform cached metadata; no lockfile is
claimed. None of these remain a blocker. Build uses `--no-isolation` to reuse the verified local
backend without a network fetch. CI retains standard isolated `python -m build`.

Distribution verification additionally checked that the sdist contains the implementation
report, examples, generated schemas, tests and golden/invalid fixtures, and that the wheel
contains the domain modules and `py.typed`. The wheel was installed with dependencies into
an independent environment outside the checkout:

```bash
UV_CACHE_DIR=/private/tmp/agentsec-uv-cache uv venv --python 3.12 /private/tmp/agentsec-phase0-wheel-smoke
UV_CACHE_DIR=/private/tmp/agentsec-uv-cache uv pip install --python /private/tmp/agentsec-phase0-wheel-smoke/bin/python dist/agent_safety_security-0.1.0-py3-none-any.whl --offline
```

From `/private/tmp`, these installed entry-point commands passed:

```bash
/private/tmp/agentsec-phase0-wheel-smoke/bin/agentsec version
/private/tmp/agentsec-phase0-wheel-smoke/bin/agentsec contract validate /Users/jasonkli/projects/agent-safety-security/examples/contracts/research.yaml
/private/tmp/agentsec-phase0-wheel-smoke/bin/agentsec examples validate --root /Users/jasonkli/projects/agent-safety-security/examples
```

A final parser review also restricted the merge-key prohibition to mapping keys, preserving
innocent `"<<"` text in scenario/content values; a regression test covers this distinction.

## Deviations from plan

- **Intentional refinement:** principal references are typed objects; wire enum values are
  uppercase (Severity is ordered numeric), not the lowercase illustrative YAML in the plan.
  This prevents duplicate vocabularies and is reflected in examples/schemas/docs.
- **Intentional refinement:** a versioned NormalizedAction explicitly binds complete arguments,
  metadata and policy hashes; a redacted PolicyRequest summary is insufficient for approval.
- **Intentional refinement:** rules/invariants are normalized on input so canonical round trips
  preserve model equality. Set semantics do not accidentally become array precedence.
- **Intentional narrowing:** Incident, ReplayBundle and ContractCompiler types mentioned by the
  long-term architecture are deferred per the narrower Phase 0 plan and prompt. Only the two
  required ports exist. Architecture reconciliation records this ambiguity.
- **Optional items omitted:** no JSONL writer, SQLite, pre-commit, provider, policy backend,
  executable argument constraints, dynamic plugin system or speculative directories.
- **Tooling refinement:** jsonschema and type stubs provide concrete schema validation benefit;
  source manifests/type marker support distributable artifacts. No tooling replacement.

## Security assumptions

Policy/configuration and evidence producers/storage must remain in trusted control. User/model/
retrieved/tool text never becomes authorization just by existing. Declared identities, trust
labels and evidence remain claims until authenticated/verified by future trusted boundaries.
Hashes detect content changes and are not signatures. Callers must not treat frozen Pydantic
objects as deep immutable or expose nested mutable JSON/configuration to untrusted code.
Only synthetic/canary content is used. See `docs/threat-model.md` for all threat categories.

## Known limitations

No Phase 0 component secures a running agent. Resource strings/destination categories are
opaque; overlap checks cover exact selectors only. References outside scenario-local setup are
not fetched/resolved. Evidence sequence validity is not a proof of authorization, dispatch,
completion, or effect. Approvals are representations without authentication/freshness/redemption.
Provenance is reference metadata without propagation. JSON Schema cannot express all Python
cross-field semantics; applications must call the shared validator. Dependency ranges are not a
reproducible lock; schema regeneration checks intentionally detect output drift after upgrades.

## Open questions

Phase 1 must define assertion missing-evidence behavior, output/sink observation coverage,
non-vacuous approval assertions, and trajectory-level causal checks. Later phases must define
resource matching, destination taxonomy, delegation subset enforcement, signed/trusted identities,
protected storage, approval freshness/reuse prevention, and a production policy backend. Any
new contract field requires explicit hash-projection review. Deep immutability may become useful
at an untrusted extension boundary; none is provided in Phase 0.

## Recommended Phase 1 changes

Build only the local deterministic evaluation runner, fixture execution, canonical event capture,
assertion executors and finding/report generation next. Reuse these domain types; do not create
parallel runtime/eval schemas. Add causal evidence validation and explicit incomplete-evidence
outcomes before claiming a scenario pass. Preserve paired security/utility measurement.

## Definition of Done and Phase 1 readiness assessment

The plan's Domain, Contracts, CLI, Fixtures, Documentation and Quality sections were inspected
against implemented files and tests. All required Phase 0 deliverables are present; no runtime,
provider, hosted, sandbox, or actual eval feature is exposed as complete.

| Readiness question | Evidence / assessment |
| --- | --- |
| Can example permissions be expressed naturally? | Research, support approval and scoped coding contracts validate without framework fields. PASS. |
| Can request/deny and approval/dispatch/return be distinguished? | Two event streams plus typed payload/discriminator tests. PASS. |
| Can malicious content be forbidden from causing email requests? | Indirect-injection scenario uses shared `email.send` with CAPABILITY_NOT_REQUESTED and TOOL_NOT_CALLED. PASS. |
| Can MCP and Python adapters share requests? | PolicyRequest/PolicyEngine contain only domain identities, capability/resource/JSON context; no adapter/provider classes. PASS. |
| Can findings reference exact evidence without raw secrets? | Finding event/artifact refs and metadata-only events tested. PASS. |
| Do eval and runtime share capability/tool vocabulary? | ToolDescriptor, CapabilityId, PolicyRequest/Decision and EventSink are shared domain models. PASS. |

Phase 1 is ready to begin within these limits. This is readiness of representations, not evidence
of runtime protection or successful adversarial evaluation. There is no implementation blocker.
