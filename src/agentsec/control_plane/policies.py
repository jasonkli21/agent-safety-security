"""Bounded canonical compilation and conservative governance comparison."""

from agentsec.compiler import compile_contract
from agentsec.compiler.diff import semantic_diff
from agentsec.compiler.reporting import coverage_report
from agentsec.contracts.canonical import document_hash
from agentsec.contracts.loader import parse_document, validate_data
from agentsec.contracts.models import AgentSecurityContract
from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import Assessment
from agentsec.eval.contract_cases import test_contract


def parse_source(source: str) -> AgentSecurityContract:
    if len(source.encode()) > 65536:
        raise TeamError("POLICY_BLOCKED")
    contract = validate_data(AgentSecurityContract, parse_document(source))
    # Bound finite partitions and generated conformance work before compilation.
    if len(contract.tools.rules) > 32 or len(contract.data.rules) > 8:
        raise TeamError("POLICY_BLOCKED")
    if (
        sum(
            len(getattr(rule, field))
            for rule in contract.data.rules
            for field in (
                "allowed_capabilities",
                "denied_capabilities",
                "allowed_destinations",
                "denied_destinations",
            )
        )
        > 64
    ):
        raise TeamError("POLICY_BLOCKED")
    value = contract.model_dump_json()
    if len(value) > 65536:
        raise TeamError("POLICY_BLOCKED")
    scope = contract.task_scope
    if (
        scope
        and scope.resource_scopes
        and (len(scope.resource_scopes) > 32 or sum(map(len, scope.resource_scopes.values())) > 64)
    ):
        raise TeamError("POLICY_BLOCKED")
    return contract


def assess(source: str, previous: str | None) -> Assessment:
    try:
        contract = parse_source(source)
        plan = compile_contract(contract)
        conformance = test_contract(contract)
        coverage = coverage_report(plan, conformance)
        kinds: tuple[str, ...] = ()
        diff = None
        unknown = False
        if previous is not None:
            old = compile_contract(parse_source(previous))
            diff = semantic_diff(old, plan)
            kinds = tuple(sorted({change.kind for change in diff.changes}))
            unknown = any(k in kinds for k in ("unsupported_change", "compiler_semantics_change"))
        statuses = {p.status for p in (*conformance.probes, *conformance.eval_cases)}
        return Assessment(
            semantic_diff=diff,
            conformance_report=conformance,
            coverage_report=coverage,
            document_hash=document_hash(contract),
            effective_policy_hash=plan.effective_policy_hash,
            compiled_plan_digest=plan.identity.compiled_plan_digest,
            initial=previous is None,
            expansions=bool(
                set(kinds)
                - {
                    "authority_reduction",
                    "policy_explanation_change",
                    "data_policy_tightening",
                    "data_policy_explanation_change",
                    "budget_tightening",
                    "task_scope_narrowing",
                }
            ),
            gaps=sum(
                not a.runtime_supported
                or a.adapter_status == "UNPROVEN"
                or a.probe_status != "PASS"
                or a.eval_status != "PASS"
                for a in coverage.atoms
            ),
            unsupported=len(plan.gaps),
            conformance="FAIL"
            if statuses & {"FAIL", "ERROR"}
            else "UNKNOWN"
            if not statuses or "NOT_RUN" in statuses
            else "PASS",
            diff_status="UNKNOWN" if unknown else "INITIAL" if previous is None else "COMPARED",
            change_kinds=kinds,
        )
    except TeamError:
        raise
    except Exception:
        raise TeamError("POLICY_BLOCKED") from None


def verify_fetch(source: str, expected: Assessment) -> None:
    """Verify immutable bytes locally without activation or runtime/config mutation."""
    actual = assess(source, None)
    if (
        actual.document_hash,
        actual.effective_policy_hash,
        actual.compiled_plan_digest,
        actual.compiler_version,
    ) != (
        expected.document_hash,
        expected.effective_policy_hash,
        expected.compiled_plan_digest,
        expected.compiler_version,
    ):
        raise TeamError("POLICY_BLOCKED")
