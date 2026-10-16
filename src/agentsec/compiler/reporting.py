"""Content-minimized, dimensioned conformance reports; no security percentage."""

from typing import Literal

from agentsec.compiler.models import CompiledSecurityPlan, SemanticAtom
from agentsec.compiler.probes import PolicyProbe, generate_probes
from agentsec.domain.base import VersionedModel
from agentsec.domain.taxonomy import PolicyOutcome
from agentsec.policy.native import NativePolicyEngine
from agentsec.policy.ports import PolicyEngine

Status = Literal["PASS", "FAIL", "ERROR", "NOT_RUN"]


class ProbeResult(VersionedModel):
    probe_id: str
    status: Status
    expected: PolicyOutcome
    actual: PolicyOutcome | None = None


class ConformanceReport(VersionedModel):
    label: Literal["contract conformance"] = "contract conformance"
    effective_policy_hash: str
    probes: tuple[ProbeResult, ...]
    eval_cases: tuple[ProbeResult, ...] = ()


def run_probe(plan: CompiledSecurityPlan, probe: PolicyProbe, engine: PolicyEngine) -> ProbeResult:
    try:
        decision = engine.decide(probe.request(plan), plan)
        valid = (
            decision.outcome == probe.expected
            and probe.reason in decision.reason_codes
            and decision.request_id == probe.probe_id
            and decision.contract_id == plan.contract_id
            and decision.effective_policy_hash == plan.effective_policy_hash
        )
        return ProbeResult(
            schema_version="0.1",
            probe_id=probe.probe_id,
            status="PASS" if valid else "FAIL",
            expected=probe.expected,
            actual=decision.outcome,
        )
    except Exception:
        return ProbeResult(
            schema_version="0.1", probe_id=probe.probe_id, status="ERROR", expected=probe.expected
        )


def run_conformance(
    plan: CompiledSecurityPlan, engine: PolicyEngine | None = None
) -> ConformanceReport:
    return ConformanceReport(
        schema_version="0.1",
        effective_policy_hash=plan.effective_policy_hash,
        probes=tuple(
            run_probe(plan, p, engine or NativePolicyEngine()) for p in generate_probes(plan)
        ),
    )


class AtomCoverage(SemanticAtom):
    adapter_status: Literal["NOT_REQUIRED", "UNPROVEN", "COVERED", "UNCOVERED"]
    probe_ids: tuple[str, ...]
    eval_case_ids: tuple[str, ...]
    probe_status: Status
    eval_status: Status


class CoverageReport(VersionedModel):
    effective_policy_hash: str
    atoms: tuple[AtomCoverage, ...]


def _status(ids: tuple[str, ...], results: tuple[ProbeResult, ...]) -> Status:
    states = {r.probe_id: r.status for r in results}
    relevant = [states.get(i, "NOT_RUN") for i in ids]
    for state in ("ERROR", "FAIL", "NOT_RUN"):
        if state in relevant:
            return state
    return "PASS" if relevant else "NOT_RUN"


def coverage_report(
    plan: CompiledSecurityPlan,
    results: ConformanceReport | None = None,
    adapter_proof: dict[str, bool] | None = None,
) -> CoverageReport:
    if results is not None and results.effective_policy_hash != plan.effective_policy_hash:
        raise ValueError("STALE_CONFORMANCE_REPORT")
    probes = generate_probes(plan)
    rows = []
    for atom in plan.atoms:
        ids = tuple(p.probe_id for p in probes if atom.atom_id in p.atom_ids)
        proof = (adapter_proof or {}).get(atom.atom_id)
        rows.append(
            AtomCoverage(
                **atom.model_dump(),
                adapter_status=(
                    "NOT_REQUIRED"
                    if not atom.adapter_required
                    else "UNPROVEN"
                    if proof is None
                    else "COVERED"
                    if proof
                    else "UNCOVERED"
                ),
                probe_ids=ids,
                eval_case_ids=ids,
                probe_status=_status(ids, results.probes if results else ()),
                eval_status=_status(ids, results.eval_cases if results else ()),
            )
        )
    return CoverageReport(
        schema_version="0.1", effective_policy_hash=plan.effective_policy_hash, atoms=tuple(rows)
    )
