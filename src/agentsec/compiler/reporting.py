"""Content-minimized, dimensioned conformance reports; no security percentage."""

from typing import Literal

from agentsec.compiler.models import CompiledSecurityPlan, PlanIdentity, SemanticAtom
from agentsec.compiler.probes import PolicyProbe, generate_probes
from agentsec.domain.base import Digest, SecurityModel, VersionedModel
from agentsec.domain.taxonomy import PolicyOutcome
from agentsec.policy.native import NativePolicyEngine
from agentsec.policy.ports import PolicyEngine

Status = Literal["PASS", "FAIL", "ERROR", "NOT_RUN"]


class ProbeResult(VersionedModel):
    probe_id: str
    status: Status
    expected: PolicyOutcome
    actual: PolicyOutcome | None = None
    obligation_kind: str = "tool_policy"
    not_derivable_reason: str | None = None


class ConformanceReport(VersionedModel):
    label: Literal["contract conformance"] = "contract conformance"
    effective_policy_hash: str
    plan_identity: PlanIdentity
    probes: tuple[ProbeResult, ...]
    eval_cases: tuple[ProbeResult, ...] = ()


def run_probe(plan: CompiledSecurityPlan, probe: PolicyProbe, engine: PolicyEngine) -> ProbeResult:
    if not probe.derivable:
        return ProbeResult(
            schema_version="0.1",
            probe_id=probe.probe_id,
            status="NOT_RUN",
            expected=probe.expected,
            obligation_kind=probe.obligation_kind,
            not_derivable_reason="No base-permitted witness for this flow obligation",
        )
    try:
        decision = engine.decide(probe.request(plan), plan)
        valid = (
            decision.outcome == probe.expected
            and decision.reason_codes == frozenset({probe.reason})
            and decision.matched_rule_ids == probe.matched_rule_ids
            and decision.request_id == probe.probe_id
            and decision.contract_id == plan.contract_id
            and decision.effective_policy_hash == plan.effective_policy_hash
        )
        return ProbeResult(
            schema_version="0.1",
            probe_id=probe.probe_id,
            status="PASS" if valid else "FAIL",
            expected=probe.expected,
            obligation_kind=probe.obligation_kind,
            actual=decision.outcome,
        )
    except Exception:
        return ProbeResult(
            schema_version="0.1",
            probe_id=probe.probe_id,
            status="ERROR",
            expected=probe.expected,
            obligation_kind=probe.obligation_kind,
        )


def run_conformance(
    plan: CompiledSecurityPlan, engine: PolicyEngine | None = None
) -> ConformanceReport:
    return ConformanceReport(
        schema_version="0.1",
        effective_policy_hash=plan.effective_policy_hash,
        plan_identity=plan.identity,
        probes=tuple(
            run_probe(plan, p, engine or NativePolicyEngine()) for p in generate_probes(plan)
        ),
    )


class AtomCoverage(SemanticAtom):
    provenance_input_required: bool = False
    source_classification_required: bool = False
    sink_classification_required: bool = False
    adapter_boundary: str | None = None
    source_classification_status: Literal["NOT_REQUIRED", "UNPROVEN", "COVERED", "UNCOVERED"] = (
        "NOT_REQUIRED"
    )
    sink_classification_status: Literal["NOT_REQUIRED", "UNPROVEN", "COVERED", "UNCOVERED"] = (
        "NOT_REQUIRED"
    )
    adapter_status: Literal["NOT_REQUIRED", "UNPROVEN", "COVERED", "UNCOVERED"]
    probe_ids: tuple[str, ...]
    eval_case_ids: tuple[str, ...]
    probe_status: Status
    eval_status: Status


class CoverageReport(VersionedModel):
    effective_policy_hash: str
    plan_identity: PlanIdentity
    atoms: tuple[AtomCoverage, ...]


def _status(ids: tuple[str, ...], results: tuple[ProbeResult, ...]) -> Status:
    states = {r.probe_id: r.status for r in results}
    relevant = [states.get(i, "NOT_RUN") for i in ids]
    for state in ("ERROR", "FAIL", "NOT_RUN"):
        if state in relevant:
            return state
    return "PASS" if relevant else "NOT_RUN"


class AdapterAtomProof(SecurityModel):
    atom_id: str
    covered: bool
    source_classification_covered: bool | None = None
    sink_classification_covered: bool | None = None


class AdapterProof(VersionedModel):
    plan_identity: PlanIdentity
    discovery_snapshot_digest: Digest
    atoms: tuple[AdapterAtomProof, ...]


def coverage_report(
    plan: CompiledSecurityPlan,
    results: ConformanceReport | None = None,
    adapter_proof: AdapterProof | None = None,
    *,
    discovery_snapshot_digest: str | None = None,
) -> CoverageReport:
    if results is not None and (
        results.plan_identity != plan.identity
        or results.effective_policy_hash != plan.effective_policy_hash
    ):
        raise ValueError("STALE_CONFORMANCE_REPORT")
    if adapter_proof is not None and (
        adapter_proof.plan_identity != plan.identity
        or adapter_proof.discovery_snapshot_digest != discovery_snapshot_digest
    ):
        raise ValueError("STALE_ADAPTER_PROOF")
    proofs = {p.atom_id: p for p in adapter_proof.atoms} if adapter_proof else {}
    probes = generate_probes(plan)
    rows = []
    for atom in plan.atoms:
        ids = tuple(p.probe_id for p in probes if atom.atom_id in p.atom_ids)
        proof = proofs.get(atom.atom_id)
        data_rule = next(
            (r for r in plan.data_rules if atom.source_ref == f"data.rules/{r.rule_id}"), None
        )

        def classification_status(
            required: bool, covered: bool | None
        ) -> Literal["NOT_REQUIRED", "UNPROVEN", "COVERED", "UNCOVERED"]:
            return (
                "NOT_REQUIRED"
                if not required
                else "UNPROVEN"
                if covered is None
                else "COVERED"
                if covered
                else "UNCOVERED"
            )

        rows.append(
            AtomCoverage(
                **atom.model_dump(),
                provenance_input_required=atom.source_ref.startswith("data.rules/"),
                source_classification_required=any(
                    atom.source_ref == f"data.rules/{r.rule_id}"
                    and r.label.value not in {"TOOL_OUTPUT", "UNTRUSTED_CONTENT"}
                    for r in plan.data_rules
                ),
                sink_classification_required=any(
                    atom.source_ref == f"data.rules/{r.rule_id}"
                    and bool(r.allowed_destinations or r.denied_destinations)
                    for r in plan.data_rules
                ),
                adapter_boundary=(
                    "Tracked released tool outputs only; unobserved user/model text "
                    "and semantic content detection are not covered"
                    if atom.source_ref.startswith("data.rules/")
                    else None
                ),
                source_classification_status=classification_status(
                    data_rule is not None
                    and data_rule.label.value not in {"TOOL_OUTPUT", "UNTRUSTED_CONTENT"},
                    proof.source_classification_covered if proof else None,
                ),
                sink_classification_status=classification_status(
                    data_rule is not None
                    and bool(data_rule.allowed_destinations or data_rule.denied_destinations),
                    proof.sink_classification_covered if proof else None,
                ),
                adapter_status=(
                    "NOT_REQUIRED"
                    if not atom.adapter_required
                    else "UNPROVEN"
                    if proof is None
                    else "COVERED"
                    if proof.covered
                    else "UNCOVERED"
                ),
                probe_ids=ids,
                eval_case_ids=ids,
                probe_status=_status(ids, results.probes if results else ()),
                eval_status=_status(ids, results.eval_cases if results else ()),
            )
        )
    return CoverageReport(
        schema_version="0.1",
        effective_policy_hash=plan.effective_policy_hash,
        plan_identity=plan.identity,
        atoms=tuple(rows),
    )
