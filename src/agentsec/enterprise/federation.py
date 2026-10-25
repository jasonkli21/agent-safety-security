"""Verify pinned source candidates locally without importing or activating authority."""

from datetime import datetime

from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import Assessment
from agentsec.control_plane.policies import assess
from agentsec.control_plane.service import checked_model
from agentsec.enterprise.models import FederatedPolicyBundle, Pin, TrustConfig
from agentsec.enterprise.signatures import verify


def verify_bundle(
    bundle: FederatedPolicyBundle, trust: TrustConfig, now: datetime
) -> tuple[Pin, Assessment]:
    bundle = checked_model(FederatedPolicyBundle, bundle)
    payload = bundle.payload
    pin = verify(payload, bundle.signature, trust, now)
    assessment = assess(payload.source, None)
    if assessment.unsupported or assessment.conformance == "FAIL":
        raise TeamError("POLICY_BLOCKED")
    if (
        assessment.document_hash,
        assessment.effective_policy_hash,
        assessment.compiled_plan_digest,
    ) != (payload.document_hash, payload.effective_policy_hash, payload.compiled_plan_digest):
        raise TeamError("POLICY_BLOCKED")
    return pin, assessment
