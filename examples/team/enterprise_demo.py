"""Credential-free two-org enterprise reference. All keys are public synthetic fixtures."""

import runpy
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fixture import CONFIG, NOW, setup, token

from agentsec.control_plane.auth import TeamVerifier
from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import Agent, RevisionInput, Transition
from agentsec.enterprise.exports import sign_export, verify_export, write_export
from agentsec.enterprise.files import backup_database
from agentsec.enterprise.models import (
    CaseInput,
    CaseTransition,
    ExportCursor,
    FederatedPolicyBundle,
    FederationPayload,
    ImportRequest,
    Pin,
    RiskInput,
    RiskTransition,
    SimulationInput,
    TrustConfig,
)
from agentsec.enterprise.service import EnterpriseService
from agentsec.enterprise.signatures import sign


def main() -> None:
    with TemporaryDirectory(prefix="agentsec-enterprise-") as directory:
        root = Path(directory)
        team = setup(root / "team.db")

        def actor(name: str):
            return TeamVerifier(CONFIG).verify(token(name), NOW)

        source = Path("examples/mcp/contract.yaml").read_text().replace("local-user", "other")
        key = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
        private = root / "synthetic-offline-key.pem"
        private.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private.chmod(0o600)
        public = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

        def publish(org: str, revision: str, editor: str, reviewer: str, owner: str) -> None:
            for who, transition in (
                (editor, Transition(action="submit", expected_version=1)),
                (
                    reviewer,
                    Transition(
                        action="approve",
                        expected_version=2,
                        acknowledge_initial=True,
                        acknowledge_expansion=True,
                        acknowledge_gaps=True,
                        review_reason="INITIAL_POLICY",
                    ),
                ),
                (owner, Transition(action="publish", expected_version=3)),
            ):
                team.transition(actor(who), org, revision, transition)

        team.create_revision(
            actor("beta-editor"),
            "beta",
            RevisionInput(
                revision_id="baseline",
                policy_key="policy",
                source=source,
                upload_source=True,
                base_generation=0,
            ),
        )
        publish("beta", "baseline", "beta-editor", "beta-reviewer", "other")
        baseline = team.revision(actor("other"), "beta", "baseline")
        revision = team.create_revision(
            actor("editor"),
            "alpha",
            RevisionInput(
                revision_id="origin",
                policy_key="policy",
                source=source.replace("max_tool_calls: 3", "max_tool_calls: 2"),
                upload_source=True,
                base_generation=0,
            ),
        )
        payload = FederationPayload(
            origin="alpha",
            target="beta",
            policy_key="policy",
            local_policy_key="policy",
            revision_id="origin",
            key_id="peer",
            sequence=1,
            issued_at=NOW,
            expires_at=NOW + timedelta(days=1),
            source=team.source(actor("owner"), "alpha", "origin"),
            document_hash=revision.assessment.document_hash,
            effective_policy_hash=revision.assessment.effective_policy_hash,
            compiled_plan_digest=revision.assessment.compiled_plan_digest,
        )
        pin = Pin(
            origin="alpha",
            target="beta",
            policy_key="policy",
            local_policy_key="policy",
            key_id="peer",
            purpose="federation",
            public_key_pem=public,
            not_before=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=30),
        )
        service = EnterpriseService(team, TrustConfig(pins=(pin,)))
        bundle = FederatedPolicyBundle(payload=payload, signature=sign(payload, private))
        imported = service.import_bundle(
            actor("beta-editor"),
            "beta",
            ImportRequest(bundle=bundle, local_revision_id="candidate", base_generation=1),
        )
        assert imported.state == "DRAFT"
        try:
            service.import_bundle(
                actor("editor"),
                "alpha",
                ImportRequest(bundle=bundle, local_revision_id="bad", base_generation=0),
            )
            raise AssertionError("wrong destination accepted")
        except TeamError as exc:
            assert exc.code == "DENIED"
        tampered = bundle.model_copy(
            update={"payload": payload.model_copy(update={"source": "tampered"})}
        )
        try:
            service.import_bundle(
                actor("beta-editor"),
                "beta",
                ImportRequest(bundle=tampered, local_revision_id="tampered", base_generation=1),
            )
            raise AssertionError("tampered federation accepted")
        except TeamError as exc:
            assert exc.code == "SIGNATURE_INVALID"
        for name, revision_id, plan in (
            ("demo-agent", "baseline", baseline.assessment.compiled_plan_digest),
            ("unknown", None, None),
        ):
            applicable = name == "demo-agent"
            team.agent(
                actor("other"),
                "beta",
                Agent(
                    agent_id=name,
                    environment="local" if applicable else "test",
                    repository="repo",
                    owner_id="other",
                    policy_revision=revision_id,
                    expected_plan=plan,
                ),
            )
        result = service.simulate(
            actor("beta-editor"),
            "beta",
            SimulationInput(
                candidate="candidate", expected_generation=1, agents=("demo-agent", "unknown")
            ),
        )
        assert result.category == "RESTRICTIVE"
        assert [r.status for r in result.agents] == ["COMPARED", "UNKNOWN"]
        publish("beta", "candidate", "beta-editor", "beta-reviewer", "other")
        service.open_case(
            actor("beta-editor"),
            "beta",
            CaseInput(
                case_id="case",
                category="POLICY",
                severity="HIGH",
                assignee="beta-editor",
                agent_id="demo-agent",
            ),
        )
        service.transition_case(
            actor("beta-editor"),
            "beta",
            "case",
            CaseTransition(action="triage", expected_version=1),
        )
        service.request_risk(
            actor("beta-editor"),
            "beta",
            RiskInput(
                risk_id="risk",
                target_kind="case",
                target_id="case",
                target_version=2,
                reason="TIME_BOUND_REMEDIATION",
                expires_at=NOW + timedelta(hours=1),
            ),
        )
        before = team.posture(actor("other"), "beta")
        service.transition_risk(
            actor("other"), "beta", "risk", RiskTransition(action="approve", expected_version=1)
        )
        assert service.risk(actor("other"), "beta", "risk").disposition == "ACTIVE"
        assert team.posture(actor("other"), "beta") == before
        team.clock = lambda: NOW + timedelta(hours=1)
        assert service.risk(actor("other"), "beta", "risk").disposition == "EXPIRED"
        team.clock = lambda: NOW
        page = service.export_page(actor("other"), "beta", ExportCursor(org="beta"))
        data, signed = sign_export(page, "exporter", private, NOW)
        export_pin = Pin(
            origin="beta",
            target="beta",
            policy_key="siem",
            local_policy_key="siem",
            key_id="exporter",
            purpose="export",
            public_key_pem=public,
            not_before=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=30),
        )
        trust = TrustConfig(pins=(export_pin,))
        verify_export(data, signed, trust, NOW)
        write_export(root / "siem.jsonl", root / "manifest.json", data, signed)
        try:
            verify_export(data + b" ", signed, trust, NOW)
            raise AssertionError("tamper accepted")
        except TeamError as exc:
            assert exc.code == "SIGNATURE_INVALID"
        start = perf_counter()
        backup_database(root / "team.db", root / "backup.db")
        print(
            f"Synthetic consistent backup verified in {perf_counter() - start:.4f}s "
            "(not an RTO promise)"
        )
        team.store.close()
        print(
            "Signed federation -> independent DRAFT review; "
            "finite restriction + UNKNOWN; risk expires"
        )
        print(
            "Minimized SIEM signature verified; modified bytes rejected; "
            "reporter assurance unchanged"
        )
        print("Enterprise store closed; local protected runtime graph follows")
        runpy.run_path("examples/multi_agent/local_session.py", run_name="__main__")


if __name__ == "__main__":
    main()
