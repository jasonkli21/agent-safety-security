"""Deterministic two-tenant HTTP demo; no listener, external IdP or persistent secrets.

Run with .[dev,control-plane]. Fixed issuer is public test material, never production.
"""

import json
import runpy
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

from fixture import NOW, setup, token
from starlette.testclient import TestClient

from agentsec.compiler import compile_contract
from agentsec.compiler.reporting import coverage_report
from agentsec.contracts.loader import load_artifact, load_contract
from agentsec.control_plane.api import create_app
from agentsec.control_plane.metadata import project_ci
from agentsec.control_plane.models import Assessment
from agentsec.control_plane.policies import verify_fetch
from agentsec.domain.scenarios import Scenario
from agentsec.eval.contract_cases import test_contract
from agentsec.eval.fixtures import FixtureTarget, TargetFixture
from agentsec.eval.runner import evaluate
from agentsec.regression.runner import load_corpus, run_case


def main() -> None:
    with TemporaryDirectory() as directory:
        service = setup(Path(directory) / "team.db")
        client = TestClient(create_app(service))

        def request(who, resource, body=None, org="alpha", expected=200):
            headers = {"Authorization": "Bearer " + token(who)}
            path = f"/v1/orgs/{org}/{resource}"
            response = (
                client.get(path, headers=headers)
                if body is None
                else client.post(path, headers=headers, json=body)
            )
            assert response.status_code == expected, response.text
            return response.json()

        revision = request(
            "editor",
            "revisions",
            {
                "revision_id": "demo",
                "policy_key": "policy",
                "source": Path("examples/mcp/contract.yaml").read_text(),
                "upload_source": True,
                "base_generation": 0,
            },
        )
        for who, action, version in (
            ("editor", "submit", 1),
            ("reviewer", "approve", 2),
            ("owner", "publish", 3),
        ):
            request(
                who,
                "revisions/demo/transitions",
                {
                    "action": action,
                    "expected_version": version,
                    "acknowledge_initial": True,
                    "acknowledge_expansion": True,
                    "acknowledge_gaps": True,
                    "review_reason": "INITIAL_POLICY",
                },
            )
        source = request("viewer", "revisions/demo/source")["source"]
        verify_fetch(source, Assessment.model_validate_json(json.dumps(revision["assessment"])))
        request(
            "owner",
            "agents",
            {
                "agent_id": "demo",
                "environment": "test",
                "repository": "repo",
                "owner_id": "owner",
                "policy_revision": "demo",
                "expected_plan": revision["assessment"]["compiled_plan_digest"],
            },
        )
        request("owner", "reporters", {"identity_id": "ci", "agent_id": "demo", "source": "CI"})
        contract = load_contract(Path("examples/contracts/research.yaml"))
        evaluation = evaluate(
            contract=contract,
            scenario=load_artifact(Path("examples/scenarios/indirect-injection.yaml"), Scenario),
            target=FixtureTarget(
                load_artifact(
                    Path("examples/eval-fixtures/indirect-injection-safe.yaml"), TargetFixture
                )
            ),
        )
        conformance = test_contract(contract)
        metadata = project_ci(
            evaluations=(evaluation,),
            regressions=tuple(run_case(c) for c in load_corpus(Path("examples/regressions"))),
            conformance=conformance,
            coverage=coverage_report(compile_contract(contract), conformance),
            run_id=UUID(int=10),
            agent_id="demo",
            environment="test",
            repository="repo",
            start=NOW,
            end=NOW,
        )
        receipt = request("ci", "reports", metadata.model_dump(mode="json"))
        assert receipt["report"]["regression"] == "DRAFT"
        request("other", "posture", expected=403)
        assert request("both", "agents", org="beta")["items"] == []
        request(
            "owner",
            "reporters",
            {
                "identity_id": "ci",
                "agent_id": "demo",
                "source": "CI",
                "enabled": False,
                "expected_version": 1,
            },
        )
        request("ci", "reports", metadata.model_dump(mode="json"), expected=403)
        posture = request("viewer", "posture")
        print("team-v1: two tenants, independent review/publication; fetch without activation")
        print("scoped CI receipt: REPORTED_UNVERIFIED; DRAFT regression preserved")
        print("advisory posture:", posture["agents"][0]["status"], posture["agents"][0]["flags"])
        print(
            "policy/effect evidence:",
            posture["agents"][0]["policy_alignment"],
            posture["agents"][0]["effect_evidence"],
        )
        print("cross-tenant access and revoked reporter: DENIED")
        service.store.close()
        request("viewer", "posture", expected=503)
        print("team store outage: closed; local Phase 9 gateway/session follows")
        runpy.run_path("examples/multi_agent/local_session.py", run_name="__main__")


if __name__ == "__main__":
    main()
