"""Explicit offline enterprise operations; keys never enter HTTP or SQLite."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import typer
from pydantic import BaseModel

from agentsec.cli.team import fail
from agentsec.contracts.loader import load_artifact, parse_document, validate_data
from agentsec.control_plane.auth import TeamVerifier
from agentsec.control_plane.models import TeamConfig
from agentsec.control_plane.service import TeamService
from agentsec.control_plane.store import Store
from agentsec.domain.serialization import canonical_json
from agentsec.enterprise.exports import sign_export, verify_export, write_export
from agentsec.enterprise.files import atomic_private_write, backup_database
from agentsec.enterprise.models import (
    CaseInput,
    CaseTransition,
    ExportCursor,
    FederatedPolicyBundle,
    FederationPayload,
    ImportRequest,
    RiskInput,
    RiskTransition,
    SignedExport,
    SimulationInput,
    TrustConfig,
)
from agentsec.enterprise.service import EnterpriseService
from agentsec.enterprise.signatures import private_bytes, sign
from agentsec.identity.ingress import read_credential

app = typer.Typer(no_args_is_help=True)


def trust_file(path: Path) -> TrustConfig:
    return validate_data(TrustConfig, parse_document(private_bytes(path).decode(), format="json"))


@app.command("request")
def request(
    db: Path,
    config: Path,
    token_file: Path,
    org: str,
    operation: Literal[
        "case-open",
        "case-transition",
        "risk-request",
        "risk-transition",
        "simulate",
        "federation-import",
        "case-read",
        "risk-read",
    ],
    request_file: Path | None = None,
    target: str = "",
    trust: Path | None = None,
) -> None:
    """Perform a strict authenticated workflow locally. Import requires a protected trust file."""
    store: Store | None = None
    try:
        team = TeamService(Store(db), load_artifact(config, TeamConfig))
        store = team.store
        actor = TeamVerifier(team.config).verify(read_credential(token_file), team.clock())
        service = EnterpriseService(team, trust_file(trust) if trust else TrustConfig())
        result: BaseModel
        if operation == "case-read":
            result = service.case(actor, org, target)
        elif operation == "risk-read":
            result = service.risk(actor, org, target)
        else:
            if request_file is None:
                raise ValueError
            if operation == "case-open":
                result = service.open_case(actor, org, load_artifact(request_file, CaseInput))
            elif operation == "case-transition":
                result = service.transition_case(
                    actor, org, target, load_artifact(request_file, CaseTransition)
                )
            elif operation == "risk-request":
                result = service.request_risk(actor, org, load_artifact(request_file, RiskInput))
            elif operation == "risk-transition":
                result = service.transition_risk(
                    actor, org, target, load_artifact(request_file, RiskTransition)
                )
            elif operation == "simulate":
                result = service.simulate(actor, org, load_artifact(request_file, SimulationInput))
            else:
                result = service.import_bundle(
                    actor, org, load_artifact(request_file, ImportRequest)
                )
        typer.echo(result.model_dump_json())
    except Exception as exc:
        fail(exc)
    finally:
        if store:
            store.close()


@app.command("federation-export")
def federation_export(
    db: Path,
    config: Path,
    token_file: Path,
    org: str,
    revision: str,
    target: str,
    local_policy: str,
    sequence: int,
    key_id: str,
    private_key: Path,
    output: Path,
) -> None:
    """Deliberately share policy SOURCE with explicit recipient and offline signing key."""
    store: Store | None = None
    try:
        team = TeamService(Store(db), load_artifact(config, TeamConfig))
        store = team.store
        actor = TeamVerifier(team.config).verify(read_credential(token_file), team.clock())
        with team.authorized(actor, org, "manage"):
            pass
        item = team.revision(actor, org, revision)
        source = team.source(actor, org, revision)
        now = team.clock()
        payload = FederationPayload(
            origin=org,
            target=target,
            policy_key=item.policy_key,
            local_policy_key=local_policy,
            revision_id=revision,
            key_id=key_id,
            sequence=sequence,
            issued_at=now,
            expires_at=now + timedelta(days=1),
            source=source,
            document_hash=item.assessment.document_hash,
            effective_policy_hash=item.assessment.effective_policy_hash,
            compiled_plan_digest=item.assessment.compiled_plan_digest,
        )
        bundle = FederatedPolicyBundle(payload=payload, signature=sign(payload, private_key))
        with team.authorized(actor, org, "manage"):
            pass
        atomic_private_write(output, (canonical_json(bundle) + "\n").encode())
        typer.echo("SIGNED_SOURCE_EXPORT")
    except Exception as exc:
        fail(exc)
    finally:
        if store:
            store.close()


@app.command("export-siem")
def export_siem(
    db: Path,
    config: Path,
    token_file: Path,
    org: str,
    key_id: str,
    private_key: Path,
    output: Path,
    manifest: Path,
    after: int = 0,
) -> None:
    """Write one bounded tenant-relative audit page and separate exact-byte signature."""
    store: Store | None = None
    try:
        team = TeamService(Store(db), load_artifact(config, TeamConfig))
        store = team.store
        actor = TeamVerifier(team.config).verify(read_credential(token_file), team.clock())
        page = EnterpriseService(team).export_page(actor, org, ExportCursor(org=org, after=after))
        data, signed = sign_export(page, key_id, private_key, team.clock())
        with team.authorized(actor, org, "manage"):
            pass
        write_export(output, manifest, data, signed)
        typer.echo(page.cursor.model_dump_json())
    except Exception as exc:
        fail(exc)
    finally:
        if store:
            store.close()


@app.command("verify-export")
def verify_export_command(data: Path, manifest: Path, trust: Path) -> None:
    """Verify exact bytes with independent local pin; does not attest reporter truth."""
    try:
        signed = validate_data(
            SignedExport, parse_document(private_bytes(manifest).decode(), format="json")
        )
        verify_export(private_bytes(data), signed, trust_file(trust), datetime.now(UTC))
        typer.echo("VERIFIED_EXPORT_ORIGIN; REPORTER_ASSURANCE_UNCHANGED")
    except Exception as exc:
        fail(exc)


@app.command("backup")
def backup(db: Path, output: Path) -> None:
    """Explicit consistent private backup. Stop the service before reference recovery drills."""
    try:
        backup_database(db, output)
        typer.echo("BACKUP_VERIFIED")
    except Exception as exc:
        fail(exc)


@app.command("verify-federation")
def verify_federation(bundle: Path, trust: Path) -> None:
    """Verify pinned signature and locally recomputed policy identities, without import."""
    try:
        from agentsec.enterprise.federation import verify_bundle

        value = validate_data(
            FederatedPolicyBundle, parse_document(private_bytes(bundle).decode(), format="json")
        )
        verify_bundle(value, trust_file(trust), datetime.now(UTC))
        typer.echo("VERIFIED_CANDIDATE; NO_RUNTIME_ACTIVATION")
    except Exception as exc:
        fail(exc)
