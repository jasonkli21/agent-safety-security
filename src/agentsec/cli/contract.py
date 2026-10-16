"""Compact inspection and offline verification commands."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from pydantic import BaseModel

from agentsec.compiler import compile_contract
from agentsec.compiler.diff import SemanticDiff, semantic_diff
from agentsec.compiler.models import CompiledSecurityPlan
from agentsec.compiler.reporting import ConformanceReport, CoverageReport, coverage_report
from agentsec.contracts.loader import load_contract
from agentsec.domain.serialization import canonical_json
from agentsec.eval.contract_cases import test_contract


class Format(StrEnum):
    TEXT = "text"
    JSON = "json"


def display(report: BaseModel, format: Format) -> None:
    if format == Format.JSON:
        typer.echo(canonical_json(report))
        return
    if isinstance(report, CompiledSecurityPlan):
        typer.echo(f"Compiled contract: {report.contract_id} ({report.compiler_version})")
        typer.echo(f"effective_policy_hash: {report.effective_policy_hash}")
        for rule in report.rules:
            typer.echo(
                f"{rule.rule_id}: {rule.capability} {rule.decision.value} "
                f"resource={canonical_json(rule.resource)}"
            )
        for data_rule in report.data_rules:
            typer.echo(
                f"{data_rule.rule_id}: data label={data_rule.label.value} "
                f"{canonical_json(data_rule)}"
            )
        typer.echo(f"Runtime budgets: {canonical_json(report.budgets)}")
        typer.echo(f"Approval timeout: {report.approvals.default_timeout_seconds}s")
        typer.echo(f"Unsupported intent: {', '.join(report.gaps) or 'none configured'}")
    elif isinstance(report, ConformanceReport):
        typer.echo("Contract conformance (synthetic policy/evidence checks)")
        typer.echo(f"effective_policy_hash: {report.effective_policy_hash}")
        for label, rows in (("probe", report.probes), ("eval", report.eval_cases)):
            for row in rows:
                actual = row.actual.value if row.actual else "unavailable"
                typer.echo(
                    f"{label} {row.probe_id} ({row.obligation_kind}): {row.status} "
                    f"expected={row.expected.value} actual={actual}"
                )
    elif isinstance(report, CoverageReport):
        typer.echo(f"Semantic coverage: {report.effective_policy_hash}")
        for atom in report.atoms:
            typer.echo(
                f"{atom.source_ref}: compiled={atom.compiled} "
                f"runtime_supported={atom.runtime_supported} "
                f"adapter={atom.adapter_status} "
                f"source={atom.source_classification_status} "
                f"sink={atom.sink_classification_status} "
                f"probes={len(atom.probe_ids)}/{atom.probe_status} "
                f"eval_cases={len(atom.eval_case_ids)}/{atom.eval_status}"
            )
    elif isinstance(report, SemanticDiff):
        typer.echo(report.comparison)
        typer.echo(f"Old: {report.old_effective_policy_hash}")
        typer.echo(f"New: {report.new_effective_policy_hash}")
        typer.echo(f"Representatives compared: {report.representatives}")
        for change in report.changes:
            typer.echo(f"{change.kind}: {change.source_ref} {change.representative_digest or ''}")
        if not report.changes:
            typer.echo("No changes detected within the comparison boundary.")


def register_contract_commands(app: typer.Typer) -> None:
    # Lazy import avoids a main/command import cycle.
    from agentsec.cli.main import checked

    @app.command("compile")
    def compile_command(
        path: Path, format: Annotated[Format, typer.Option()] = Format.TEXT
    ) -> None:
        """Inspect executable intent and explicit gaps (contains authored policy values)."""
        checked(lambda: display(compile_contract(load_contract(path)), format))

    @app.command("test")
    def test_command(path: Path, format: Annotated[Format, typer.Option()] = Format.TEXT) -> None:
        """Run native probes and Phase 1 synthetic contract conformance cases."""

        def operation() -> None:
            report = test_contract(load_contract(path))
            display(report, format)
            statuses = {r.status for r in (*report.probes, *report.eval_cases)}
            if "ERROR" in statuses:
                raise typer.Exit(4)
            if "FAIL" in statuses:
                raise typer.Exit(1)

        checked(operation)

    @app.command("coverage")
    def coverage_command(
        path: Path,
        format: Annotated[Format, typer.Option()] = Format.TEXT,
        run: Annotated[bool, typer.Option()] = False,
    ) -> None:
        """Show separate semantic dimensions; adapter proof is UNPROVEN offline."""

        def operation() -> None:
            contract = load_contract(path)
            display(
                coverage_report(
                    compile_contract(contract), test_contract(contract) if run else None
                ),
                format,
            )

        checked(operation)

    @app.command("diff")
    def diff_command(
        old: Path, new: Path, format: Annotated[Format, typer.Option()] = Format.TEXT
    ) -> None:
        """Compare finite exact-match authority partitions without activating policy."""
        checked(
            lambda: display(
                semantic_diff(
                    compile_contract(load_contract(old)), compile_contract(load_contract(new))
                ),
                format,
            )
        )
