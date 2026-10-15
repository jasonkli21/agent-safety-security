"""Cross-field semantics shared by direct construction and file loading."""

from typing import TYPE_CHECKING

from agentsec.contracts.errors import ArtifactValidationError, ErrorCode, ValidationIssue

if TYPE_CHECKING:
    from agentsec.contracts.models import AgentSecurityContract


def validate_contract_semantics(contract: "AgentSecurityContract") -> None:
    issues: list[ValidationIssue] = []
    ids: set[str] = set()
    matches: dict[tuple[str, str | None], str] = {}
    for index, rule in enumerate(contract.tools.rules):
        path = f"tools.rules[{index}]"
        if rule.rule_id in ids:
            issues.append(
                ValidationIssue(
                    code=ErrorCode.DUPLICATE_RULE_ID,
                    message="Duplicate rule ID",
                    path=path + ".rule_id",
                )
            )
        ids.add(rule.rule_id)
        selector = (rule.capability, rule.resource)
        if selector in matches:
            code = (
                ErrorCode.DUPLICATE_RULE
                if matches[selector] == rule.decision
                else ErrorCode.CONTRADICTORY_RULE
            )
            issues.append(ValidationIssue(code=code, message="Duplicate exact selector", path=path))
        matches[selector] = rule.decision
    labels: set[str] = set()
    for index, data_rule in enumerate(contract.data.rules):
        path = f"data.rules[{index}]"
        if data_rule.rule_id in ids:
            issues.append(
                ValidationIssue(
                    code=ErrorCode.DUPLICATE_RULE_ID,
                    message="Duplicate rule ID",
                    path=path + ".rule_id",
                )
            )
        ids.add(data_rule.rule_id)
        if data_rule.label in labels:
            issues.append(
                ValidationIssue(
                    code=ErrorCode.DUPLICATE_RULE, message="Duplicate data label rule", path=path
                )
            )
        labels.add(data_rule.label)
        if (
            data_rule.allowed_destinations & data_rule.denied_destinations
            or data_rule.allowed_capabilities & data_rule.denied_capabilities
        ):
            issues.append(
                ValidationIssue(
                    code=ErrorCode.CONTRADICTORY_RULE, message="Data allow/deny overlap", path=path
                )
            )
    invariant_ids = [i.id for i in contract.invariants]
    if len(invariant_ids) != len(set(invariant_ids)):
        issues.append(
            ValidationIssue(
                code=ErrorCode.DUPLICATE_ID, message="Duplicate invariant ID", path="invariants"
            )
        )
    if contract.environment.mode != contract.agent.environment:
        issues.append(
            ValidationIssue(
                code=ErrorCode.INVALID_SCHEMA,
                message="Agent and contract environment differ",
                path="environment.mode",
            )
        )
    if issues:
        raise ArtifactValidationError(issues)
