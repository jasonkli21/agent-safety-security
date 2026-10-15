"""Stable, JSON-ready validation issues and their exception transport."""

from enum import StrEnum
from typing import NoReturn

from agentsec.domain.base import SecurityModel
from agentsec.domain.taxonomy import Severity


class ErrorCode(StrEnum):
    INVALID_SCHEMA = "INVALID_SCHEMA"
    UNSUPPORTED_SCHEMA_VERSION = "UNSUPPORTED_SCHEMA_VERSION"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    INVALID_IDENTIFIER = "INVALID_IDENTIFIER"
    DUPLICATE_RULE_ID = "DUPLICATE_RULE_ID"
    DUPLICATE_ID = "DUPLICATE_ID"
    DUPLICATE_RULE = "DUPLICATE_RULE"
    CONTRADICTORY_RULE = "CONTRADICTORY_RULE"
    INVALID_BUDGET = "INVALID_BUDGET"
    INVALID_TIMEOUT = "INVALID_TIMEOUT"
    INVALID_TIMESTAMP_RANGE = "INVALID_TIMESTAMP_RANGE"
    INVALID_CAPABILITY = "INVALID_CAPABILITY"
    INVALID_TOOL_SCHEMA = "INVALID_TOOL_SCHEMA"
    INVALID_EVENT_SEQUENCE = "INVALID_EVENT_SEQUENCE"
    UNKNOWN_ASSERTION_TYPE = "UNKNOWN_ASSERTION_TYPE"
    UNSAFE_YAML = "UNSAFE_YAML"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    INPUT_TOO_DEEP = "INPUT_TOO_DEEP"
    PATH_ERROR = "PATH_ERROR"


class ValidationIssue(SecurityModel):
    code: ErrorCode
    message: str
    path: str = ""
    severity: Severity = Severity.HIGH


class ArtifactValidationError(Exception):
    def __init__(self, issues: list[ValidationIssue]) -> None:
        self.issues = tuple(issues)
        super().__init__("; ".join(f"{i.code}: {i.path}: {i.message}" for i in issues))


def fail(code: ErrorCode, message: str, path: str = "") -> NoReturn:
    raise ArtifactValidationError([ValidationIssue(code=code, message=message, path=path)])
