"""Closed diagnostic vocabulary; never include untrusted input in errors."""

from typing import Literal

Code = Literal[
    "SIGNATURE_INVALID",
    "TRUST_UNAVAILABLE",
    "TOKEN_MISSING",
    "TOKEN_INVALID",
    "DENIED",
    "NOT_FOUND",
    "CONFLICT",
    "INVALID_INPUT",
    "POLICY_BLOCKED",
    "STORE_UNAVAILABLE",
    "PUBLICATION_UNCERTAIN",
    "AUDIT_CAPACITY",
    "CONTENT_TYPE",
    "TOO_LARGE",
    "TIMEOUT",
]
STATUS: dict[Code, int] = {
    "SIGNATURE_INVALID": 422,
    "TRUST_UNAVAILABLE": 403,
    "TOKEN_MISSING": 401,
    "TOKEN_INVALID": 401,
    "DENIED": 403,
    "NOT_FOUND": 404,
    "CONFLICT": 409,
    "INVALID_INPUT": 422,
    "POLICY_BLOCKED": 422,
    "STORE_UNAVAILABLE": 503,
    "PUBLICATION_UNCERTAIN": 503,
    "AUDIT_CAPACITY": 503,
    "CONTENT_TYPE": 415,
    "TOO_LARGE": 413,
    "TIMEOUT": 408,
}


class TeamError(Exception):
    def __init__(self, code: Code) -> None:
        self.code = code
        self.status = STATUS[code]
        super().__init__(code)
