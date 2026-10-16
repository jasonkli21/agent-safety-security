"""Protocol-independent results and stable safe failures."""

from pydantic import JsonValue

from agentsec.domain.base import SecurityModel


class RuntimeFailure(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ToolResponse(SecurityModel):
    body: dict[str, JsonValue]
    success: bool
    structured: JsonValue = None
