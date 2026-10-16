"""Authentication boundary. Implementations return only minimized trusted facts."""

from datetime import datetime
from typing import Protocol

from agentsec.domain.authority import VerifiedCredential


class IdentityError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class IdentityProvider(Protocol):
    def verify(self, credential: str | None, now: datetime) -> VerifiedCredential: ...
