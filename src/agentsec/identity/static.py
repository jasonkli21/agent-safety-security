"""Protected local configuration, explicitly not remote caller authentication."""

from datetime import datetime

from agentsec.domain.authority import VerifiedCredential
from agentsec.domain.identity import PrincipalRef
from agentsec.identity.ports import IdentityError


class StaticIdentityProvider:
    def __init__(
        self, principal: PrincipalRef, capability_ceiling: frozenset[str] | None = None
    ) -> None:
        self.principal, self.capability_ceiling = principal, capability_ceiling

    def verify(self, credential: str | None, now: datetime) -> VerifiedCredential:
        if credential is not None:
            raise IdentityError("UNEXPECTED_CREDENTIAL")
        return VerifiedCredential(
            schema_version="0.1",
            principal=self.principal,
            assurance="STATIC_TRUSTED_CONFIG",
            capability_ceiling=self.capability_ceiling,
            valid_from=now,
        )
