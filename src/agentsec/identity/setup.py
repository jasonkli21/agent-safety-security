"""Protected runtime setup, distinct from authored policy and protocol requests."""

from datetime import datetime
from pathlib import Path

from agentsec.domain.authority import AuthorityContext
from agentsec.domain.identity import Delegation, PrincipalRef
from agentsec.domain.serialization import canonical_json
from agentsec.identity.config import IdentityConfig, JwtIdentityConfig
from agentsec.identity.ingress import read_credential
from agentsec.identity.ports import IdentityError, IdentityProvider
from agentsec.identity.static import StaticIdentityProvider


def configured_provider(config: IdentityConfig | None, principal: PrincipalRef) -> IdentityProvider:
    if isinstance(config, JwtIdentityConfig):
        from agentsec.adapters.identity.jwt import JwtIdentityProvider

        return JwtIdentityProvider(config)
    return StaticIdentityProvider(
        config.principal if config else principal, config.capability_ceiling if config else None
    )


def bind_authority(
    config: IdentityConfig | None,
    principal: PrincipalRef,
    delegation: Delegation | None,
    credential_file: Path | None,
    now: datetime,
) -> AuthorityContext:
    provider = configured_provider(config, principal)
    if credential_file is not None and not isinstance(config, JwtIdentityConfig):
        raise IdentityError("UNEXPECTED_CREDENTIAL")
    credential = read_credential(credential_file) if credential_file else None
    verified = provider.verify(credential, now)
    return AuthorityContext(
        schema_version="0.1",
        credential=verified,
        delegation_json=canonical_json(delegation) if delegation else None,
    )
