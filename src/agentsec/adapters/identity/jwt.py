"""Pinned asymmetric PyJWT verifier; no discovery, issuance or remote key resolution."""

import math
from datetime import UTC, datetime, timedelta

from agentsec.domain.authority import VerifiedCredential
from agentsec.identity.config import JwtIdentityConfig
from agentsec.identity.ports import IdentityError

MAX_CREDENTIAL_BYTES = 16384


class JwtIdentityProvider:
    def __init__(self, config: JwtIdentityConfig) -> None:
        # Take an isolated snapshot; protected configuration cannot change mid-session.
        self.config = JwtIdentityConfig.model_validate_json(config.model_dump_json())
        try:
            import jwt
            from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            for key in self.config.keys:
                parsed = load_pem_public_key(key.public_key_pem.encode("ascii"))
                valid_type = (
                    (
                        key.algorithm == "RS256"
                        and isinstance(parsed, rsa.RSAPublicKey)
                        and parsed.key_size >= 2048
                    )
                    or (
                        key.algorithm == "ES256"
                        and isinstance(parsed, ec.EllipticCurvePublicKey)
                        and isinstance(parsed.curve, ec.SECP256R1)
                    )
                    or (
                        key.algorithm == "EdDSA"
                        and isinstance(parsed, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey))
                    )
                )
                if not valid_type:
                    raise ValueError
                jwt.algorithms.get_default_algorithms()[key.algorithm].prepare_key(parsed)
        except Exception:
            raise IdentityError("IDENTITY_VERIFIER_CONFIGURATION_INVALID") from None

    def verify(self, credential: str | None, now: datetime) -> VerifiedCredential:
        if credential is None:
            raise IdentityError("IDENTITY_CREDENTIAL_MISSING")
        try:
            import jwt

            if len(credential.encode("utf-8")) > MAX_CREDENTIAL_BYTES:
                raise ValueError
            header = jwt.get_unverified_header(credential)
            if set(header) - {"alg", "kid", "typ"}:
                raise ValueError
            key = next(k for k in self.config.keys if k.kid == header.get("kid"))
            if header.get("alg") != key.algorithm:
                raise ValueError
            claims = jwt.decode(
                credential,
                key.public_key_pem,
                algorithms=[key.algorithm],
                issuer=self.config.issuer,
                audience=self.config.audience,
                options={
                    "require": ["iss", "aud", "sub", "exp"],
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
            # Time is checked here only to use the same injected clock as the runtime.
            exp = claims["exp"]
            nbf = claims.get("nbf", now.timestamp())
            if any(type(t) not in {int, float} or not math.isfinite(t) for t in (exp, nbf)):
                raise ValueError
            skew = self.config.clock_skew_seconds
            if (
                now.timestamp() >= exp + skew
                or now.timestamp() + skew < nbf
                or ("nbf" in claims and exp <= nbf)
            ):
                raise ValueError
            subject = claims["sub"]
            principal = next(s.principal for s in self.config.subjects if s.subject == subject)
            ceiling = None
            if self.config.scope_mapping is not None:
                scope = claims.get("scope", "")
                if not isinstance(scope, str):
                    raise ValueError
                ceiling = frozenset(
                    self.config.scope_mapping[s]
                    for s in scope.split()
                    if s in self.config.scope_mapping
                )
            return VerifiedCredential(
                schema_version="0.1",
                principal=principal,
                assurance="SIGNED_JWT",
                capability_ceiling=ceiling,
                valid_from=datetime.fromtimestamp(nbf, UTC) - timedelta(seconds=skew),
                expires_at=datetime.fromtimestamp(exp, UTC) + timedelta(seconds=skew),
            )
        except Exception:
            # No verifier exception/claim/token reaches the diagnostic boundary.
            raise IdentityError("IDENTITY_CREDENTIAL_INVALID") from None
