"""Separate team JWT assurance domain, with no runtime credential conversion."""

import base64
import math
from dataclasses import dataclass
from datetime import datetime

from agentsec.contracts.loader import parse_document
from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import TeamConfig


@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    subject: str
    expires_at: float


class TeamVerifier:
    def __init__(self, config: TeamConfig) -> None:
        self.config = TeamConfig.model_validate_json(config.model_dump_json())
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            for issuer in self.config.issuers:
                for key in issuer.keys:
                    if not isinstance(
                        load_pem_public_key(key.public_key_pem.encode()), Ed25519PublicKey
                    ):
                        raise ValueError
        except Exception:
            raise TeamError("INVALID_INPUT") from None

    def verify(self, token: str | None, now: datetime) -> VerifiedIdentity:
        if token is None:
            raise TeamError("TOKEN_MISSING")
        try:
            import jwt

            if len(token.encode()) > 16384:
                raise ValueError
            segments = token.split(".")
            if len(segments) != 3:
                raise ValueError
            # Reject duplicate JSON claims/headers instead of last-key-wins interpretation.
            for segment in segments[:2]:
                parse_document(
                    base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)).decode(),
                    format="json",
                )
            header = jwt.get_unverified_header(token)
            if set(header) - {"alg", "kid", "typ"} or header.get("alg") != "EdDSA":
                raise ValueError
            if header.get("typ", "JWT") != "JWT":
                raise ValueError
            # Unverified issuer selects only among protected pins, never a URL/key fetch.
            untrusted = jwt.decode(token, options={"verify_signature": False})
            issuer = next(i for i in self.config.issuers if i.issuer == untrusted.get("iss"))
            key = next(k for k in issuer.keys if k.kid == header.get("kid"))
            claims = jwt.decode(
                token,
                key.public_key_pem,
                algorithms=["EdDSA"],
                issuer=issuer.issuer,
                audience=issuer.audience,
                options={
                    "require": ["iss", "aud", "sub", "exp", "nbf"],
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "strict_aud": True,
                },
            )
            exp, nbf = claims["exp"], claims["nbf"]
            if any(type(t) not in {int, float} or not math.isfinite(t) for t in (exp, nbf)):
                raise ValueError
            skew = self.config.skew_seconds
            if exp <= nbf or now.timestamp() >= exp + skew or now.timestamp() + skew < nbf:
                raise ValueError
            sub = claims["sub"]
            if not isinstance(sub, str) or not 1 <= len(sub) <= 128:
                raise ValueError
            return VerifiedIdentity(issuer.issuer, sub, float(exp + skew))
        except Exception:
            raise TeamError("TOKEN_INVALID") from None
