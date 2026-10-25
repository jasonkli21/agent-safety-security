"""Fixed-endpoint outbound HTTP, without proxies, redirects or retries."""

import asyncio
import http.client
import re
import ssl
import time
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, model_validator

from agentsec.domain.base import Identifier, NonEmpty, VersionedModel
from agentsec.domain.execution import ExecutionBinding
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.runtime.bindings import ProtectedCall, ProtectedTool
from agentsec.runtime.gateway import RuntimeGateway
from agentsec.runtime.models import RuntimeFailure, ToolResponse


class HttpAction(VersionedModel):
    adapter_id: Identifier
    origin: str
    path: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    headers: dict[str, str] = Field(default_factory=dict, repr=False)
    timeout_seconds: int = Field(default=10, ge=1, le=300)
    request_limit: int = Field(default=65536, ge=1, le=1048576)
    response_limit: int = Field(default=65536, ge=1, le=1048576)
    destination: Identifier
    trusted_effect_resource: NonEmpty | None = Field(
        default=None,
        description="Reviewed operator assertion of the fixed endpoint's effective resource.",
    )
    tls_ca_pem: str | None = Field(
        default=None,
        repr=False,
        description="Protected PEM CA bundle required for HTTPS; ambient TLS trust is ignored.",
    )

    @model_validator(mode="after")
    def safe_endpoint(self) -> Self:
        u = urlsplit(self.origin)
        if (
            u.scheme not in {"http", "https"}
            or not u.hostname
            or u.username is not None
            or u.password is not None
            or u.path not in {"", "/"}
            or u.query
            or u.fragment
            or any(ord(c) <= 32 or ord(c) >= 127 for c in self.origin)
        ):
            raise ValueError("Invalid fixed origin")
        _ = u.port
        if u.scheme == "https":
            if self.tls_ca_pem is None or not 1 <= len(self.tls_ca_pem) <= 1_048_576:
                raise ValueError("HTTPS requires a bounded protected CA bundle")
        elif self.tls_ca_pem is not None:
            raise ValueError("TLS CA bundle is only valid for HTTPS")
        if (
            not self.path.startswith("/")
            or self.path.startswith("//")
            or "#" in self.path
            or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
        ):
            raise ValueError("Invalid fixed path")
        for key, value in self.headers.items():
            if (
                not key
                or any(
                    c
                    not in (
                        "!#$%&'*+-.^_`|~0123456789"
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    )
                    for c in key
                )
                or any(ord(c) < 32 or ord(c) >= 127 for c in value)
                or key.lower()
                in {
                    "host",
                    "content-length",
                    "transfer-encoding",
                    "connection",
                    "proxy-authorization",
                    "proxy-connection",
                }
            ):
                raise ValueError("Invalid protected header")
        if len({k.lower() for k in self.headers}) != len(self.headers):
            raise ValueError("Duplicate header")
        return self


def protect_http(gateway: RuntimeGateway, tool: ProtectedTool, config: HttpAction) -> ProtectedCall:
    config = HttpAction.model_validate_json(config.model_dump_json())
    binding = ExecutionBinding(
        schema_version="0.1",
        adapter_kind="http",
        adapter_id=config.adapter_id,
        adapter_version="2",
        binding_digest=content_digest(config),
    )
    tool = tool.model_copy(
        update={
            "execution_binding": binding,
            "data_sink_destination": config.destination,
            "trusted_effect_resource": config.trusted_effect_resource,
        }
    )

    u = urlsplit(config.origin)
    tls_context = _tls_context(config)

    def preflight(arguments: dict[str, JsonValue]) -> None:
        if config.method == "GET" and arguments:
            raise RuntimeFailure("HTTP_GET_ARGUMENTS_UNSUPPORTED")
        if (
            config.method != "GET"
            and len(canonical_json(arguments).encode()) > config.request_limit
        ):
            raise RuntimeFailure("HTTP_REQUEST_LIMIT")

    def request(arguments: dict[str, JsonValue]) -> ToolResponse:
        body = canonical_json(arguments).encode() if config.method != "GET" else None
        if config.method == "GET" and arguments:
            raise RuntimeFailure("HTTP_GET_ARGUMENTS_UNSUPPORTED")
        if body is not None and len(body) > config.request_limit:
            raise RuntimeFailure("HTTP_REQUEST_LIMIT")
        conn: http.client.HTTPConnection
        if u.scheme == "https":
            assert tls_context is not None
            conn = http.client.HTTPSConnection(
                u.hostname or "", u.port, timeout=config.timeout_seconds, context=tls_context
            )
        else:
            conn = http.client.HTTPConnection(
                u.hostname or "", u.port, timeout=config.timeout_seconds
            )
        deadline = time.monotonic() + config.timeout_seconds
        try:
            headers = {"Content-Type": "application/json", **config.headers}
            conn.request(config.method, config.path, body=body, headers=headers)
            response = conn.getresponse()
            if 300 <= response.status < 400:
                raise RuntimeFailure("HTTP_REDIRECT_REJECTED")
            data = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeFailure("HTTP_TIMEOUT")
                if conn.sock is not None:
                    conn.sock.settimeout(remaining)
                chunk = response.read1(min(65536, config.response_limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > config.response_limit:
                    raise RuntimeFailure("HTTP_RESPONSE_LIMIT")
            result: dict[str, JsonValue] = {
                "status": response.status,
                "text": data.decode("utf-8", errors="replace"),
            }
            return ToolResponse(
                body=result, structured=result, success=200 <= response.status < 300
            )
        except RuntimeFailure:
            raise
        except Exception as exc:
            raise RuntimeFailure("HTTP_TRANSPORT_FAILURE") from exc
        finally:
            conn.close()

    async def dispatch(arguments: dict[str, JsonValue]) -> ToolResponse:
        # Cancellation cannot undo an HTTP request already sent. Gateway records unknown effect.
        return await asyncio.to_thread(request, arguments)

    return ProtectedCall(gateway, tool, dispatch, preflight)


def _tls_context(config: HttpAction) -> ssl.SSLContext | None:
    if urlsplit(config.origin).scheme != "https":
        return None
    ca_pem = config.tls_ca_pem
    if ca_pem is None:
        raise RuntimeFailure("HTTP_TLS_CONFIGURATION_INVALID")
    try:
        # Some Python/OpenSSL builds seed PROTOCOL_TLS_CLIENT with ambient roots.
        # Prefer the client protocol, but fall back to an empty generic context if needed.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if context.cert_store_stats()["x509_ca"] != 0:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        if context.cert_store_stats()["x509_ca"] != 0:
            raise RuntimeFailure("HTTP_TLS_AMBIENT_CA_STORE")
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        # The runtime accepts None to disable key logging; the type stub omits None.
        context.keylog_filename = None  # type: ignore[assignment]
        context.load_verify_locations(cadata=ca_pem)
        certificates = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            ca_pem,
            flags=re.DOTALL,
        )
        remainder = re.sub(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            "",
            ca_pem,
            flags=re.DOTALL,
        )
        if not certificates or remainder.strip():
            raise RuntimeFailure("HTTP_TLS_CA_BUNDLE_INVALID")
        expected = {ssl.PEM_cert_to_DER_cert(certificate) for certificate in certificates}
        actual = set(context.get_ca_certs(binary_form=True))
        if not expected or actual != expected:
            raise RuntimeFailure("HTTP_TLS_CA_STORE_MISMATCH")
        return context
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise RuntimeFailure("HTTP_TLS_CONFIGURATION_INVALID") from exc
