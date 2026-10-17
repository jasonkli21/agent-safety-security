"""Fixed-endpoint outbound HTTP, without proxies, redirects or retries."""

import asyncio
import http.client
import time
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, model_validator

from agentsec.domain.base import Identifier, VersionedModel
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
        binding_digest=content_digest(config),
    )
    tool = tool.model_copy(
        update={"execution_binding": binding, "data_sink_destination": config.destination}
    )

    def request(arguments: dict[str, JsonValue]) -> ToolResponse:
        body = canonical_json(arguments).encode() if config.method != "GET" else None
        if config.method == "GET" and arguments:
            raise RuntimeFailure("HTTP_GET_ARGUMENTS_UNSUPPORTED")
        if body is not None and len(body) > config.request_limit:
            raise RuntimeFailure("HTTP_REQUEST_LIMIT")
        u = urlsplit(config.origin)
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = cls(u.hostname or "", u.port, timeout=config.timeout_seconds)
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

    return ProtectedCall(gateway, tool, dispatch)
