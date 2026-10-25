"""Optional Starlette HTTP adapter. No request bodies/tokens in diagnostics or logs."""

import asyncio
import json
from typing import Literal

from pydantic import BaseModel
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from agentsec.contracts.loader import parse_document, validate_data
from agentsec.control_plane.auth import TeamVerifier, VerifiedIdentity
from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import (
    Agent,
    Member,
    Metadata,
    Reporter,
    RevisionInput,
    Transition,
)
from agentsec.control_plane.service import TeamService
from agentsec.domain.serialization import canonical_json


async def body[M: BaseModel](request: Request, model: type[M]) -> M:
    if request.headers.get("content-type", "").split(";")[0] != "application/json":
        raise TeamError("CONTENT_TYPE")
    value = bytearray()
    try:
        async with asyncio.timeout(10):
            async for chunk in request.stream():
                value.extend(chunk)
                if len(value) > 131072:
                    raise TeamError("TOO_LARGE")
        return validate_data(model, parse_document(value.decode("utf-8"), format="json"))
    except TeamError:
        raise
    except TimeoutError:
        raise TeamError("TIMEOUT") from None
    except Exception:
        raise TeamError("INVALID_INPUT") from None


def create_app(service: TeamService) -> Starlette:
    verifier = TeamVerifier(service.config)

    def token(request: Request) -> VerifiedIdentity:
        values = request.headers.getlist("authorization")
        if not values:
            return verifier.verify(None, service.clock())
        if len(values) != 1 or not values[0].startswith("Bearer "):
            raise TeamError("TOKEN_INVALID")
        return verifier.verify(values[0][7:], service.clock())

    async def endpoint(request: Request) -> JSONResponse:
        try:
            identity = token(request)
            org = request.path_params["org"]
            resource = request.path_params["resource"]
            parts = resource.split("/")
            result: object
            if request.method == "GET":
                if set(request.query_params) - {"offset", "limit"}:
                    raise TeamError("INVALID_INPUT")
                if any(len(request.query_params.getlist(k)) != 1 for k in request.query_params):
                    raise TeamError("INVALID_INPUT")
                try:
                    offset = int(request.query_params.get("offset", "0"))
                    limit = int(request.query_params.get("limit", "100"))
                except ValueError:
                    raise TeamError("INVALID_INPUT") from None
                if not 0 <= offset <= 10000 or not 1 <= limit <= 100:
                    raise TeamError("INVALID_INPUT")
                collections: dict[
                    str, Literal["member", "agent", "reporter", "revision", "receipt"]
                ] = {
                    "members": "member",
                    "agents": "agent",
                    "reporters": "reporter",
                    "revisions": "revision",
                    "reports": "receipt",
                }
                if resource in collections:
                    result = await run_in_threadpool(
                        service.list_records, identity, org, collections[resource], offset, limit
                    )
                elif resource == "posture":
                    result = await run_in_threadpool(service.posture, identity, org)
                elif resource == "alerts":
                    posture = await run_in_threadpool(service.posture, identity, org)
                    result = {
                        "schema_version": "team-v1",
                        "advisory": True,
                        "agents": [a.model_dump(mode="json") for a in posture.agents if a.flags],
                    }
                elif resource == "audit":
                    result = await run_in_threadpool(
                        service.audit_log, identity, org, offset, limit
                    )
                elif resource == "own-status":
                    result = await run_in_threadpool(service.own_status, identity, org)
                elif len(parts) == 2 and parts[0] == "revisions":
                    result = await run_in_threadpool(service.revision, identity, org, parts[1])
                elif len(parts) == 3 and parts[0] == "revisions" and parts[2] == "source":
                    source = await run_in_threadpool(service.source, identity, org, parts[1])
                    result = {"schema_version": "team-v1", "source": source}
                else:
                    # Unknown paths still require tenant authorization.
                    await run_in_threadpool(service.list_records, identity, org, "agent", 0, 1)
                    raise TeamError("NOT_FOUND")
            elif request.method == "POST":
                if request.query_params:
                    raise TeamError("INVALID_INPUT")
                if resource == "members":
                    result = await run_in_threadpool(
                        service.member, identity, org, await body(request, Member)
                    )
                elif resource == "agents":
                    result = await run_in_threadpool(
                        service.agent, identity, org, await body(request, Agent)
                    )
                elif resource == "reporters":
                    result = await run_in_threadpool(
                        service.reporter, identity, org, await body(request, Reporter)
                    )
                elif resource == "revisions":
                    result = await run_in_threadpool(
                        service.create_revision, identity, org, await body(request, RevisionInput)
                    )
                elif len(parts) == 3 and parts[0] == "revisions" and parts[2] == "transitions":
                    result = await run_in_threadpool(
                        service.transition, identity, org, parts[1], await body(request, Transition)
                    )
                elif resource == "reports":
                    result = await run_in_threadpool(
                        service.report, identity, org, await body(request, Metadata)
                    )
                elif resource == "metadata-purge":
                    # An empty strict team-v1 body prevents accidental body acceptance.
                    from agentsec.control_plane.models import TeamModel

                    await body(request, TeamModel)
                    result = {
                        "schema_version": "team-v1",
                        "purged": await run_in_threadpool(service.purge, identity, org),
                    }
                else:
                    await run_in_threadpool(service.list_records, identity, org, "agent", 0, 1)
                    raise TeamError("NOT_FOUND")
            else:
                raise TeamError("NOT_FOUND")
            return JSONResponse(
                json.loads(canonical_json(result)),
                headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
            )
        except TeamError as exc:
            return JSONResponse(
                {"schema_version": "team-v1", "error": exc.code},
                status_code=exc.status,
                headers={"Cache-Control": "no-store"},
            )
        except Exception:
            # Corrupt persisted models and unexpected store failures never echo inputs.
            return JSONResponse(
                {"schema_version": "team-v1", "error": "STORE_UNAVAILABLE"}, status_code=503
            )

    return Starlette(
        debug=False,
        routes=[Route("/v1/orgs/{org}/{resource:path}", endpoint, methods=["GET", "POST"])],
    )
