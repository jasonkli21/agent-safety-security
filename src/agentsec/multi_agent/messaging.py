"""Fixed adjacent in-memory routes; sender identity and labels never come from arguments."""

from typing import TYPE_CHECKING
from uuid import uuid4

from pydantic import JsonValue

from agentsec.adapters.native import native_binding
from agentsec.domain.events import GraphEventPayload, ToolDispatchedPayload
from agentsec.domain.provenance import DataOrigin
from agentsec.domain.serialization import content_digest
from agentsec.domain.taxonomy import DataLabel, SideEffectClass, TrustClass
from agentsec.domain.tools import ToolDescriptor
from agentsec.runtime.bindings import ProtectedCall, ProtectedTool
from agentsec.runtime.models import RuntimeFailure, ToolResponse

if TYPE_CHECKING:
    from agentsec.multi_agent.session import MultiAgentSession


class MessageRoute:
    """Operator-created endpoint. Give each agent only its own send/receive handles."""

    def __init__(self, session: "MultiAgentSession", sender: str, recipient: str) -> None:
        session._owner()
        edges = {(e.parent_id, e.child_id) for e in session.material.graph.edges}
        if (sender, recipient) not in edges and (recipient, sender) not in edges:
            raise RuntimeFailure("GRAPH_NONADJACENT_ROUTE")
        self.__session, self.__sender, self.__recipient = session, sender, recipient
        source = session._gateways[sender]
        # This route identity is protected independently of caller content.
        self.__tool = ProtectedTool(
            schema_version="0.1",
            descriptor=ToolDescriptor(
                schema_version="0.1",
                tool_id=f"message/{sender}/{recipient}",
                namespace="agent",
                name=f"send_{recipient}",
                protocol="in_process",
                description="Send untrusted content to one configured adjacent peer",
                input_schema={
                    "type": "object",
                    "properties": {"body": {"type": "string"}},
                    "required": ["body"],
                    "additionalProperties": False,
                },
                capabilities=frozenset({"agent.message.send"}),
                side_effect_class=SideEffectClass.EXTERNAL_WRITE,
            ),
            execution_binding=native_binding(
                f"message/{sender}/{recipient}", "agentsec.message.v1"
            ),
            data_sink_destination=f"agent:{recipient}",
            output_data_labels=frozenset(),
        )

        # Register now to establish trust/coverage; each send uses the identical snapshot.
        async def unavailable(arguments: dict[str, JsonValue]) -> ToolResponse:
            raise RuntimeFailure("GRAPH_MESSAGE_INTERNAL_ERROR")

        ProtectedCall(source, self.__tool, unavailable)

    @property
    def tool(self) -> ProtectedTool:
        """Defensive operator metadata for offline trust review/registration."""
        return ProtectedTool.model_validate_json(self.__tool.model_dump_json(round_trip=True))

    async def send(self, body: str) -> ToolResponse:
        session = self.__session
        session._owner()
        if type(body) is not str or len(body.encode("utf-8")) > 65536:
            raise RuntimeFailure("GRAPH_MESSAGE_SIZE_LIMIT")
        if len(session._messages) >= 1024:
            raise RuntimeFailure("GRAPH_MESSAGE_COUNT_LIMIT")
        sender, recipient = self.__sender, self.__recipient
        source, target = session._gateways[sender], session._gateways[recipient]
        binding = session._binding(sender, session._clock())
        peer = session._binding(recipient, session._clock())
        refs = source.provenance.snapshot()
        if len(refs) > 64 or len(target.provenance.snapshot()) > 64:
            raise RuntimeFailure("GRAPH_MESSAGE_REFERENCE_LIMIT")
        labels = frozenset({DataLabel.UNTRUSTED_CONTENT, DataLabel.USER_PROVIDED}) | frozenset(
            label for ref in refs for label in ref.labels
        )
        message_id = str(uuid4())

        def fresh() -> None:
            if (
                session._binding(sender, session._clock()) != binding
                or session._binding(recipient, session._clock()) != peer
            ):
                raise RuntimeFailure("GRAPH_MESSAGE_STALE")

        async def deliver(arguments: dict[str, JsonValue]) -> ToolResponse:
            fresh()
            if message_id in session._messages or len(session._messages) >= 1024:
                raise RuntimeFailure("GRAPH_MESSAGE_DUPLICATE_OR_LIMIT")
            event = source.events.last_event
            if event is None or not isinstance(event.payload, ToolDispatchedPayload):
                raise RuntimeFailure("GRAPH_MESSAGE_DISPATCH_REQUIRED")
            for ref in refs:
                if source.provenance.get(ref.artifact_id) != ref:
                    raise RuntimeFailure("GRAPH_MESSAGE_FOREIGN_ARTIFACT")
            artifact = target.provenance.derive(
                DataOrigin(
                    origin_type="agent_message",
                    source_id=message_id,
                    trust_class=TrustClass.UNTRUSTED_EXTERNAL,
                ),
                parents=target.provenance.snapshot(),
                labels=labels,
                content_hash=content_digest(body),
            )
            sent = GraphEventPayload(
                schema_version="0.1",
                operation="MESSAGE_SENT",
                binding=binding,
                peer_binding=peer,
                message_id=message_id,
                source_run_id=source.events.run_id,
                source_trace_id=source.events.trace_id,
                source_event_id=event.event_id,
                source_request_id=event.payload.request_id,
                source_dispatch_id=event.payload.dispatch_id,
                content_hash=content_digest(body),
                content_size=len(body.encode("utf-8")),
                artifact=artifact,
                source_artifact_digest=content_digest(refs),
            )
            source.events.emit(sent)

            def record() -> None:
                fresh()
                target.events.emit(sent.model_copy(update={"operation": "MESSAGE_IMPORTED"}))
                fresh()

            # Critical receiver evidence, then monotonic frontier, then content release, no await.
            target.provenance.expose(artifact, record)
            session._messages.add(message_id)
            session._inboxes.setdefault(recipient, []).append(body)
            return ToolResponse(
                body={"message_id": message_id, "status": "RELEASE_COMMITTED"}, success=True
            )

        return await ProtectedCall(source, self.__tool, deliver).invoke({"body": body})
