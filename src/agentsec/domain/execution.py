"""Safe operational route identity, independent of authorization grants."""

from agentsec.domain.base import Digest, Identifier, VersionedModel


class ExecutionBinding(VersionedModel):
    adapter_kind: Identifier
    adapter_id: Identifier
    adapter_version: Identifier = "1"
    binding_digest: Digest
    isolation_digest: Digest | None = None
