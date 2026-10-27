"""Bounded session-wide MCP identity retention without eviction."""

import asyncio

import pytest

from agentsec.adapters.mcp.server import McpRequestIdentityGuard
from agentsec.runtime.models import RuntimeFailure


def test_duplicate_concurrent_and_sequential_identities():
    async def scenario():
        guard = McpRequestIdentityGuard()
        assert sum(await asyncio.gather(*(guard.claim("one") for _ in range(20)))) == 1
        assert not await guard.claim("one")
        assert await guard.claim(1)
        assert await guard.claim("1")

    asyncio.run(scenario())


@pytest.mark.parametrize("request_id", ["x" * 257, "界" * 100, 2**257])
def test_oversized_identity_is_not_retained(request_id):
    guard = McpRequestIdentityGuard()
    with pytest.raises(RuntimeFailure, match="REQUEST_ID_SIZE_LIMIT"):
        asyncio.run(guard.claim(request_id))
    assert not guard._seen


@pytest.mark.parametrize("request_id", [None, True, 1.5])
def test_invalid_identity_is_not_retained(request_id):
    guard = McpRequestIdentityGuard()
    with pytest.raises(RuntimeFailure, match="INVALID_REQUEST_ID"):
        asyncio.run(guard.claim(request_id))
    assert not guard._seen


def test_unique_unknown_tool_flood_has_permanent_session_ceiling():
    async def scenario():
        guard = McpRequestIdentityGuard()
        for index in range(guard.MAX_IDENTITIES):
            assert await guard.claim(index)
        for index in [guard.MAX_IDENTITIES, guard.MAX_IDENTITIES + 1, 0]:
            with pytest.raises(RuntimeFailure, match="REQUEST_ID_CAPACITY"):
                await guard.claim(index)
        assert len(guard._seen) == guard.MAX_IDENTITIES

    asyncio.run(scenario())
