"""Tests for InMemoryAgentRegistry."""

import pytest

from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry


@pytest.fixture()
def registry() -> InMemoryAgentRegistry:
    return InMemoryAgentRegistry()


class TestInMemoryAgentRegistry:
    async def test_register_and_get(self, registry: InMemoryAgentRegistry) -> None:
        await registry.register("did:agent:test:1", "did:ethr:0xabc")
        record = await registry.get_record("did:agent:test:1")
        assert record is not None
        assert record.did == "did:agent:test:1"
        assert record.controller == "did:ethr:0xabc"

    async def test_register_idempotent(self, registry: InMemoryAgentRegistry) -> None:
        await registry.register("did:agent:test:1", "did:ethr:0xabc")
        await registry.register("did:agent:test:1", "did:ethr:0xother")
        record = await registry.get_record("did:agent:test:1")
        assert record is not None
        assert record.controller == "did:ethr:0xabc"

    async def test_set_document_reference(self, registry: InMemoryAgentRegistry) -> None:
        await registry.register("did:agent:test:1", "did:ethr:0xabc")
        await registry.set_document_reference("did:agent:test:1", "hash://sha256/abc")
        record = await registry.get_record("did:agent:test:1")
        assert record is not None
        assert record.document_ref == "hash://sha256/abc"

    async def test_set_reference_not_found(self, registry: InMemoryAgentRegistry) -> None:
        with pytest.raises(ValueError, match="not found"):
            await registry.set_document_reference("did:agent:test:missing", "ref")

    async def test_revoke(self, registry: InMemoryAgentRegistry) -> None:
        await registry.register("did:agent:test:1", "did:ethr:0xabc")
        assert await registry.is_revoked("did:agent:test:1") is False
        await registry.revoke("did:agent:test:1")
        assert await registry.is_revoked("did:agent:test:1") is True

    async def test_revoke_not_found(self, registry: InMemoryAgentRegistry) -> None:
        with pytest.raises(ValueError, match="not found"):
            await registry.revoke("did:agent:test:missing")

    async def test_get_unknown(self, registry: InMemoryAgentRegistry) -> None:
        assert await registry.get_record("did:agent:test:unknown") is None

    async def test_is_revoked_unknown(self, registry: InMemoryAgentRegistry) -> None:
        assert await registry.is_revoked("did:agent:test:unknown") is False
