"""Tests for EvmAgentRegistry adapter."""

from __future__ import annotations

import pytest

from agent_did_sdk.registry.evm_registry import EvmAgentRegistry
from agent_did_sdk.registry.evm_types import EvmAgentRegistryAdapterConfig, EvmTxResponse
from agent_did_sdk.registry.types import AgentRegistryRecord


class FakeContract:
    """Minimal fake contract that implements EvmAgentRegistryContract."""

    def __init__(self) -> None:
        self._records: dict[str, AgentRegistryRecord] = {}

    async def register_agent(self, did: str, controller: str, document_ref: str | None = None) -> EvmTxResponse | None:
        self._records[did] = AgentRegistryRecord(did=did, controller=controller, createdAt="2024-01-01T00:00:00Z")
        return None

    async def set_document_ref(self, did: str, document_ref: str) -> EvmTxResponse | None:
        rec = self._records.get(did)
        if rec:
            self._records[did] = rec.model_copy(update={"document_ref": document_ref})
        return None

    async def revoke_agent(self, did: str) -> EvmTxResponse | None:
        rec = self._records.get(did)
        if rec:
            self._records[did] = rec.model_copy(update={"revoked_at": "2024-06-01T00:00:00Z"})
        return None

    async def get_agent_record(self, did: str) -> AgentRegistryRecord | None:
        return self._records.get(did)

    async def is_revoked(self, did: str) -> bool:
        rec = self._records.get(did)
        return bool(rec and rec.revoked_at)


@pytest.fixture()
def evm_registry() -> EvmAgentRegistry:
    contract = FakeContract()
    return EvmAgentRegistry(EvmAgentRegistryAdapterConfig(contract_client=contract))  # type: ignore[arg-type]


class TestEvmAgentRegistry:
    async def test_register_and_get(self, evm_registry: EvmAgentRegistry) -> None:
        await evm_registry.register("did:agent:test:1", "did:ethr:0xabc")
        record = await evm_registry.get_record("did:agent:test:1")
        assert record is not None
        assert record.did == "did:agent:test:1"

    async def test_revoke(self, evm_registry: EvmAgentRegistry) -> None:
        await evm_registry.register("did:agent:test:1", "did:ethr:0xabc")
        await evm_registry.revoke("did:agent:test:1")
        assert await evm_registry.is_revoked("did:agent:test:1") is True

    async def test_set_document_reference(self, evm_registry: EvmAgentRegistry) -> None:
        await evm_registry.register("did:agent:test:1", "did:ethr:0xabc")
        await evm_registry.set_document_reference("did:agent:test:1", "hash://sha256/abc")
        record = await evm_registry.get_record("did:agent:test:1")
        assert record is not None
        assert record.document_ref == "hash://sha256/abc"
