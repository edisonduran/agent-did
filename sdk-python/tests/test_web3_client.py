"""Tests for Web3AgentRegistryContractClient."""

from __future__ import annotations

import pytest

from agent_did_sdk.registry.web3_client import Web3AgentRegistryContractClient


class FakeContractFunctions:
    """Simulates a web3 contract functions object returning tuple-shaped results."""

    def getAgentRecord(self, did: str):  # noqa: N802
        class CallableResult:
            def call(self_inner):  # noqa: N805
                return ("did:agent:test:1", "did:ethr:0xabc", "2024-01-01T00:00:00Z", "", "")
        return CallableResult()


class FakeContractInvalid:
    class functions:
        @staticmethod
        def getAgentRecord(did: str):  # noqa: N802
            class CallableResult:
                def call(self):
                    return 42  # invalid shape
            return CallableResult()


class TestWeb3Client:
    async def test_tuple_response(self) -> None:
        fake = type("Obj", (), {"functions": FakeContractFunctions()})()
        client = Web3AgentRegistryContractClient(fake)
        record = await client.get_agent_record("did:agent:test:1")
        assert record is not None
        assert record.did == "did:agent:test:1"

    async def test_invalid_shape_raises(self) -> None:
        fake = FakeContractInvalid()
        client = Web3AgentRegistryContractClient(fake)
        with pytest.raises(ValueError, match="Invalid contract response"):
            await client.get_agent_record("did:agent:test:1")
