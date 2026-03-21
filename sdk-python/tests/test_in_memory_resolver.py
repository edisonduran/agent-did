"""Tests for InMemoryDIDResolver."""

import pytest

from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver


def _make_doc(did: str = "did:agent:polygon:0xtest") -> AgentDIDDocument:
    return AgentDIDDocument(
        **{
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": did,
            "controller": "did:ethr:0xcontroller",
            "created": "2024-01-01T00:00:00Z",
            "updated": "2024-01-01T00:00:00Z",
            "agentMetadata": {
                "name": "TestAgent",
                "version": "1.0.0",
                "coreModelHash": "hash://sha256/abc",
                "systemPromptHash": "hash://sha256/def",
            },
            "verificationMethod": [
                {
                    "id": f"{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:ethr:0xcontroller",
                    "publicKeyMultibase": "z1234567890abcdef",
                }
            ],
            "authentication": [f"{did}#key-1"],
        }
    )


@pytest.fixture()
def resolver() -> InMemoryDIDResolver:
    return InMemoryDIDResolver()


class TestInMemoryDIDResolver:
    async def test_register_and_resolve(self, resolver: InMemoryDIDResolver) -> None:
        doc = _make_doc()
        resolver.register_document(doc)
        resolved = await resolver.resolve("did:agent:polygon:0xtest")
        assert resolved.id == doc.id

    async def test_resolve_not_found(self, resolver: InMemoryDIDResolver) -> None:
        with pytest.raises(ValueError, match="not found"):
            await resolver.resolve("did:agent:polygon:0xmissing")

    async def test_remove(self, resolver: InMemoryDIDResolver) -> None:
        doc = _make_doc()
        resolver.register_document(doc)
        resolver.remove("did:agent:polygon:0xtest")
        with pytest.raises(ValueError, match="not found"):
            await resolver.resolve("did:agent:polygon:0xtest")

    async def test_deep_copy(self, resolver: InMemoryDIDResolver) -> None:
        doc = _make_doc()
        resolver.register_document(doc)
        resolved1 = await resolver.resolve("did:agent:polygon:0xtest")
        resolved2 = await resolver.resolve("did:agent:polygon:0xtest")
        assert resolved1 is not resolved2
