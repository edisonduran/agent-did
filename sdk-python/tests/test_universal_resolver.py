"""Tests for UniversalResolverClient."""

from __future__ import annotations

import pytest

from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver
from agent_did_sdk.resolver.types import UniversalResolverConfig
from agent_did_sdk.resolver.universal import UniversalResolverClient


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
                    "publicKeyMultibase": "z1234",
                }
            ],
            "authentication": [f"{did}#key-1"],
        }
    )


class FakeSource:
    def __init__(self, doc: AgentDIDDocument | None = None) -> None:
        self._doc = doc

    async def get_by_reference(self, ref: str) -> AgentDIDDocument | None:
        return self._doc


class TestUniversalResolverClient:
    async def test_cache_hit(self) -> None:
        registry = InMemoryAgentRegistry()
        source = FakeSource()
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=registry, document_source=source, cache_ttl_ms=60_000,
        ))
        doc = _make_doc()
        resolver.register_document(doc)
        resolved = await resolver.resolve("did:agent:polygon:0xtest")
        assert resolved.id == doc.id
        stats = resolver.get_cache_stats()
        assert stats.hits == 1

    async def test_fallback(self) -> None:
        registry = InMemoryAgentRegistry()
        source = FakeSource(None)
        fallback = InMemoryDIDResolver()
        doc = _make_doc()
        fallback.register_document(doc)
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=registry, document_source=source, fallback_resolver=fallback, cache_ttl_ms=60_000,
        ))
        resolved = await resolver.resolve("did:agent:polygon:0xtest")
        assert resolved.id == doc.id

    async def test_error_no_fallback(self) -> None:
        registry = InMemoryAgentRegistry()
        source = FakeSource(None)
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=registry, document_source=source, cache_ttl_ms=60_000,
        ))
        with pytest.raises(ValueError, match="not found"):
            await resolver.resolve("did:agent:polygon:0xmissing")
