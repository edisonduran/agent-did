"""Tests for HttpDIDDocumentSource."""

from __future__ import annotations

import httpx

from agent_did_sdk.resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig


def _make_jsonld_response(did: str = "did:agent:polygon:0xtest") -> dict:
    return {
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


class TestHttpDIDDocumentSource:
    async def test_successful_fetch(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_make_jsonld_response())

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(http_client=client))
        doc = await source.get_by_reference("https://example.com/doc.json")
        assert doc is not None
        assert doc.id == "did:agent:polygon:0xtest"

    async def test_404_returns_none(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(http_client=client))
        doc = await source.get_by_reference("https://example.com/missing.json")
        assert doc is None

    async def test_ssrf_reject_file(self) -> None:
        source = HttpDIDDocumentSource()
        doc = await source.get_by_reference("file:///etc/passwd")
        assert doc is None

    async def test_ssrf_reject_data(self) -> None:
        source = HttpDIDDocumentSource()
        doc = await source.get_by_reference("data:text/html,<h1>hi</h1>")
        assert doc is None

    async def test_ipfs_gateway_failover(self) -> None:
        call_count = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(500)
            return httpx.Response(200, json=_make_jsonld_response())

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(
            http_client=client,
            ipfs_gateways=["https://gw1.example.com/ipfs/", "https://gw2.example.com/ipfs/"],
        ))
        doc = await source.get_by_reference("ipfs://QmTest123")
        assert doc is not None
