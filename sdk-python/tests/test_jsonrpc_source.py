"""Tests for JsonRpcDIDDocumentSource."""

from __future__ import annotations

import httpx
import pytest

from agent_did_sdk.resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig


def _make_jsonld() -> dict:
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": "did:agent:polygon:0xtest",
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
                "id": "did:agent:polygon:0xtest#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:ethr:0xcontroller",
                "publicKeyMultibase": "z1234",
            }
        ],
        "authentication": ["did:agent:polygon:0xtest#key-1"],
    }


class TestJsonRpcDIDDocumentSource:
    async def test_resolve_success(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": _make_jsonld()})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(
            endpoint="https://rpc.example.com",
            http_client=client,
        ))
        doc = await source.get_by_reference("hash://sha256/abc")
        assert doc is not None
        assert doc.id == "did:agent:polygon:0xtest"

    async def test_not_found_code(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32004, "message": "not found"}},
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(
            endpoint="https://rpc.example.com",
            http_client=client,
        ))
        doc = await source.get_by_reference("hash://sha256/missing")
        assert doc is None

    async def test_failover(self) -> None:
        call_count = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(500)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": _make_jsonld()})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(
            endpoints=["https://rpc1.example.com", "https://rpc2.example.com"],
            http_client=client,
        ))
        doc = await source.get_by_reference("hash://sha256/abc")
        assert doc is not None

    async def test_an_endpoint_blocked_by_policy_is_an_error_not_a_missing_document(self) -> None:
        source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(
            endpoints=["file:///etc/passwd", "http://10.0.0.5/rpc"],
        ))
        with pytest.raises(RuntimeError, match="Failed to resolve DID document via JSON-RPC endpoints"):
            await source.get_by_reference("hash://sha256/abc")

    async def test_a_blocked_endpoint_next_to_one_answering_not_found_is_an_error(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": 404, "message": "nf"}})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(
            endpoints=["http://10.0.0.5/rpc", "https://rpc.example.com"],
            http_client=client,
        ))
        with pytest.raises(RuntimeError, match="10.0.0.5"):
            await source.get_by_reference("hash://sha256/abc")
        await client.aclose()

    def test_no_endpoint_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one endpoint"):
            JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig())
