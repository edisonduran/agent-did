"""Tests for HttpDIDDocumentSource."""

from __future__ import annotations

import json

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

    async def test_store_document_over_http(self) -> None:
        seen_requests: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(204)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(http_client=client))
        from agent_did_sdk.core.types import AgentDIDDocument

        await source.store_by_reference(
            "https://example.com/doc.json",
            AgentDIDDocument.model_validate(_make_jsonld_response()),
        )

        assert len(seen_requests) == 1
        assert seen_requests[0].method == "PUT"
        assert seen_requests[0].headers["content-type"] == "application/json; charset=utf-8"
        assert json.loads(seen_requests[0].content.decode("utf-8"))["id"] == "did:agent:polygon:0xtest"

    async def test_fetch_raw_did_log_with_failover(self) -> None:
        did_log = json.dumps({"versionId": "1-QmHttpScid", "state": _make_jsonld_response()})
        call_count = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(503)
            return httpx.Response(200, text=did_log)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(
            http_client=client,
            reference_to_urls=lambda _ref: [
                "https://resolver-a.example/history/did.jsonl",
                "https://resolver-b.example/history/did.jsonl",
            ],
        ))

        loaded = await source.get_did_log_by_reference("https://example.com/history/did.jsonl")
        assert loaded == did_log
        assert call_count == 2

    async def test_store_raw_did_log_over_http_with_custom_method(self) -> None:
        seen_requests: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(201)

        did_log = json.dumps({"versionId": "1-QmHttpScid", "state": _make_jsonld_response()})
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(
            http_client=client,
            did_log_store_method="POST",
        ))

        await source.store_did_log_by_reference("https://example.com/history/did.jsonl", did_log)

        assert len(seen_requests) == 1
        assert seen_requests[0].method == "POST"
        assert seen_requests[0].headers["content-type"] == "application/jsonl; charset=utf-8"
        assert seen_requests[0].content.decode("utf-8") == did_log
