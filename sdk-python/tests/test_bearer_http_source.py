"""Tests for BearerTokenHttpDIDDocumentSource."""

from __future__ import annotations

import json

import httpx

from agent_did_sdk.resolver.bearer_http_source import (
    BearerTokenHttpDIDDocumentSource,
    BearerTokenHttpDIDDocumentSourceConfig,
)


def _make_document() -> dict[str, object]:
    did = "did:webvh:QmBearerScid:example.com:agents:bearer-bot"
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": did,
        "controller": "did:webvh:QmBearerScid:example.com:organizations:ops-root",
        "created": "2026-05-07T00:00:00.000Z",
        "updated": "2026-05-07T00:00:00.000Z",
        "agentMetadata": {
            "name": "BearerResolverBot",
            "version": "1.0.0",
            "coreModelHash": "hash://sha256/model",
            "systemPromptHash": "hash://sha256/prompt",
        },
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:webvh:QmBearerScid:example.com:organizations:ops-root",
                "publicKeyMultibase": "zabc",
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
    }


class TestBearerTokenHttpDIDDocumentSource:
    async def test_injects_bearer_authorization_on_reads(self) -> None:
        seen_requests: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(200, json=_make_document())

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = BearerTokenHttpDIDDocumentSource(BearerTokenHttpDIDDocumentSourceConfig(
            token="secret-token",
            http_client=client,
            reference_to_url=lambda document_ref: f"https://secured.example/{document_ref.replace(':', '_')}.json",
        ))

        loaded = await source.get_by_reference("hash://sha256/bearer-doc")

        assert loaded is not None
        assert loaded.id == _make_document()["id"]
        assert len(seen_requests) == 1
        assert seen_requests[0].headers["authorization"] == "Bearer secret-token"

    async def test_injects_auth_on_did_log_writes_and_merges_content_type(self) -> None:
        seen_requests: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(200)

        async def get_token() -> str:
            return "refreshed-token"

        did_log = json.dumps({"versionId": "1-QmBearerScid", "state": _make_document()})
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = BearerTokenHttpDIDDocumentSource(BearerTokenHttpDIDDocumentSourceConfig(
            get_token=get_token,
            http_client=client,
            reference_to_url=lambda document_ref: f"https://secured.example/{document_ref.replace(':', '_')}.jsonl",
            did_log_store_method="POST",
        ))

        await source.store_did_log_by_reference("history://bearer/bot", did_log)

        assert len(seen_requests) == 1
        assert seen_requests[0].method == "POST"
        assert seen_requests[0].headers["authorization"] == "Bearer refreshed-token"
        assert seen_requests[0].headers["content-type"] == "application/jsonl; charset=utf-8"
        assert seen_requests[0].content.decode("utf-8") == did_log