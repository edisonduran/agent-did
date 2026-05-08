"""Tests for WebvhDIDDocumentSource."""

from __future__ import annotations

import json

import httpx

from agent_did_sdk.resolver.webvh_source import WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig


def _make_webvh_state(did: str = "did:webvh:QmExampleScid:example.com:agents:webvh-bot") -> dict:
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": did,
        "controller": "did:webvh:QmExampleScid:example.com:organizations:acme-support",
        "created": "2026-05-06T00:00:00.000Z",
        "updated": "2026-05-06T00:00:00.000Z",
        "agentMetadata": {
            "name": "WebvhResolverBot",
            "version": "1.0.0",
            "coreModelHash": "hash://sha256/model",
            "systemPromptHash": "hash://sha256/prompt",
        },
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:webvh:QmExampleScid:example.com:organizations:acme-support",
                "publicKeyMultibase": "zabc",
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
    }


class TestWebvhDIDDocumentSource:
    async def test_parses_latest_state_from_did_log(self) -> None:
        latest_state = _make_webvh_state()
        older_state = {**latest_state, "updated": "2026-05-05T00:00:00.000Z"}

        def handler(request: httpx.Request) -> httpx.Response:
            body = "\n".join([
                json.dumps({"versionId": "1-QmExampleScid", "state": older_state}),
                json.dumps({"versionId": "2-QmExampleScid", "state": latest_state}),
            ])
            return httpx.Response(200, text=body)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = WebvhDIDDocumentSource(WebvhDIDDocumentSourceConfig(http_client=client))
        doc = await source.get_by_reference("https://example.com/agents/webvh-bot/did.jsonl")
        assert doc is not None
        assert doc.id == latest_state["id"]
        assert doc.updated == latest_state["updated"]

    async def test_404_returns_none(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = WebvhDIDDocumentSource(WebvhDIDDocumentSourceConfig(http_client=client))
        doc = await source.get_by_reference("https://example.com/.well-known/did.jsonl")
        assert doc is None

    async def test_candidate_urls_fail_over_until_success(self) -> None:
        candidate_urls = [
            "https://primary.example/agents/webvh-bot/did.jsonl",
            "https://secondary.example/agents/webvh-bot/did.jsonl",
            "https://tertiary.example/agents/webvh-bot/did.jsonl",
        ]
        requested_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_urls.append(str(request.url))
            if str(request.url) == candidate_urls[0]:
                return httpx.Response(503)
            if str(request.url) == candidate_urls[1]:
                return httpx.Response(404)
            return httpx.Response(200, text=json.dumps({"versionId": "2-QmExampleScid", "state": _make_webvh_state()}))

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = WebvhDIDDocumentSource(WebvhDIDDocumentSourceConfig(
            http_client=client,
            reference_to_urls=lambda _document_ref: candidate_urls,
        ))
        doc = await source.get_by_reference("https://example.com/agents/webvh-bot/did.jsonl")

        assert doc is not None
        assert doc.id == _make_webvh_state()["id"]
        assert requested_urls == candidate_urls