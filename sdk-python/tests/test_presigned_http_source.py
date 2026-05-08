"""Tests for PresignedHttpDIDDocumentSource."""

from __future__ import annotations

import json

import httpx

from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.resolver.presigned_http_source import (
    PresignedHttpDIDDocumentSource,
    PresignedHttpDIDDocumentSourceConfig,
)


def _make_document() -> dict[str, object]:
    did = "did:webvh:QmPresignedScid:example.com:agents:presigned-bot"
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": did,
        "controller": "did:webvh:QmPresignedScid:example.com:organizations:ops-root",
        "created": "2026-05-06T00:00:00.000Z",
        "updated": "2026-05-06T00:00:00.000Z",
        "agentMetadata": {
            "name": "PresignedResolverBot",
            "version": "1.0.0",
            "coreModelHash": "hash://sha256/model",
            "systemPromptHash": "hash://sha256/prompt",
        },
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:webvh:QmPresignedScid:example.com:organizations:ops-root",
                "publicKeyMultibase": "zabc",
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
    }


class TestPresignedHttpDIDDocumentSource:
    async def test_resolve_document_via_public_read_url(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_make_document())

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = PresignedHttpDIDDocumentSource(PresignedHttpDIDDocumentSourceConfig(
            http_client=client,
            reference_to_read_url=lambda document_ref: f"https://cdn.example/{document_ref.replace(':', '_')}.json",
        ))

        loaded = await source.get_by_reference("hash://sha256/presigned-doc")

        assert loaded is not None
        assert loaded.id == _make_document()["id"]

    async def test_write_document_via_dedicated_upload_url(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(204)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = PresignedHttpDIDDocumentSource(PresignedHttpDIDDocumentSourceConfig(
            http_client=client,
            reference_to_read_url=(
                lambda document_ref: f"https://cdn.example/{document_ref.replace(':', '_')}.json"
            ),
            reference_to_write_url=(
                lambda document_ref: f"https://upload.example/{document_ref.replace(':', '_')}?signature=document"
            ),
        ))

        await source.store_by_reference(
            "hash://sha256/presigned-doc",
            AgentDIDDocument.model_validate(_make_document()),
        )

        assert len(seen_requests) == 1
        assert seen_requests[0].url == "https://upload.example/hash_//sha256/presigned-doc?signature=document"
        assert seen_requests[0].method == "PUT"

    async def test_write_did_log_via_dedicated_upload_url(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(201)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = PresignedHttpDIDDocumentSource(PresignedHttpDIDDocumentSourceConfig(
            http_client=client,
            reference_to_read_url=(
                lambda document_ref: f"https://cdn.example/{document_ref.replace(':', '_')}.jsonl"
            ),
            reference_to_write_url=(
                lambda document_ref: f"https://upload.example/{document_ref.replace(':', '_')}?signature=document"
            ),
            did_log_reference_to_write_url=(
                lambda document_ref: f"https://upload.example/{document_ref.replace(':', '_')}?signature=history"
            ),
            did_log_store_method="POST",
        ))
        did_log = json.dumps({"versionId": "1-QmPresignedScid", "state": _make_document()})

        await source.store_did_log_by_reference("history://presigned/bot", did_log)

        assert len(seen_requests) == 1
        assert seen_requests[0].url == "https://upload.example/history_//presigned/bot?signature=history"
        assert seen_requests[0].method == "POST"
        assert seen_requests[0].content.decode("utf-8") == did_log

    async def test_fetch_raw_did_log_via_public_read_urls_with_failover(self) -> None:
        did_log = json.dumps({"versionId": "1-QmPresignedScid", "state": _make_document()})
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(503)
            return httpx.Response(200, text=did_log)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = PresignedHttpDIDDocumentSource(PresignedHttpDIDDocumentSourceConfig(
            http_client=client,
            did_log_reference_to_read_urls=lambda document_ref: [
                f"https://cdn-a.example/{document_ref.replace(':', '_')}.jsonl",
                f"https://cdn-b.example/{document_ref.replace(':', '_')}.jsonl",
            ],
        ))

        loaded = await source.get_did_log_by_reference("history://presigned/bot")

        assert loaded == did_log
        assert call_count == 2

    async def test_read_documents_and_did_logs_from_separate_public_urls(self) -> None:
        did_log = json.dumps({"versionId": "1-QmPresignedScid", "state": _make_document()})
        seen_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            if str(request.url).startswith("https://cdn-docs.example/"):
                return httpx.Response(200, json=_make_document())
            return httpx.Response(200, text=did_log)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = PresignedHttpDIDDocumentSource(PresignedHttpDIDDocumentSourceConfig(
            http_client=client,
            reference_to_read_url=(
                lambda document_ref: f"https://cdn-docs.example/{document_ref.replace(':', '_')}.json"
            ),
            did_log_reference_to_read_url=(
                lambda document_ref: f"https://cdn-logs.example/{document_ref.replace(':', '_')}.jsonl"
            ),
        ))

        loaded_document = await source.get_by_reference("hash://sha256/presigned-doc")
        loaded_did_log = await source.get_did_log_by_reference("history://presigned/bot")

        assert loaded_document is not None
        assert loaded_document.id == _make_document()["id"]
        assert loaded_did_log == did_log
        assert seen_urls == [
            "https://cdn-docs.example/hash_//sha256/presigned-doc.json",
            "https://cdn-logs.example/history_//presigned/bot.jsonl",
        ]
