"""Tests for S3CompatibleDIDDocumentSource."""

from __future__ import annotations

import json

import httpx

from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.resolver.s3_compatible_source import (
    S3CompatibleDIDDocumentSource,
    S3CompatibleDIDDocumentSourceConfig,
)


def _make_document() -> dict[str, object]:
    did = "did:webvh:QmS3Scid:example.com:agents:s3-bot"
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": did,
        "controller": "did:webvh:QmS3Scid:example.com:organizations:ops-root",
        "created": "2026-05-07T00:00:00.000Z",
        "updated": "2026-05-07T00:00:00.000Z",
        "agentMetadata": {
            "name": "S3ResolverBot",
            "version": "1.0.0",
            "coreModelHash": "hash://sha256/model",
            "systemPromptHash": "hash://sha256/prompt",
        },
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:webvh:QmS3Scid:example.com:organizations:ops-root",
                "publicKeyMultibase": "zabc",
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
    }


class TestS3CompatibleDIDDocumentSource:
    async def test_resolve_documents_from_bucket_backed_public_url(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_make_document())

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = S3CompatibleDIDDocumentSource(S3CompatibleDIDDocumentSourceConfig(
            bucket="agent-did-history",
            endpoint="https://objects.example.com",
            http_client=client,
        ))

        loaded = await source.get_by_reference("hash://sha256/s3-doc")

        assert loaded is not None
        assert loaded.id == _make_document()["id"]

    async def test_write_documents_via_presigned_upload_url(self) -> None:
        seen_requests: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(200)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = S3CompatibleDIDDocumentSource(S3CompatibleDIDDocumentSourceConfig(
            bucket="agent-did-history",
            endpoint="https://objects.example.com",
            http_client=client,
            reference_to_write_url=lambda _document_ref, object_key: f"https://upload.example.com/{object_key}?signature=document",
        ))

        await source.store_by_reference(
            "hash://sha256/s3-doc",
            AgentDIDDocument.model_validate(_make_document()),
        )

        assert len(seen_requests) == 1
        assert seen_requests[0].url == "https://upload.example.com/documents/hash%3A%2F%2Fsha256%2Fs3-doc.json?signature=document"
        assert seen_requests[0].method == "PUT"

    async def test_resolve_and_write_did_logs_with_did_log_specific_configuration(self) -> None:
        did_log = json.dumps({"versionId": "1-QmS3Scid", "state": _make_document()})
        seen_requests: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            if request.method == "GET":
                return httpx.Response(200, text=did_log)
            return httpx.Response(201)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = S3CompatibleDIDDocumentSource(S3CompatibleDIDDocumentSourceConfig(
            bucket="agent-did-history",
            endpoint="https://objects.example.com",
            http_client=client,
            did_log_key_prefix="histories",
            did_log_public_base_url="https://cdn.example.com/agent-did-history",
            did_log_reference_to_write_url=lambda _document_ref, object_key: f"https://upload.example.com/{object_key}?signature=history",
            did_log_store_method="POST",
        ))

        loaded = await source.get_did_log_by_reference("history://s3/bot")
        await source.store_did_log_by_reference("history://s3/bot", did_log)

        assert loaded == did_log
        assert [str(request.url) for request in seen_requests] == [
            "https://cdn.example.com/agent-did-history/histories/history%3A%2F%2Fs3%2Fbot.jsonl",
            "https://upload.example.com/histories/history%3A%2F%2Fs3%2Fbot.jsonl?signature=history",
        ]