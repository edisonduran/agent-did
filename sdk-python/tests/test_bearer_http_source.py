"""Tests for BearerTokenHttpDIDDocumentSource."""

from __future__ import annotations

import json

import httpx
import pytest

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
            allowed_origins=["https://secured.example"],
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
            allowed_origins=["https://secured.example"],
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


class TestBearerHttpSecurity:
    async def test_http_security_can_be_passed_to_the_constructor(self) -> None:
        from agent_did_sdk.core.http_security import HttpTargetValidationOptions

        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, json=_make_document())

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        url = "http://10.0.0.5/agents/bearer-bot.json"

        blocked = BearerTokenHttpDIDDocumentSource(BearerTokenHttpDIDDocumentSourceConfig(
            allowed_origins=["http://10.0.0.5"],
            token="t", reference_to_url=lambda ref: url, http_client=client,
        ))
        with pytest.raises(RuntimeError, match="private/reserved"):
            await blocked.get_by_reference("ref")
        assert seen == []

        allowed = BearerTokenHttpDIDDocumentSource(BearerTokenHttpDIDDocumentSourceConfig(
            allowed_origins=["http://10.0.0.5"],
            token="t",
            reference_to_url=lambda ref: url,
            http_client=client,
            http_security=HttpTargetValidationOptions(allow_private_targets=True),
        ))
        assert await allowed.get_by_reference("ref") is not None
        assert seen == [url]
        await client.aclose()


class TestBearerAllowedOrigins:
    async def test_refuses_an_origin_outside_allowed_origins_before_resolving_the_token(self) -> None:
        seen: list[str] = []
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, json=_make_document())

        def get_token() -> str:
            calls.append(1)
            return "secret-token"

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = BearerTokenHttpDIDDocumentSource(BearerTokenHttpDIDDocumentSourceConfig(
            allowed_origins=["https://Secured.Example:443/ignored-path"],
            get_token=get_token,
            http_client=client,
        ))

        with pytest.raises(RuntimeError, match="refuses to send credentials to https://attacker.example"):
            await source.get_did_log_by_reference("https://attacker.example/agents/bot/did.jsonl")
        with pytest.raises(RuntimeError, match="not in allowed_origins"):
            await source.get_by_reference("https://secured.example:8443/doc.json")
        assert calls == []
        assert seen == []

        assert await source.get_by_reference("https://secured.example/doc.json") is not None
        assert seen == ["https://secured.example/doc.json"]
        await client.aclose()

    def test_requires_a_non_empty_list_of_http_origins(self) -> None:
        with pytest.raises(TypeError, match="requires allowed_origins"):
            BearerTokenHttpDIDDocumentSource(BearerTokenHttpDIDDocumentSourceConfig(token="t"))
        with pytest.raises(TypeError, match="requires allowed_origins"):
            BearerTokenHttpDIDDocumentSource(BearerTokenHttpDIDDocumentSourceConfig(token="t", allowed_origins=[]))
        with pytest.raises(TypeError, match="not an http"):
            BearerTokenHttpDIDDocumentSource(
                BearerTokenHttpDIDDocumentSourceConfig(token="t", allowed_origins=["ftp://x.example"])
            )
