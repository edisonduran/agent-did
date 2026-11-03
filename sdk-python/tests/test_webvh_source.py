"""Tests for WebvhDIDDocumentSource (parity: sdk/tests/WebvhDIDDocumentSource.test.ts)."""

from __future__ import annotations

import json

import httpx
import pytest

from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.resolver.types import DocumentIntegrityError
from agent_did_sdk.resolver.webvh_source import WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig
from agent_did_sdk.webvh.adapter import update_did_webvh_log

from .webvh_helpers import TEST_CONTROLLER_KEY, create_agent_webvh_log, tamper_last_state

URL = "https://example.com/agents/webvh-bot/did.jsonl"


def _source(body: str, status: int = 200, **config: object) -> WebvhDIDDocumentSource:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return WebvhDIDDocumentSource(WebvhDIDDocumentSourceConfig(http_client=client, **config))  # type: ignore[arg-type]


class TestWebvhDIDDocumentSource:
    async def test_verifies_the_log_and_returns_the_latest_state(self) -> None:
        created = await create_agent_webvh_log("example.com", ["agents", "webvh-bot"])
        updated = await update_did_webvh_log(
            log=created.log,
            signer=LocalKeySigner(TEST_CONTROLLER_KEY),
            document={**created.state, "updated": "2026-01-02T00:00:00Z"},
            updated="2026-01-02T00:00:00Z",
        )

        doc = await _source(updated.log).get_by_reference(URL)

        assert doc is not None
        assert doc.id == created.did
        assert doc.updated == "2026-01-02T00:00:00Z"

    async def test_rejects_a_log_that_fails_verification(self) -> None:
        created = await create_agent_webvh_log("example.com", ["agents", "webvh-bot"])
        tampered = tamper_last_state(
            created.log, lambda state: state.__setitem__("controller", "did:webvh:QmAttacker:attacker.example")
        )
        with pytest.raises(DocumentIntegrityError):
            await _source(tampered).get_by_reference(URL)

    async def test_rejects_a_log_in_the_pre_v1_format(self) -> None:
        created = await create_agent_webvh_log("example.com", ["agents", "webvh-bot"])
        legacy = json.dumps({"versionId": f"1-{created.metadata.scid}", "state": created.state})
        with pytest.raises(DocumentIntegrityError):
            await _source(legacy).get_by_reference(URL)

    async def test_rejects_a_verified_state_that_is_not_an_agent_document(self) -> None:
        from agent_did_sdk.webvh.adapter import DID_WEBVH_PLACEHOLDER, create_did_webvh_log

        created = await create_did_webvh_log(
            domain="example.com",
            document={"@context": ["https://www.w3.org/ns/did/v1"], "id": DID_WEBVH_PLACEHOLDER},
            signer=LocalKeySigner(TEST_CONTROLLER_KEY),
            created="2026-01-01T00:00:00Z",
        )
        with pytest.raises(DocumentIntegrityError):
            await _source(created.log).get_by_reference(URL)

    async def test_returns_the_raw_log_text(self) -> None:
        created = await create_agent_webvh_log("example.com", ["agents", "webvh-bot"])
        assert await _source(created.log).get_did_log_by_reference(URL) == created.log

    async def test_404_returns_none(self) -> None:
        source = _source("", status=404)
        assert await source.get_by_reference("https://example.com/.well-known/did.jsonl") is None
        assert await source.get_did_log_by_reference("https://example.com/.well-known/did.jsonl") is None

    async def test_candidate_urls_fail_over_until_success(self) -> None:
        created = await create_agent_webvh_log("example.com", ["agents", "webvh-bot"])
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
            return httpx.Response(200, text=created.log)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = WebvhDIDDocumentSource(
            WebvhDIDDocumentSourceConfig(http_client=client, reference_to_urls=lambda _ref: candidate_urls)
        )
        doc = await source.get_by_reference(URL)

        assert doc is not None
        assert doc.id == created.did
        assert requested_urls == candidate_urls

    async def test_raises_when_every_endpoint_fails(self) -> None:
        with pytest.raises(RuntimeError, match="HTTP 503"):
            await _source("", status=503).get_did_log_by_reference(URL)

    async def test_store_is_not_supported(self) -> None:
        with pytest.raises(NotImplementedError):
            await _source("").store_did_log_by_reference(URL, "")
