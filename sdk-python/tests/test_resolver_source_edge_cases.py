"""Edge cases of the DID document sources that the resolver tests do not reach (C-QA-2).

TypeScript parity: sdk/tests/ResolverSourceEdgeCases.test.ts and the edge-case block of
sdk/tests/WebvhDIDDocumentSource.test.ts. Python also covers the paths where a source creates (and closes) its own
SSRF-safe client: ``create_safe_client`` is replaced by a client on an in-process transport.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.resolver import (
    aws_sigv4_s3_source,
    bearer_http_source,
    http_source,
    jsonrpc_source,
    webvh_source,
)
from agent_did_sdk.resolver.aws_sigv4_s3_source import AwsSigV4S3DIDDocumentSource, AwsSigV4S3DIDDocumentSourceConfig
from agent_did_sdk.resolver.bearer_http_source import (
    BearerTokenHttpDIDDocumentSource,
    BearerTokenHttpDIDDocumentSourceConfig,
)
from agent_did_sdk.resolver.file_source import FilesystemDIDDocumentSource, FilesystemDIDDocumentSourceConfig
from agent_did_sdk.resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from agent_did_sdk.resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig
from agent_did_sdk.resolver.s3_compatible_source import (
    S3CompatibleDIDDocumentSource,
    S3CompatibleDIDDocumentSourceConfig,
)
from agent_did_sdk.resolver.webvh_source import WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig

from .test_witnesses import _witnessed_log

DID = "did:webvh:QmEdgeScid:example.com:agents:edge-bot"
DOCUMENT: dict[str, Any] = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
    "id": DID,
    "controller": "did:webvh:QmEdgeScid:example.com:organizations:ops-root",
    "created": "2026-05-06T00:00:00Z",
    "updated": "2026-05-06T00:00:00Z",
    "agentMetadata": {"name": "EdgeBot", "version": "1.0.0"},
    "verificationMethod": [{"id": f"{DID}#key-1", "type": "Multikey", "controller": DID, "publicKeyMultibase": "zabc"}],
    "authentication": [f"{DID}#key-1"],
    "assertionMethod": [f"{DID}#key-1"],
}
URL = "https://dids.example/doc.json"

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture
def own_client(monkeypatch: pytest.MonkeyPatch) -> Callable[[Handler], list[httpx.Request]]:
    """Makes every source build its own client on *handler*; returns the requests it receives."""

    def install(handler: Handler) -> list[httpx.Request]:
        seen: list[httpx.Request] = []

        def recording(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return handler(request)

        for module in (http_source, jsonrpc_source, webvh_source, bearer_http_source, aws_sigv4_s3_source):
            monkeypatch.setattr(module, "create_safe_client", lambda *_args, **_kw: _client(recording))
        return seen

    return install


# --- WebvhDIDDocumentSource ---------------------------------------------------------------------------------------


async def test_webvh_fetches_did_witness_json_and_still_applies_the_document_guard() -> None:
    _signer, _w, created = await _witnessed_log(1, 1)
    files = {
        "https://witness.example/did.jsonl": created.log,
        "https://witness.example/did-witness.json": created.witness_file,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        body = files.get(str(request.url))
        return httpx.Response(200, text=body) if body is not None else httpx.Response(404)

    source = WebvhDIDDocumentSource(WebvhDIDDocumentSourceConfig(http_client=_client(handler)))
    # The witnessed log verifies; its state is a plain controller document, not an Agent-DID document
    with pytest.raises(Exception, match="Agent-DID"):
        await source.get_by_reference("https://witness.example/did.jsonl")
    witness_url = "https://witness.example/did-witness.json"
    assert await source.get_did_witness_file_by_reference(witness_url) == created.witness_file


async def test_webvh_fails_closed_without_did_witness_json_or_a_did_jsonl_name() -> None:
    _signer, _w, created = await _witnessed_log(1, 1)

    def only_log(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=created.log) if str(request.url).endswith("did.jsonl") else httpx.Response(404)

    source = WebvhDIDDocumentSource(WebvhDIDDocumentSourceConfig(http_client=_client(only_log)))
    with pytest.raises(Exception, match="no did-witness.json"):
        await source.get_by_reference("https://witness.example/did.jsonl")

    anywhere = WebvhDIDDocumentSource(
        WebvhDIDDocumentSourceConfig(http_client=_client(lambda _r: httpx.Response(200, text=created.log)))
    )
    with pytest.raises(Exception, match="cannot be located"):
        await anywhere.get_by_reference("https://witness.example/log")


async def test_webvh_reports_blocked_targets_and_network_errors(own_client: Any) -> None:
    blocked = WebvhDIDDocumentSource()
    with pytest.raises(RuntimeError, match="Failed to fetch"):
        await blocked.get_did_log_by_reference("http://127.0.0.1/did.jsonl")

    def failing(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection reset")

    own_client(failing)
    with pytest.raises(RuntimeError, match="connection reset"):
        await WebvhDIDDocumentSource().get_did_log_by_reference("https://example.com/did.jsonl")


# --- HttpDIDDocumentSource --------------------------------------------------------------------------------------


async def test_http_source_with_its_own_client(own_client: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            return httpx.Response(403)
        if str(request.url).endswith(".jsonl"):
            return httpx.Response(404)
        return httpx.Response(200, json=DOCUMENT)

    own_client(handler)
    source = HttpDIDDocumentSource()

    assert (await source.get_by_reference(URL)) is not None
    assert await source.get_did_log_by_reference("https://dids.example/did.jsonl") is None
    with pytest.raises(RuntimeError, match="HTTP 403"):
        await source.store_by_reference(URL, AgentDIDDocument.model_validate(DOCUMENT))


async def test_http_source_refuses_blocked_targets_and_writes_without_a_target() -> None:
    source = HttpDIDDocumentSource()
    with pytest.raises(RuntimeError, match="Failed to fetch"):
        await source.get_did_log_by_reference("http://127.0.0.1/did.jsonl")
    with pytest.raises(RuntimeError):
        await source.store_did_log_by_reference("http://127.0.0.1/did.jsonl", "log")

    no_target = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(reference_to_urls=lambda _ref: []))
    with pytest.raises(RuntimeError, match="No HTTP target candidates"):
        await no_target.store_did_log_by_reference(URL, "log")


# --- JsonRpcDIDDocumentSource -----------------------------------------------------------------------------------


async def test_jsonrpc_with_its_own_client(own_client: Any) -> None:
    replies = iter(
        [
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}},
            {"jsonrpc": "2.0", "id": 1, "result": None},
            "not json",
        ]
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        reply = next(replies)
        return httpx.Response(200, text=reply) if isinstance(reply, str) else httpx.Response(200, json=reply)

    own_client(handler)
    source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(endpoint="https://rpc.example"))

    with pytest.raises(RuntimeError, match="RPC -32000 boom"):
        await source.get_by_reference("ref")
    assert await source.get_by_reference("ref") is None
    with pytest.raises(RuntimeError, match="Failed to resolve"):
        await source.get_by_reference("ref")


async def test_jsonrpc_has_no_did_logs_and_is_read_only() -> None:
    source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(endpoint="https://rpc.example"))
    assert await source.get_did_log_by_reference("ref") is None
    with pytest.raises(NotImplementedError):
        await source.store_did_log_by_reference("ref", "log")


# --- S3-compatible, Bearer and SigV4 sources ------------------------------------------------------------------


async def test_s3_virtual_hosted_urls_and_writes_to_the_read_url() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={})

    source = S3CompatibleDIDDocumentSource(
        S3CompatibleDIDDocumentSourceConfig(
            bucket="agents", endpoint="https://s3.example.com", force_path_style=False, key_prefix="/",
            http_client=_client(handler),
        )
    )
    await source.store_by_reference("ref", AgentDIDDocument.model_validate(DOCUMENT))
    assert seen == ["https://agents.s3.example.com/ref.json"]

    with pytest.raises(RuntimeError, match="Invalid S3-compatible endpoint"):
        S3CompatibleDIDDocumentSource(
            S3CompatibleDIDDocumentSourceConfig(bucket="agents", endpoint="s3.example.com", force_path_style=False)
        )


async def test_bearer_source(own_client: Any) -> None:
    with pytest.raises(TypeError, match="not an http"):
        BearerTokenHttpDIDDocumentSource(
            BearerTokenHttpDIDDocumentSourceConfig(allowed_origins=["https://[bad"], token="t")
        )

    seen = own_client(lambda _request: httpx.Response(200, json=DOCUMENT))
    source = BearerTokenHttpDIDDocumentSource(
        BearerTokenHttpDIDDocumentSourceConfig(allowed_origins=["https://dids.example"], token="t")
    )
    assert await source.get_by_reference(URL) is not None
    await source.store_by_reference(URL, AgentDIDDocument.model_validate(DOCUMENT))
    assert [request.headers["authorization"] for request in seen] == ["Bearer t", "Bearer t"]

    empty = BearerTokenHttpDIDDocumentSource(
        BearerTokenHttpDIDDocumentSourceConfig(allowed_origins=["https://dids.example"], get_token=lambda: "")
    )
    with pytest.raises(RuntimeError, match="empty token"):
        await empty.store_by_reference(URL, AgentDIDDocument.model_validate(DOCUMENT))
    none = BearerTokenHttpDIDDocumentSource(BearerTokenHttpDIDDocumentSourceConfig(allowed_origins=["https://dids.example"]))
    with pytest.raises(RuntimeError, match="requires token or get_token"):
        await none.store_by_reference(URL, AgentDIDDocument.model_validate(DOCUMENT))


async def test_sigv4_source_with_its_own_client(own_client: Any) -> None:
    seen = own_client(lambda _request: httpx.Response(200, text="log"))
    source = AwsSigV4S3DIDDocumentSource(
        AwsSigV4S3DIDDocumentSourceConfig(
            bucket="agent-did-history",
            endpoint="https://s3.us-east-1.amazonaws.com",
            region="us-east-1",
            access_key_id="AKIDEXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        )
    )
    await source.store_by_reference("ref", AgentDIDDocument.model_validate(DOCUMENT))
    assert await source.get_did_log_by_reference("ref") == "log"
    assert all(request.headers["authorization"].startswith("AWS4-HMAC-SHA256 ") for request in seen)
    stamp = datetime.strptime(seen[0].headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - stamp).total_seconds()) < 300


# --- FilesystemDIDDocumentSource ---------------------------------------------------------------------------------


async def test_filesystem_reports_unreadable_files_and_refuses_writes_without_a_path(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{ not json", encoding="utf-8")
    source = FilesystemDIDDocumentSource(
        FilesystemDIDDocumentSourceConfig(reference_to_paths=lambda _ref: [tmp_path / "missing.json", broken])
    )
    with pytest.raises(RuntimeError, match="Failed to read DID document"):
        await source.get_by_reference("ref")

    directory = FilesystemDIDDocumentSource(
        FilesystemDIDDocumentSourceConfig(reference_to_paths=lambda _ref: [tmp_path])
    )
    with pytest.raises(RuntimeError, match="Failed to read did:webvh DID log"):
        await directory.get_did_log_by_reference("ref")

    missing = FilesystemDIDDocumentSource(
        FilesystemDIDDocumentSourceConfig(reference_to_paths=lambda _ref: [tmp_path / "missing.jsonl"])
    )
    assert await missing.get_did_log_by_reference("ref") is None

    nowhere = FilesystemDIDDocumentSource(FilesystemDIDDocumentSourceConfig(reference_to_paths=lambda _ref: []))
    with pytest.raises(RuntimeError, match="No filesystem path candidates"):
        await nowhere.store_did_log_by_reference("ref", "log")


def test_document_constant_is_valid_json() -> None:
    assert json.loads(json.dumps(DOCUMENT))["id"] == DID


def test_sigv4_canonical_uri_of_an_empty_path_and_bytes_bodies() -> None:
    assert aws_sigv4_s3_source._AwsSigV4AsyncClient._canonical_uri("") == "/"
    assert aws_sigv4_s3_source._AwsSigV4AsyncClient._coerce_body_bytes(b"raw") == b"raw"
    assert aws_sigv4_s3_source._AwsSigV4AsyncClient._coerce_body_bytes(None) == b""
