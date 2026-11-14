"""Security edge-case tests — SSRF protection and invalid inputs."""

from __future__ import annotations

import httpx
import pytest

from agent_did_sdk.resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from agent_did_sdk.resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig


class TestHttpSourceSSRF:
    async def test_reject_file_protocol(self) -> None:
        source = HttpDIDDocumentSource()
        with pytest.raises(RuntimeError):
            await source.get_by_reference("file:///etc/passwd")

    async def test_reject_data_protocol(self) -> None:
        source = HttpDIDDocumentSource()
        with pytest.raises(RuntimeError):
            await source.get_by_reference("data:text/html,<h1>evil</h1>")

    async def test_accept_https(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(http_client=client))
        result = await source.get_by_reference("https://example.com/doc.json")
        assert result is None  # 404 is expected, but protocol was accepted


class TestJsonRpcSourceSSRF:
    async def test_reject_file_protocol(self) -> None:
        source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(
            endpoints=["file:///etc/passwd"],
        ))
        with pytest.raises(RuntimeError, match="Failed to resolve DID document via JSON-RPC endpoints"):
            await source.get_by_reference("hash://sha256/abc")

    async def test_reject_javascript(self) -> None:
        source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(
            endpoints=["javascript:alert(1)"],
        ))
        with pytest.raises(RuntimeError, match="Failed to resolve DID document via JSON-RPC endpoints"):
            await source.get_by_reference("hash://sha256/abc")

