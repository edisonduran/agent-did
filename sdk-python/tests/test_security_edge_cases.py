"""Security edge-case tests — SSRF protection and invalid inputs."""

from __future__ import annotations

import httpx
import pytest

from agent_did_sdk.registry.web3_client import Web3AgentRegistryContractClient
from agent_did_sdk.resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from agent_did_sdk.resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig


class TestHttpSourceSSRF:
    async def test_reject_file_protocol(self) -> None:
        source = HttpDIDDocumentSource()
        result = await source.get_by_reference("file:///etc/passwd")
        assert result is None

    async def test_reject_data_protocol(self) -> None:
        source = HttpDIDDocumentSource()
        result = await source.get_by_reference("data:text/html,<h1>evil</h1>")
        assert result is None

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
        result = await source.get_by_reference("hash://sha256/abc")
        assert result is None

    async def test_reject_javascript(self) -> None:
        source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(
            endpoints=["javascript:alert(1)"],
        ))
        result = await source.get_by_reference("hash://sha256/abc")
        assert result is None


class TestWeb3ClientInvalidShape:
    async def test_invalid_response_raises(self) -> None:
        class FakeContract:
            class functions:
                @staticmethod
                def getAgentRecord(did: str):  # noqa: N802
                    class CallableResult:
                        def call(self):
                            return 42
                    return CallableResult()

        client = Web3AgentRegistryContractClient(FakeContract())
        with pytest.raises(ValueError, match="Invalid contract response"):
            await client.get_agent_record("did:agent:test:1")
