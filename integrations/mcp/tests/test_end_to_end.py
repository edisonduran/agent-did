"""End to end: a real ``mcp`` client and ``MCPServer`` over Streamable HTTP (in process, ASGI), with Agent-DID request
signatures checked by the middleware and the verified DID read by a tool."""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx2
import pytest
from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    CreateAgentResult,
    HttpTargetValidationOptions,
    InMemoryAgentRegistry,
    LocalKeySigner,
)
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import Context, MCPServer
from starlette.types import ASGIApp

from agent_did_mcp import AgentDidMcpAuth, AgentDidSignatureMiddleware, get_agent_did_principal

BASE = "https://mcp.example.com"
URL = f"{BASE}/mcp"


async def _agent(name: str) -> tuple[AgentIdentity, CreateAgentResult]:
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    return identity, await identity.create(CreateAgentParams(name=name, core_model="m", system_prompt="p"))


def _server() -> MCPServer:
    server = MCPServer("whoami")

    @server.tool()
    def whoami(ctx: Context) -> str:  # type: ignore[type-arg]
        principal = get_agent_did_principal(ctx)
        return "anonymous" if principal is None else principal.did

    return server


@contextlib.asynccontextmanager
async def _running(app: Any) -> AsyncIterator[None]:
    async with app.router.lifespan_context(app):
        yield


def _auth(identity: AgentIdentity, runtime: CreateAgentResult) -> AgentDidMcpAuth:
    key_id = (runtime.document.assertion_method or [""])[0]
    return AgentDidMcpAuth(
        agent_identity=identity,
        server_url=URL,
        agent_did=runtime.document.id,
        verification_method_id=key_id,
        agent_private_key=runtime.agent_private_key,
        http_security=HttpTargetValidationOptions(allow_private_targets=True),
    )


async def _call_whoami(wrapped: ASGIApp, auth: httpx2.Auth | None) -> str:
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=wrapped), auth=auth) as http_client:
        async with streamable_http_client(URL, http_client=http_client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                result = await session.call_tool("whoami", {})
    return str(result.content[0].text)  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_a_signed_mcp_session_reaches_the_tool_with_the_verified_did() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    server_identity, _ = await _agent("Server")
    client_identity, client_runtime = await _agent("Client")
    app = _server().streamable_http_app(stateless_http=True, json_response=True, host="mcp.example.com")
    wrapped = AgentDidSignatureMiddleware(app, agent_identity=server_identity, public_base_url=BASE)
    async with _running(app):
        assert await _call_whoami(wrapped, _auth(client_identity, client_runtime)) == client_runtime.document.id


@pytest.mark.asyncio
async def test_an_unsigned_request_is_rejected_with_401() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    server_identity, _ = await _agent("Server")
    app = _server().streamable_http_app(stateless_http=True, json_response=True, host="mcp.example.com")
    wrapped = AgentDidSignatureMiddleware(app, agent_identity=server_identity, public_base_url=BASE)
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=wrapped)) as http_client:
        response = await http_client.post(URL, content=b"{}", headers={"content-type": "application/json"})
    assert response.status_code == 401
    assert json.loads(response.content)["reason"] == "missing_headers"


@pytest.mark.asyncio
async def test_allowed_dids_refuse_other_agents() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    server_identity, _ = await _agent("Server")
    client_identity, client_runtime = await _agent("Client")
    app = _server().streamable_http_app(stateless_http=True, json_response=True, host="mcp.example.com")
    wrapped = AgentDidSignatureMiddleware(
        app, agent_identity=server_identity, public_base_url=BASE, allowed_dids=["did:webvh:Qm:other.example"]
    )
    auth = _auth(client_identity, client_runtime)
    async with _running(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=wrapped), auth=auth) as http_client:
            response = await http_client.post(URL, content=b"{}", headers={"content-type": "application/json"})
    assert response.status_code == 401
    assert json.loads(response.content)["reason"] == "did_not_allowed"
