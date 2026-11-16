"""Capability invocations through the middleware, composition with an inner auth (OAuth), DID client assertions and
the CIMD / JWKS routes."""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator, Generator
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
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from agent_did_mcp import (
    AgentDidMcpAuth,
    AgentDidSignatureMiddleware,
    agent_did_assertion_provider,
    client_metadata_routes,
    get_agent_did_principal,
)

BASE = "https://mcp.example.com"
URL = f"{BASE}/mcp"
AS_ISSUER = "https://auth.example.com"
FAR = "2099-01-01T00:00:00Z"
PRIVATE = HttpTargetValidationOptions(allow_private_targets=True)


async def _agent(identity: AgentIdentity, name: str, relationships: list[str] | None = None) -> CreateAgentResult:
    return await identity.create(
        CreateAgentParams(name=name, additional_verification_relationships=relationships or [])  # type: ignore[arg-type]
    )


def _echo_app() -> Starlette:
    async def echo(request: Request) -> JSONResponse:
        principal = get_agent_did_principal(request)
        body = await request.body()
        return JSONResponse(
            {
                "did": principal.did if principal else None,
                "capability": principal.capability_id if principal else None,
                "body": body.decode(),
                "authorization": request.headers.get("authorization"),
            }
        )

    return Starlette(routes=[Route("/mcp", echo, methods=["POST"]), Route("/public", echo, methods=["POST"])])


@pytest.mark.asyncio
async def test_a_capability_invocation_passes_and_names_the_capability() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    owner = await _agent(identity, "Owner", ["capabilityDelegation"])
    caller = await _agent(identity, "Caller", ["capabilityInvocation"])
    capability = await identity.client.create_capability(
        invocation_target=URL,
        controller=caller.document.id,
        expires=FAR,
        allowed_action=["POST"],
        verification_method_id=f"{owner.document.id}#key-1",
        signer=LocalKeySigner(owner.agent_private_key),
    )
    roots = {URL: [owner.document.id]}
    wrapped = AgentDidSignatureMiddleware(
        _echo_app(), agent_identity=identity, public_base_url=BASE, root_controllers=roots, require_capability=True
    )

    def auth(with_capability: bool) -> AgentDidMcpAuth:
        return AgentDidMcpAuth(
            agent_identity=identity,
            server_url=URL,
            agent_did=caller.document.id,
            verification_method_id=f"{caller.document.id}#key-1",
            agent_private_key=caller.agent_private_key,
            capability=capability if with_capability else None,
            http_security=PRIVATE,
        )

    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=wrapped), auth=auth(True)) as client:
        response = await client.post(URL, content=b'{"x":1}')
    assert response.status_code == 200
    data = json.loads(response.content)
    assert (data["did"], data["capability"], data["body"]) == (caller.document.id, capability["id"], '{"x":1}')

    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=wrapped), auth=auth(False)) as client:
        refused = await client.post(URL, content=b"{}")
    assert (refused.status_code, json.loads(refused.content)["reason"]) == (403, "capability_required")

    with pytest.raises(ValueError):
        AgentDidSignatureMiddleware(_echo_app(), agent_identity=identity, require_capability=True)


class _BearerThenToken(httpx2.Auth):
    """Stands in for the OAuth provider: a token request to the authorization server, then the request with a token."""

    def sync_auth_flow(self, request: httpx2.Request) -> Generator[httpx2.Request, httpx2.Response, None]:
        raise NotImplementedError

    async def async_auth_flow(self, request: httpx2.Request) -> AsyncGenerator[httpx2.Request, httpx2.Response]:
        token_response = yield httpx2.Request("POST", f"{AS_ISSUER}/token", content=b"grant_type=client_credentials")
        request.headers["authorization"] = f"Bearer {json.loads(token_response.content)['access_token']}"
        yield request


@pytest.mark.asyncio
async def test_only_requests_to_the_mcp_origin_are_signed_after_the_inner_auth() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    agent = await _agent(identity, "Agent")
    seen: list[httpx2.Request] = []
    wrapped = AgentDidSignatureMiddleware(_echo_app(), agent_identity=identity, public_base_url=BASE)
    mcp_transport = httpx2.ASGITransport(app=wrapped)

    class Router(httpx2.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
            seen.append(request)
            if request.url.host == "auth.example.com":
                return httpx2.Response(200, json={"access_token": "t0k"})
            return await mcp_transport.handle_async_request(request)

    auth = AgentDidMcpAuth(
        agent_identity=identity,
        server_url=URL,
        agent_did=agent.document.id,
        verification_method_id=f"{agent.document.id}#key-1",
        agent_private_key=agent.agent_private_key,
        inner=_BearerThenToken(),
        http_security=PRIVATE,
    )
    async with httpx2.AsyncClient(transport=Router(), auth=auth) as client:
        response = await client.post(URL, content=b"{}")

    assert response.status_code == 200
    assert json.loads(response.content)["did"] == agent.document.id
    assert json.loads(response.content)["authorization"] == "Bearer t0k"
    token_request, mcp_request = seen
    assert "signature" not in token_request.headers
    assert "signature" in mcp_request.headers and "agent-did" in mcp_request.headers


@pytest.mark.asyncio
async def test_unprotected_paths_pass_through_and_large_bodies_are_refused() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    wrapped = AgentDidSignatureMiddleware(_echo_app(), agent_identity=identity, max_body_bytes=4)
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=wrapped)) as client:
        public = await client.post(f"{BASE}/public", content=b"{}")
        large = await client.post(URL, content=b"0123456789")
    assert public.status_code == 200 and json.loads(public.content)["did"] is None
    assert (large.status_code, json.loads(large.content)["reason"]) == (413, "body_too_large")


@pytest.mark.asyncio
async def test_the_assertion_provider_signs_a_client_assertion_the_sdk_verifies() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    agent = await _agent(identity, "Agent")
    client_id = "https://agent.example.com/oauth/client.json"
    provider = agent_did_assertion_provider(
        client_id=client_id,
        verification_method_id=f"{agent.document.id}#key-1",
        agent_private_key=agent.agent_private_key,
    )
    assertion = await provider(AS_ISSUER)
    result = await identity.client.verify_client_assertion(
        assertion, issuer=AS_ISSUER, client_id=client_id, did=agent.document.id
    )
    assert result.ok, result.reason
    with pytest.raises(ValueError):
        agent_did_assertion_provider(client_id=client_id, verification_method_id="x")


@pytest.mark.asyncio
async def test_metadata_routes_serve_the_cimd_and_jwks() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    agent = await _agent(identity, "Agent")
    client_id = "https://agent.example.com/oauth/client.json"
    app = Starlette(
        routes=client_metadata_routes(
            client_id=client_id,
            client_name="Agent",
            did_document=lambda: agent.document,
            jwks_path="/oauth/jwks.json",
        )
    )
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app)) as client:
        metadata: dict[str, Any] = json.loads((await client.get(client_id)).content)
        jwks: dict[str, Any] = json.loads((await client.get("https://agent.example.com/oauth/jwks.json")).content)
    assert metadata["client_id"] == client_id
    assert metadata["token_endpoint_auth_method"] == "private_key_jwt"
    assert metadata["jwks_uri"] == "https://agent.example.com/oauth/jwks.json"
    assert jwks["keys"][0]["kid"] == f"{agent.document.id}#key-1"
    with pytest.raises(ValueError):
        client_metadata_routes(
            client_id="http://agent.example.com/c.json", client_name="A", did_document=lambda: agent.document
        )
