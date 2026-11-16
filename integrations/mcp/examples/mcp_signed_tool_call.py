"""Example: an MCP tool call signed with Agent-DID, verified by the server, which reads the caller's DID.

Runs in process: a real ``MCPServer`` (Streamable HTTP) wrapped by ``AgentDidSignatureMiddleware`` and a real
``mcp`` client whose ``httpx2`` client signs each request with ``AgentDidMcpAuth``. In production the server runs
under an ASGI server (uvicorn) and the client adds ``create_agent_did_oauth_provider(...)`` as ``inner`` when the
MCP server requires OAuth.

Usage:
    python -m examples.mcp_signed_tool_call
"""

from __future__ import annotations

import asyncio

import httpx2
from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    HttpTargetValidationOptions,
    InMemoryAgentRegistry,
    LocalKeySigner,
)
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import Context, MCPServer

from agent_did_mcp import AgentDidMcpAuth, AgentDidSignatureMiddleware, get_agent_did_principal

BASE = "https://mcp.example.com"


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    # --- Server: an MCP server whose tool knows which agent DID called it ---
    server_identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    server = MCPServer("whoami")

    @server.tool()
    def whoami(ctx: Context) -> str:  # type: ignore[type-arg]
        principal = get_agent_did_principal(ctx)
        return "anonymous" if principal is None else f"Hello {principal.did}"

    app = server.streamable_http_app(stateless_http=True, json_response=True, host="mcp.example.com")
    protected = AgentDidSignatureMiddleware(app, agent_identity=server_identity, public_base_url=BASE)

    # --- Client: an agent with its own DID ---
    client_identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    agent = await client_identity.create(CreateAgentParams(name="CallerAgent", core_model="m", system_prompt="p"))
    auth = AgentDidMcpAuth(
        agent_identity=client_identity,
        server_url=f"{BASE}/mcp",
        agent_did=agent.document.id,
        verification_method_id=f"{agent.document.id}#key-1",
        agent_private_key=agent.agent_private_key,
        # in process only: the ASGI transport has no public address
        http_security=HttpTargetValidationOptions(allow_private_targets=True),
    )

    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=protected), auth=auth) as http_client:
            async with streamable_http_client(f"{BASE}/mcp", http_client=http_client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    result = await session.call_tool("whoami", {})
    print(result.content[0].text)  # type: ignore[union-attr]


if __name__ == "__main__":
    asyncio.run(main())
