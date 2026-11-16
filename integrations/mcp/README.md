# Agent-DID × Model Context Protocol (MCP) Integration

> **Design:** [ADR-008](../../docs/ADR-008-Delegation-OAuth-and-MCP.md) (D-12c, D-12d)

Agent-DID for MCP clients and servers that use the Streamable HTTP transport, built on the official [`mcp` Python SDK](https://pypi.org/project/mcp/) (2.x). An agent authenticates to an MCP authorization server with a JWT client assertion signed by its DID key, and can sign every MCP request so the server learns which agent DID sent it.

This package works alongside MCP authorization (OAuth 2.1), not instead of it. It is aligned with the MCP authorization specification and its OAuth Client Credentials extension; it is **not** verified against an MCP conformance suite.

## What it provides

| Piece | Side | What it does |
|---|---|---|
| `create_agent_did_oauth_provider(...)` | client | The `mcp` SDK's `PrivateKeyJWTOAuthProvider` (client credentials, `private_key_jwt`, RFC 7523) with a fresh DID client assertion per token request (`agent_did_sdk.create_client_assertion`) |
| `agent_did_assertion_provider(...)` | client | The `assertion_provider` callback alone, for your own provider setup |
| `AgentDidMcpAuth` | client | An `httpx2.Auth` that signs each request to the MCP server's origin with an Agent-DID HTTP Message Signature (RFC-001 §6.5), optionally with a capability (§6.7), after an `inner` auth (the OAuth provider) has added its token. Requests to other origins (the authorization server) are not signed |
| `AgentDidSignatureMiddleware` | server | An ASGI middleware for any app (for example `MCPServer.streamable_http_app()`): verifies the signature, or the capability invocation, of each request under `protected_paths` and answers `401` (`403` for `capability_required`, `413` for `body_too_large`) with the reason |
| `get_agent_did_principal(ctx)` | server | In a tool handler: the verified `AgentDidPrincipal` (`did`, `key_id`, `controllers`, `capability_id`, `allowed_action`…) |
| `client_metadata_routes(...)` | client's web host | Starlette routes that serve a Client ID Metadata Document (CIMD) and a JWKS built from the DID document |

## Installation

Requires Python 3.11+ (the `mcp` 2.x SDK depends on `httpx2`, which needs 3.11).

```bash
cd sdk-python && python -m pip install -e ".[dev]"
cd ../integrations/mcp && python -m pip install -e ".[dev]"
```

## Server: verify the calling agent

```python
from mcp.server.mcpserver import Context, MCPServer
from agent_did_mcp import AgentDidSignatureMiddleware, get_agent_did_principal

server = MCPServer("files")

@server.tool()
def whoami(ctx: Context) -> str:
    principal = get_agent_did_principal(ctx)
    return principal.did if principal else "anonymous"

app = AgentDidSignatureMiddleware(
    server.streamable_http_app(),
    agent_identity=identity,                     # an AgentIdentity whose client resolves DIDs
    public_base_url="https://mcp.example.com",   # the origin clients sign for (behind a proxy)
    allowed_dids=["did:webvh:…:agents:caller"],  # or allowed_controllers=[...]
)
```

A valid signature proves which DID sent the request, not what it may do: restrict senders with `allowed_dids` / `allowed_controllers`, or require a capability (`root_controllers={"https://mcp.example.com/mcp": [owner_did]}, require_capability=True`). The middleware reads at most `max_body_bytes` (1 MiB) of each body to check `Content-Digest`. Bearer tokens are still checked by the MCP server's own authorization.

## Client: OAuth token plus signed requests

```python
import httpx2
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from agent_did_mcp import AgentDidMcpAuth, create_agent_did_oauth_provider

oauth = create_agent_did_oauth_provider(
    server_url="https://mcp.example.com/mcp",
    client_id="https://agent.example.com/oauth/client.json",  # CIMD URL, or a pre-registered id
    issuer="https://auth.example.com",                          # the authorization server's issuer
    verification_method_id=f"{did}#key-1",                     # an `authentication` key
    agent_private_key=private_key_hex,                          # or signer=<KMS / HSM AgentSigner>
    storage=token_storage,
)
auth = AgentDidMcpAuth(
    agent_identity=identity,
    server_url="https://mcp.example.com/mcp",
    agent_did=did,
    verification_method_id=f"{did}#key-1",                     # an `assertionMethod` key
    agent_private_key=private_key_hex,
    inner=oauth,
)
async with httpx2.AsyncClient(auth=auth) as http_client:
    async with streamable_http_client("https://mcp.example.com/mcp", http_client=http_client) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            await session.call_tool("whoami", {})
```

The authorization server must know the client's keys. With CIMD it fetches the `client_id` URL: serve it with `client_metadata_routes(client_id=..., client_name=..., did_document=lambda: runtime.document, jwks_path="/oauth/jwks.json")`, and serve it again after a key rotation (authorization servers cache it). An authorization server that knows Agent-DID can instead check the assertion against the DID document with `AgentDidClient.verify_client_assertion`.

With a capability, pass `capability=` (a capability whose `controller` is the agent DID) and a `capabilityInvocation` key as `verification_method_id`.

## Example

```bash
python -m examples.mcp_signed_tool_call
```

A real `mcp` client calls a tool on a real `MCPServer` in process; the tool answers with the caller's verified DID.

## Limits

- Streamable HTTP only: stdio has no HTTP request to sign.
- Python only; a TypeScript MCP integration is planned after 1.0 (ADR-008).
- The middleware verifies requests; it does not sign responses.
- No claim of conformance with the MCP specification: the tests run the official `mcp` SDK client and server in process.

## Tests

```bash
python -m pytest tests -q        # from integrations/mcp
npm run test:mcp                 # from the repository root
```
