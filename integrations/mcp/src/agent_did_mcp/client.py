"""MCP client side: OAuth client credentials with a DID client assertion, and Agent-DID request signatures.

Two independent pieces, usable together:

- :func:`agent_did_assertion_provider` returns the ``assertion_provider`` callback of the ``mcp`` SDK's
  ``PrivateKeyJWTOAuthProvider`` (OAuth Client Credentials extension, ``private_key_jwt``, RFC 7523): each call signs a
  fresh client assertion with the agent's DID key for the authorization server's issuer
  (``agent_did_sdk.create_client_assertion``). :func:`create_agent_did_oauth_provider` builds that provider.
- :class:`AgentDidMcpAuth` is an ``httpx2.Auth`` that signs every request to the MCP server's origin with an Agent-DID
  HTTP Message Signature (RFC-001 §6.5), optionally with a capability (§6.7), after an inner auth (such as the OAuth
  provider) has added its credentials. Requests to other origins (the authorization server) are passed on unsigned.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from typing import Any
from urllib.parse import urlsplit

import httpx2
from agent_did_sdk import (
    AgentIdentity,
    AgentSigner,
    HttpTargetValidationOptions,
    SignHttpRequestParams,
    create_client_assertion,
)
from mcp.client.auth import TokenStorage
from mcp.client.auth.extensions.client_credentials import PrivateKeyJWTOAuthProvider

SIGNATURE_HEADERS = ("signature", "signature-input", "agent-did", "agent-did-capability", "content-digest", "date")
"""Header fields a signature sets; a re-signed request drops the previous values first."""


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port or {"https": 443, "http": 80}.get(scheme)
    return scheme, (parts.hostname or "").lower(), port


def agent_did_assertion_provider(
    *,
    client_id: str,
    verification_method_id: str,
    signer: AgentSigner | None = None,
    agent_private_key: str | None = None,
    lifetime_seconds: int = 60,
) -> Callable[[str], Awaitable[str]]:
    """The ``assertion_provider`` of ``PrivateKeyJWTOAuthProvider``: called with the authorization server's issuer
    (the assertion ``aud``), it returns a client assertion (``iss`` = ``sub`` = *client_id*) signed by the
    ``authentication`` key *verification_method_id* of the agent DID, through *signer* or *agent_private_key*."""
    if (signer is None) == (agent_private_key is None):
        raise ValueError("Pass exactly one of signer or agent_private_key")

    async def provider(audience: str) -> str:
        return await create_client_assertion(
            client_id=client_id,
            issuer=audience,
            verification_method_id=verification_method_id,
            signer=signer,
            agent_private_key=agent_private_key,
            lifetime_seconds=lifetime_seconds,
        )

    return provider


def create_agent_did_oauth_provider(
    *,
    server_url: str,
    client_id: str,
    issuer: str,
    verification_method_id: str,
    storage: TokenStorage,
    signer: AgentSigner | None = None,
    agent_private_key: str | None = None,
    scope: str | None = None,
) -> PrivateKeyJWTOAuthProvider:
    """The ``mcp`` SDK's OAuth client credentials provider (``private_key_jwt``) with DID client assertions.

    *client_id* is the client's identifier at the authorization server *issuer* (a Client ID Metadata Document URL,
    see :func:`agent_did_mcp.client_metadata_routes`, or a pre-registered id). The authorization server must know the
    client's keys: from the metadata document's ``jwks`` / ``jwks_uri`` (``build_client_jwks``) or from the DID
    document (``AgentDidClient.verify_client_assertion``)."""
    return PrivateKeyJWTOAuthProvider(
        server_url=server_url,
        storage=storage,
        client_id=client_id,
        assertion_provider=agent_did_assertion_provider(
            client_id=client_id,
            verification_method_id=verification_method_id,
            signer=signer,
            agent_private_key=agent_private_key,
        ),
        scope=scope,
        issuer=issuer,
    )


class AgentDidMcpAuth(httpx2.Auth):
    """Signs the requests to the MCP server's origin with an Agent-DID HTTP Message Signature.

    *inner* (for example :func:`create_agent_did_oauth_provider`) runs first; each request it sends to the origin of
    *server_url* (the MCP request itself, or its retry with a new token) is signed just before it goes out, so the
    signature is fresh. With *capability* (a capability whose ``controller`` is *agent_did*), the signature covers it
    (``Agent-DID-Capability``) and *verification_method_id* must be a ``capabilityInvocation`` key; otherwise it must be
    an ``assertionMethod`` key. Async clients only (``httpx2.AsyncClient``).
    """

    requires_request_body = True

    def __init__(
        self,
        *,
        agent_identity: AgentIdentity,
        server_url: str,
        agent_did: str,
        verification_method_id: str,
        signer: AgentSigner | None = None,
        agent_private_key: str | None = None,
        capability: dict[str, Any] | None = None,
        inner: httpx2.Auth | None = None,
        http_security: HttpTargetValidationOptions | None = None,
    ) -> None:
        if (signer is None) == (agent_private_key is None):
            raise ValueError("Pass exactly one of signer or agent_private_key")
        self._identity = agent_identity
        self._origin = _origin(server_url)
        self._agent_did = agent_did
        self._key_id = verification_method_id
        self._signer = signer
        self._private_key = agent_private_key
        self._capability = capability
        self._inner = inner
        self._http_security = http_security

    def targets_server(self, request: httpx2.Request) -> bool:
        """Whether *request* goes to the MCP server's origin (and is signed)."""
        return _origin(str(request.url)) == self._origin

    async def sign(self, request: httpx2.Request) -> None:
        """Add (or replace) the Agent-DID signature headers of *request*."""
        body = await request.aread()
        headers = await self._identity.sign_http_request(
            SignHttpRequestParams(
                method=request.method,
                url=str(request.url),
                body=body or None,
                agent_did=self._agent_did,
                verification_method_id=self._key_id,
                signer=self._signer,
                agent_private_key=self._private_key,
                capability=self._capability,
                http_security=self._http_security,
            )
        )
        for name in SIGNATURE_HEADERS:
            if name in request.headers:
                del request.headers[name]
        request.headers.update(headers)

    def sync_auth_flow(self, request: httpx2.Request) -> Generator[httpx2.Request, httpx2.Response, None]:
        raise RuntimeError("AgentDidMcpAuth signs asynchronously: use httpx2.AsyncClient")

    async def async_auth_flow(self, request: httpx2.Request) -> AsyncGenerator[httpx2.Request, httpx2.Response]:
        if self._inner is None:
            if self.targets_server(request):
                await self.sign(request)
            yield request
            return
        flow = self._inner.async_auth_flow(request)
        try:
            outgoing = await flow.__anext__()
            while True:
                if self.targets_server(outgoing):
                    await self.sign(outgoing)
                response = yield outgoing
                outgoing = await flow.asend(response)
        except StopAsyncIteration:
            return
        finally:
            await flow.aclose()
