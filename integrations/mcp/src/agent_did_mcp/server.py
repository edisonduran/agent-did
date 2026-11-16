"""MCP server side: an ASGI middleware that verifies Agent-DID request signatures and names the verified agent.

:class:`AgentDidSignatureMiddleware` wraps any ASGI app (for example ``MCPServer.streamable_http_app()``). For each
HTTP request under ``protected_paths`` it reads the body (up to ``max_body_bytes``), verifies the Agent-DID HTTP
Message Signature (RFC-001 §6.5) or, when the request carries ``Agent-DID-Capability``, the capability invocation
(§6.7), and either answers ``401`` with the rejection reason or passes the request on with the verified
:class:`AgentDidPrincipal` in ``scope["state"]["agent_did"]``. A tool handler reads it with
:func:`get_agent_did_principal` (``ctx.request_context.request.state``).

The signature is checked in addition to whatever authorization the MCP server applies (OAuth bearer tokens): it says
which agent DID sent the request, not what it may do. Authorization stays with the server (``allowed_dids``,
``allowed_controllers``, capabilities).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_did_sdk import AgentIdentity, VerifyHttpRequestSignatureParams
from agent_did_sdk.core.types import VerifyHttpCapabilityInvocationParams
from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_MAX_BODY_BYTES = 1024 * 1024
"""Largest request body the middleware reads to check ``Content-Digest`` (1 MiB)."""

STATE_KEY = "agent_did"
"""Key of the verified :class:`AgentDidPrincipal` in ``scope["state"]``."""


@dataclass(frozen=True)
class AgentDidPrincipal:
    """The agent a verified request comes from."""

    did: str
    key_id: str | None
    controllers: tuple[str, ...] = ()
    capability_id: str | None = None
    """The invoked capability, when the request carried one."""
    allowed_action: tuple[str, ...] | None = None
    root_id: str | None = None
    delegators: tuple[str, ...] = field(default_factory=tuple)


def get_agent_did_principal(source: Any) -> AgentDidPrincipal | None:
    """The verified principal of a request: *source* is an MCP tool ``Context``, a Starlette ``Request`` or an ASGI
    scope. ``None`` when the request did not go through :class:`AgentDidSignatureMiddleware`."""
    request_context = getattr(source, "request_context", None)
    if request_context is not None:
        source = getattr(request_context, "request", None)
    if isinstance(source, dict):
        state = source.get("state") or {}
        principal = state.get(STATE_KEY)
    else:
        principal = getattr(getattr(source, "state", None), STATE_KEY, None)
    return principal if isinstance(principal, AgentDidPrincipal) else None


class AgentDidSignatureMiddleware:
    """Verifies the Agent-DID signature of each HTTP request under *protected_paths* (path prefixes; default
    ``("/mcp",)``) and rejects the others with ``401``.

    *public_base_url* (``https://mcp.example.com``) is the origin clients sign for, when the app runs behind a proxy;
    otherwise the URL is rebuilt from the request (scheme, ``Host``, path, query). *root_controllers* enables
    capability invocations (``Agent-DID-Capability``); *require_capability* refuses requests without one.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        agent_identity: AgentIdentity,
        protected_paths: Sequence[str] = ("/mcp",),
        public_base_url: str | None = None,
        allowed_dids: list[str] | None = None,
        allowed_controllers: list[str] | None = None,
        root_controllers: dict[str, list[str]] | None = None,
        require_capability: bool = False,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ) -> None:
        if require_capability and not root_controllers:
            raise ValueError("require_capability needs root_controllers")
        self.app = app
        self._identity = agent_identity
        self._paths = tuple(protected_paths)
        self._base = public_base_url.rstrip("/") if public_base_url else None
        self._allowed_dids = allowed_dids
        self._allowed_controllers = allowed_controllers
        self._root_controllers = root_controllers
        self._require_capability = require_capability
        self._max_body = max_body_bytes

    def _protected(self, path: str) -> bool:
        return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in self._paths)

    def _url(self, scope: Scope, headers: dict[str, str]) -> str:
        path = scope.get("raw_path", b"").decode("latin-1").split("?", 1)[0] or scope["path"]
        query = scope.get("query_string", b"").decode("latin-1")
        if self._base is not None:
            base = self._base
        else:
            host = headers.get("host")
            if host is None:
                server = scope.get("server") or ("localhost", None)
                host = server[0] if server[1] is None else f"{server[0]}:{server[1]}"
            base = f"{scope.get('scheme', 'http')}://{host}"
        return f"{base}{path}?{query}" if query else f"{base}{path}"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._protected(scope["path"]):
            await self.app(scope, receive, send)
            return
        body = bytearray()
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            more = message.get("more_body", False)
            if len(body) > self._max_body:
                await _reject(send, 413, "body_too_large")
                return
        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope["headers"]}
        principal, reason = await self._verify(scope["method"], self._url(scope, headers), headers, bytes(body))
        if principal is None:
            await _reject(send, 403 if reason == "capability_required" else 401, reason or "signature_invalid")
            return
        scope.setdefault("state", {})[STATE_KEY] = principal
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    async def _verify(
        self, method: str, url: str, headers: dict[str, str], body: bytes
    ) -> tuple[AgentDidPrincipal | None, str | None]:
        common: dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": headers,
            "body": body or None,
            "allowed_dids": self._allowed_dids,
            "allowed_controllers": self._allowed_controllers,
        }
        client = self._identity.client
        try:
            if "agent-did-capability" in headers and self._root_controllers:
                invocation = await client.verify_http_capability_invocation(
                    VerifyHttpCapabilityInvocationParams(**common, root_controllers=self._root_controllers)
                )
                if not invocation.ok or invocation.did is None:
                    return None, invocation.reason
                return (
                    AgentDidPrincipal(
                        did=invocation.did,
                        key_id=invocation.key_id,
                        controllers=tuple(invocation.controllers),
                        capability_id=_capability_id(invocation.capability) or invocation.capability_id,
                        allowed_action=invocation.allowed_action,
                        root_id=invocation.root_id,
                        delegators=tuple(invocation.delegators),
                    ),
                    None,
                )
            if self._require_capability:
                return None, "capability_required"
            result = await client.verify_http_request_signature_detailed(VerifyHttpRequestSignatureParams(**common))
        except Exception:
            return None, "malformed_headers"
        if not result.ok or result.did is None:
            return None, result.reason
        return AgentDidPrincipal(did=result.did, key_id=result.key_id, controllers=tuple(result.controllers)), None


def _capability_id(capability: dict[str, Any] | None) -> str | None:
    value = (capability or {}).get("id")
    return value if isinstance(value, str) else None


async def _reject(send: Send, status: int, reason: str) -> None:
    body = json.dumps({"error": "agent_did_signature_rejected", "reason": reason}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
