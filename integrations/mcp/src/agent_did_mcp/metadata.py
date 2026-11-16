"""Starlette routes that publish an agent's OAuth client metadata: a Client ID Metadata Document (CIMD) and a JWKS
built from its DID document (``agent_did_sdk.build_client_metadata_document`` / ``build_client_jwks``).

An MCP authorization server that supports CIMD fetches the document at the ``client_id`` URL and checks the client
assertions against its ``jwks``. The routes read the DID document on each request, so a key rotation shows up at once
(authorization servers cache the document: rotate with an overlap).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from agent_did_sdk import AnyDidDocument, build_client_jwks, build_client_metadata_document
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

DidDocumentSource = Callable[[], AnyDidDocument]
"""Returns the agent's current DID document (for example ``lambda: runtime_identity.document``)."""


def client_metadata_routes(
    *,
    client_id: str,
    client_name: str,
    did_document: DidDocumentSource,
    jwks_path: str | None = None,
    client_uri: str | None = None,
    max_age_seconds: int = 300,
) -> list[Route]:
    """Routes serving the CIMD at the path of *client_id* (an ``https`` URL on this app's origin) and, with
    *jwks_path*, the JWKS there (the CIMD then names it in ``jwks_uri`` instead of embedding ``jwks``)."""
    parts = urlsplit(client_id)
    if parts.scheme != "https" or not parts.netloc or not parts.path or parts.query or parts.fragment:
        raise ValueError("client_id must be an https URL with a path and no query or fragment")
    jwks_uri = f"{parts.scheme}://{parts.netloc}{jwks_path}" if jwks_path else None
    cache = {"cache-control": f"public, max-age={max_age_seconds}"}

    def metadata() -> dict[str, Any]:
        return build_client_metadata_document(
            client_id=client_id,
            client_name=client_name,
            did_document=did_document(),
            client_uri=client_uri,
            jwks_uri=jwks_uri,
        )

    async def serve_metadata(_request: Request) -> JSONResponse:
        return JSONResponse(metadata(), headers=cache)

    async def serve_jwks(_request: Request) -> JSONResponse:
        return JSONResponse(build_client_jwks(did_document()), headers=cache)

    routes = [Route(parts.path, serve_metadata, methods=["GET"])]
    if jwks_path:
        routes.append(Route(jwks_path, serve_jwks, methods=["GET"]))
    return routes
