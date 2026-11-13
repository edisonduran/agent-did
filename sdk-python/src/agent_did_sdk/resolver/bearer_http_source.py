"""Authenticated HTTP DID document source using Bearer or custom token headers."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlsplit

import httpx

from ..core.http_security import HttpTargetValidationOptions
from ..core.safe_client import create_safe_client
from ..core.types import AgentDIDDocument
from .http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin_of(url: str) -> str | None:
    """``scheme://host[:port]`` of an http(s) URL, lowercased and without a default port, or ``None``."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    host = f"[{host}]" if ":" in host else host.lower()
    return f"{scheme}://{host}" if port is None or port == _DEFAULT_PORTS[scheme] else f"{scheme}://{host}:{port}"


def _normalize_allowed_origins(origins: list[str] | None) -> frozenset[str]:
    if not origins:
        raise TypeError(
            "BearerTokenHttpDIDDocumentSource requires allowed_origins: the origins the credential may be sent to"
        )
    normalized = set()
    for entry in origins:
        origin = _origin_of(entry)
        if origin is None:
            raise TypeError(f"allowed_origins entry is not an http(s) origin: {entry}")
        normalized.add(origin)
    return frozenset(normalized)


@dataclass
class BearerTokenHttpDIDDocumentSourceConfig:
    allowed_origins: list[str] | None = None
    """Origins (``https://storage.example.com``, port included when it is not the default) the credential may be
    sent to. Required and non-empty: a request to any other origin is refused before the token is resolved, so a
    source that is also given URLs derived from a DID (``wba_document_source``, ``webvh_document_source``) cannot
    hand the token to the DID's host."""
    token: str | None = None
    get_token: Callable[[], str | Awaitable[str]] | None = None
    header_name: str = "authorization"
    scheme: str = "Bearer"
    reference_to_url: Callable[[str], str] | None = None
    reference_to_urls: Callable[[str], list[str]] | None = None
    http_client: httpx.AsyncClient | None = None
    ipfs_gateways: list[str] | None = None
    http_security: HttpTargetValidationOptions | None = None
    store_method: str = "PUT"
    did_log_store_method: str | None = None


class _BearerAuthAsyncClient:
    def __init__(self, config: BearerTokenHttpDIDDocumentSourceConfig) -> None:
        self._config = config
        self._client = config.http_client
        self._allowed_origins = _normalize_allowed_origins(config.allowed_origins)

    async def get(self, url: str) -> httpx.Response:
        self._assert_allowed(url)
        headers = await self._build_headers({})
        client, should_close = self._acquire_client()
        try:
            return await client.get(url, headers=headers)
        finally:
            if should_close:
                await client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        content: str | bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        self._assert_allowed(url)
        merged_headers = await self._build_headers(headers or {})
        client, should_close = self._acquire_client()
        try:
            return await client.request(method, url, content=content, headers=merged_headers)
        finally:
            if should_close:
                await client.aclose()

    async def aclose(self) -> None:
        return None

    def _assert_allowed(self, url: str) -> None:
        origin = _origin_of(url)
        if origin is None or origin not in self._allowed_origins:
            raise RuntimeError(
                "BearerTokenHttpDIDDocumentSource refuses to send credentials to "
                f"{origin or 'an invalid URL'}: not in allowed_origins"
            )

    def _acquire_client(self) -> tuple[httpx.AsyncClient, bool]:
        if self._client is not None:
            return self._client, False
        return create_safe_client(self._config.http_security), True

    async def _build_headers(self, headers: dict[str, str]) -> dict[str, str]:
        token = await self._resolve_token()
        merged = {key.lower(): value for key, value in headers.items()}
        merged[self._config.header_name.lower()] = self._format_token(token)
        return merged

    async def _resolve_token(self) -> str:
        if self._config.get_token is not None:
            resolved = self._config.get_token()
            token = await resolved if inspect.isawaitable(resolved) else resolved
            if not token:
                raise RuntimeError("BearerTokenHttpDIDDocumentSource received an empty token from get_token")
            return token

        if not self._config.token:
            raise RuntimeError("BearerTokenHttpDIDDocumentSource requires token or get_token")

        return self._config.token

    def _format_token(self, token: str) -> str:
        return f"{self._config.scheme} {token}" if self._config.scheme else token


class BearerTokenHttpDIDDocumentSource:
    """Wraps HttpDIDDocumentSource with Bearer/custom token header injection."""

    def __init__(self, config: BearerTokenHttpDIDDocumentSourceConfig) -> None:
        auth_client = cast(httpx.AsyncClient, _BearerAuthAsyncClient(config))
        self._source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(
            reference_to_url=config.reference_to_url,
            reference_to_urls=config.reference_to_urls,
            http_client=auth_client,
            ipfs_gateways=config.ipfs_gateways,
            http_security=config.http_security,
            store_method=config.store_method,
            did_log_store_method=config.did_log_store_method,
        ))

    async def get_by_reference(self, document_ref: str) -> AgentDIDDocument | None:
        return await self._source.get_by_reference(document_ref)

    async def store_by_reference(self, document_ref: str, document: AgentDIDDocument) -> None:
        await self._source.store_by_reference(document_ref, document)

    async def get_did_log_by_reference(self, document_ref: str) -> str | None:
        return await self._source.get_did_log_by_reference(document_ref)

    async def store_did_log_by_reference(self, document_ref: str, did_log: str) -> None:
        await self._source.store_did_log_by_reference(document_ref, did_log)
