"""Authenticated HTTP DID document source using Bearer or custom token headers."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import cast

import httpx

from ..core.types import AgentDIDDocument
from .http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig


@dataclass
class BearerTokenHttpDIDDocumentSourceConfig:
    token: str | None = None
    get_token: Callable[[], str | Awaitable[str]] | None = None
    header_name: str = "authorization"
    scheme: str = "Bearer"
    reference_to_url: Callable[[str], str] | None = None
    reference_to_urls: Callable[[str], list[str]] | None = None
    http_client: httpx.AsyncClient | None = None
    ipfs_gateways: list[str] | None = None
    http_security = None
    store_method: str = "PUT"
    did_log_store_method: str | None = None


class _BearerAuthAsyncClient:
    def __init__(self, config: BearerTokenHttpDIDDocumentSourceConfig) -> None:
        self._config = config
        self._client = config.http_client

    async def get(self, url: str) -> httpx.Response:
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
        merged_headers = await self._build_headers(headers or {})
        client, should_close = self._acquire_client()
        try:
            return await client.request(method, url, content=content, headers=merged_headers)
        finally:
            if should_close:
                await client.aclose()

    async def aclose(self) -> None:
        return None

    def _acquire_client(self) -> tuple[httpx.AsyncClient, bool]:
        if self._client is not None:
            return self._client, False
        return httpx.AsyncClient(), True

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
