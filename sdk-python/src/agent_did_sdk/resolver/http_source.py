"""HTTP-based DID document source with SSRF protection and IPFS gateway failover."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from ..core.http_security import HttpTargetValidationOptions, validate_http_target
from ..core.types import AgentDIDDocument


@dataclass
class HttpDIDDocumentSourceConfig:
    reference_to_url: Callable[[str], str] | None = None
    reference_to_urls: Callable[[str], list[str]] | None = None
    http_client: httpx.AsyncClient | None = None
    ipfs_gateways: list[str] | None = None
    http_security: HttpTargetValidationOptions | None = None
    store_method: str = "PUT"
    did_log_store_method: str | None = None


_DEFAULT_IPFS_GATEWAYS = [
    "https://cloudflare-ipfs.com/ipfs/",
    "https://ipfs.io/ipfs/",
]


class HttpDIDDocumentSource:
    """Fetches DID documents over HTTP(S) with SSRF protection and IPFS fallback."""

    def __init__(self, config: HttpDIDDocumentSourceConfig | None = None) -> None:
        cfg = config or HttpDIDDocumentSourceConfig()
        self._reference_to_url = cfg.reference_to_url or (lambda ref: ref)
        self._reference_to_urls = cfg.reference_to_urls
        self._client = cfg.http_client
        self._ipfs_gateways = cfg.ipfs_gateways or list(_DEFAULT_IPFS_GATEWAYS)
        self._http_security = cfg.http_security or HttpTargetValidationOptions()
        self._store_method = cfg.store_method.upper()
        self._did_log_store_method = (cfg.did_log_store_method or cfg.store_method).upper()

    async def get_by_reference(self, document_ref: str) -> AgentDIDDocument | None:
        urls = self._resolve_candidate_urls(document_ref)
        errors: list[str] = []
        all_not_found = True

        for url in urls:
            try:
                validate_http_target(url, self._http_security)
            except ValueError as ve:
                errors.append(f"{url}: {ve}")
                continue

            try:
                client = self._client or httpx.AsyncClient()
                try:
                    response = await client.get(url)
                finally:
                    if self._client is None:
                        await client.aclose()

                if 200 <= response.status_code < 300:
                    return AgentDIDDocument.model_validate(response.json())

                if response.status_code != 404:
                    all_not_found = False
                    errors.append(f"{url}: HTTP {response.status_code}")
            except Exception as exc:
                all_not_found = False
                errors.append(f"{url}: {exc}")

        if all_not_found:
            return None

        raise RuntimeError(f"Failed to fetch DID document from all endpoints. {' | '.join(errors)}")

    async def store_by_reference(self, document_ref: str, document: AgentDIDDocument) -> None:
        await self._write_reference(
            self._resolve_primary_url(document_ref),
            json.dumps(document.model_dump(by_alias=True, exclude_none=True)),
            self._store_method,
            "application/json; charset=utf-8",
        )

    async def get_did_log_by_reference(self, document_ref: str) -> str | None:
        urls = self._resolve_candidate_urls(document_ref)
        errors: list[str] = []
        all_not_found = True

        for url in urls:
            try:
                validate_http_target(url, self._http_security)
            except ValueError as ve:
                errors.append(f"{url}: {ve}")
                continue

            try:
                client = self._client or httpx.AsyncClient()
                try:
                    response = await client.get(url)
                finally:
                    if self._client is None:
                        await client.aclose()

                if 200 <= response.status_code < 300:
                    return response.text

                if response.status_code != 404:
                    all_not_found = False
                    errors.append(f"{url}: HTTP {response.status_code}")
            except Exception as exc:
                all_not_found = False
                errors.append(f"{url}: {exc}")

        if all_not_found:
            return None

        raise RuntimeError(f"Failed to fetch did:webvh DID log from all endpoints. {' | '.join(errors)}")

    async def store_did_log_by_reference(self, document_ref: str, did_log: str) -> None:
        await self._write_reference(
            self._resolve_primary_url(document_ref),
            did_log,
            self._did_log_store_method,
            "application/jsonl; charset=utf-8",
        )

    def _resolve_candidate_urls(self, document_ref: str) -> list[str]:
        if self._reference_to_urls:
            return self._reference_to_urls(document_ref)

        if document_ref.startswith("ipfs://"):
            cid_path = document_ref[len("ipfs://"):].lstrip("/")
            return [f"{gw.rstrip('/')}/{cid_path}" for gw in self._ipfs_gateways]

        return [self._reference_to_url(document_ref)]

    def _resolve_primary_url(self, document_ref: str) -> str:
        urls = self._resolve_candidate_urls(document_ref)
        if not urls:
            raise RuntimeError(f"No HTTP target candidates configured for reference: {document_ref}")
        return urls[0]

    async def _write_reference(self, url: str, body: str, method: str, content_type: str) -> None:
        try:
            validate_http_target(url, self._http_security)
        except ValueError as ve:
            raise RuntimeError(f"{url}: {ve}") from ve

        client = self._client or httpx.AsyncClient()
        try:
            response = await client.request(
                method,
                url,
                content=body,
                headers={"content-type": content_type},
            )
        finally:
            if self._client is None:
                await client.aclose()

        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"Failed to write remote DID content. {url}: HTTP {response.status_code}")
