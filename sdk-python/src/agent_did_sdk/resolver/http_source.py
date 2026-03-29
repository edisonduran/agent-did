"""HTTP-based DID document source with SSRF protection and IPFS gateway failover."""

from __future__ import annotations

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

    def _resolve_candidate_urls(self, document_ref: str) -> list[str]:
        if self._reference_to_urls:
            return self._reference_to_urls(document_ref)

        if document_ref.startswith("ipfs://"):
            cid_path = document_ref[len("ipfs://"):].lstrip("/")
            return [f"{gw.rstrip('/')}/{cid_path}" for gw in self._ipfs_gateways]

        return [self._reference_to_url(document_ref)]
