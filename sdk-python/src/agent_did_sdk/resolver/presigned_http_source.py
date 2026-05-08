"""Presigned/object-storage style DID document source over HTTP(S)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import httpx

from ..core.http_security import HttpTargetValidationOptions
from ..core.types import AgentDIDDocument
from .http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig


@dataclass
class PresignedHttpDIDDocumentSourceConfig:
    reference_to_read_url: Callable[[str], str] | None = None
    reference_to_read_urls: Callable[[str], list[str]] | None = None
    did_log_reference_to_read_url: Callable[[str], str] | None = None
    did_log_reference_to_read_urls: Callable[[str], list[str]] | None = None
    reference_to_write_url: Callable[[str], str] | None = None
    did_log_reference_to_write_url: Callable[[str], str] | None = None
    http_client: httpx.AsyncClient | None = None
    ipfs_gateways: list[str] | None = None
    http_security: HttpTargetValidationOptions | None = None
    store_method: str = "PUT"
    did_log_store_method: str | None = None


class PresignedHttpDIDDocumentSource:
    """Splits public read URLs from upload/write URLs for object-store style backends."""

    def __init__(self, config: PresignedHttpDIDDocumentSourceConfig | None = None) -> None:
        cfg = config or PresignedHttpDIDDocumentSourceConfig()
        fallback_read_url = cfg.reference_to_read_url or cfg.reference_to_write_url or (lambda ref: ref)
        fallback_did_log_read_url = (
            cfg.did_log_reference_to_read_url
            or cfg.reference_to_read_url
            or cfg.did_log_reference_to_write_url
            or cfg.reference_to_write_url
            or (lambda ref: ref)
        )
        fallback_write_url = cfg.reference_to_write_url or cfg.reference_to_read_url or (lambda ref: ref)
        fallback_did_log_write_url = (
            cfg.did_log_reference_to_write_url
            or cfg.reference_to_write_url
            or cfg.reference_to_read_url
            or (lambda ref: ref)
        )

        self._document_read_source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(
            reference_to_url=fallback_read_url,
            reference_to_urls=cfg.reference_to_read_urls,
            http_client=cfg.http_client,
            ipfs_gateways=cfg.ipfs_gateways,
            http_security=cfg.http_security,
        ))
        self._did_log_read_source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(
            reference_to_url=fallback_did_log_read_url,
            reference_to_urls=cfg.did_log_reference_to_read_urls or cfg.reference_to_read_urls,
            http_client=cfg.http_client,
            ipfs_gateways=cfg.ipfs_gateways,
            http_security=cfg.http_security,
        ))
        self._document_write_source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(
            reference_to_url=fallback_write_url,
            http_client=cfg.http_client,
            http_security=cfg.http_security,
            store_method=cfg.store_method,
        ))
        self._did_log_write_source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(
            reference_to_url=fallback_did_log_write_url,
            http_client=cfg.http_client,
            http_security=cfg.http_security,
            store_method=cfg.store_method,
            did_log_store_method=cfg.did_log_store_method,
        ))

    async def get_by_reference(self, document_ref: str) -> AgentDIDDocument | None:
        return await self._document_read_source.get_by_reference(document_ref)

    async def store_by_reference(self, document_ref: str, document: AgentDIDDocument) -> None:
        await self._document_write_source.store_by_reference(document_ref, document)

    async def get_did_log_by_reference(self, document_ref: str) -> str | None:
        return await self._did_log_read_source.get_did_log_by_reference(document_ref)

    async def store_did_log_by_reference(self, document_ref: str, did_log: str) -> None:
        await self._did_log_write_source.store_did_log_by_reference(document_ref, did_log)
