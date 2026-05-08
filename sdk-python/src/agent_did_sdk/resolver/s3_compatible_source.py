"""S3-compatible DID document source built on top of presigned/object-storage HTTP flows."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote

from ..core.http_security import HttpTargetValidationOptions
from ..core.types import AgentDIDDocument
from .presigned_http_source import PresignedHttpDIDDocumentSource, PresignedHttpDIDDocumentSourceConfig

import httpx


@dataclass
class S3CompatibleDIDDocumentSourceConfig:
    bucket: str
    endpoint: str | None = None
    public_base_url: str | None = None
    did_log_public_base_url: str | None = None
    key_prefix: str | None = None
    did_log_key_prefix: str | None = None
    force_path_style: bool = True
    reference_to_object_key: Callable[[str], str] | None = None
    reference_to_did_log_object_key: Callable[[str], str] | None = None
    reference_to_write_url: Callable[[str, str], str] | None = None
    did_log_reference_to_write_url: Callable[[str, str], str] | None = None
    http_client: httpx.AsyncClient | None = None
    http_security: HttpTargetValidationOptions | None = None
    store_method: str = "PUT"
    did_log_store_method: str | None = None


class S3CompatibleDIDDocumentSource:
    """Maps DID references into S3-compatible object keys and presigned/public URLs."""

    def __init__(self, config: S3CompatibleDIDDocumentSourceConfig) -> None:
        self._document_key_resolver = config.reference_to_object_key or (
            lambda document_ref: self._default_object_key(document_ref, config.key_prefix or "documents", ".json")
        )
        self._did_log_key_resolver = config.reference_to_did_log_object_key or (
            lambda document_ref: self._default_object_key(document_ref, config.did_log_key_prefix or "did-logs", ".jsonl")
        )
        self._document_read_base_url = config.public_base_url or self._default_base_url(config)
        self._did_log_read_base_url = config.did_log_public_base_url or self._document_read_base_url
        self._reference_to_write_url = config.reference_to_write_url
        self._did_log_reference_to_write_url = config.did_log_reference_to_write_url

        self._source = PresignedHttpDIDDocumentSource(PresignedHttpDIDDocumentSourceConfig(
            reference_to_read_url=lambda document_ref: self._build_object_url(
                self._document_read_base_url,
                self._document_key_resolver(document_ref),
            ),
            did_log_reference_to_read_url=lambda document_ref: self._build_object_url(
                self._did_log_read_base_url,
                self._did_log_key_resolver(document_ref),
            ),
            reference_to_write_url=lambda document_ref: self._resolve_document_write_url(document_ref),
            did_log_reference_to_write_url=lambda document_ref: self._resolve_did_log_write_url(document_ref),
            http_client=config.http_client,
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

    def _resolve_document_write_url(self, document_ref: str) -> str:
        object_key = self._document_key_resolver(document_ref)
        if self._reference_to_write_url:
            return self._reference_to_write_url(document_ref, object_key)
        return self._build_object_url(self._document_read_base_url, object_key)

    def _resolve_did_log_write_url(self, document_ref: str) -> str:
        object_key = self._did_log_key_resolver(document_ref)
        if self._did_log_reference_to_write_url:
            return self._did_log_reference_to_write_url(document_ref, object_key)
        return self._build_object_url(self._did_log_read_base_url, object_key)

    @staticmethod
    def _default_object_key(document_ref: str, prefix: str, suffix: str) -> str:
        normalized_prefix = prefix.strip("/")
        encoded_ref = quote(document_ref, safe="")
        if normalized_prefix:
            return f"{normalized_prefix}/{encoded_ref}{suffix}"
        return f"{encoded_ref}{suffix}"

    @staticmethod
    def _build_object_url(base_url: str, object_key: str) -> str:
        return f"{base_url.rstrip('/')}/{object_key}"

    @staticmethod
    def _default_base_url(config: S3CompatibleDIDDocumentSourceConfig) -> str:
        endpoint = (config.endpoint or "https://s3.amazonaws.com").rstrip("/")
        bucket = config.bucket.strip("/")

        if config.force_path_style:
            return f"{endpoint}/{bucket}"

        if "://" not in endpoint:
            raise RuntimeError(f"Invalid S3-compatible endpoint: {endpoint}")

        scheme, remainder = endpoint.split("://", 1)
        return f"{scheme}://{bucket}.{remainder}"