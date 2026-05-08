"""AWS SigV4-authenticated S3 DID document source built on top of the S3-compatible adapter."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast
from urllib.parse import parse_qsl, quote, unquote, urlsplit

import httpx

from ..core.http_security import HttpTargetValidationOptions
from ..core.types import AgentDIDDocument
from .s3_compatible_source import S3CompatibleDIDDocumentSource, S3CompatibleDIDDocumentSourceConfig


@dataclass
class AwsSigV4S3DIDDocumentSourceConfig:
    bucket: str
    region: str
    access_key_id: str
    secret_access_key: str
    session_token: str | None = None
    service: str = "s3"
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
    now: Callable[[], datetime] | None = None


class _AwsSigV4AsyncClient:
    def __init__(self, config: AwsSigV4S3DIDDocumentSourceConfig) -> None:
        self._config = config
        self._client = config.http_client

    async def get(self, url: str) -> httpx.Response:
        headers = self._sign_request("GET", url, {}, b"")
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
        body_bytes = self._coerce_body_bytes(content)
        signed_headers = self._sign_request(method, url, headers or {}, body_bytes)
        client, should_close = self._acquire_client()
        try:
            return await client.request(method, url, content=content, headers=signed_headers)
        finally:
            if should_close:
                await client.aclose()

    async def aclose(self) -> None:
        return None

    def _acquire_client(self) -> tuple[httpx.AsyncClient, bool]:
        if self._client is not None:
            return self._client, False
        return httpx.AsyncClient(), True

    def _sign_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> dict[str, str]:
        split_url = urlsplit(url)
        amz_date = self._format_amz_date(self._now())
        date_stamp = amz_date[:8]
        payload_hash = hashlib.sha256(body).hexdigest()
        normalized_headers = {
            key.lower(): " ".join(value.strip().split())
            for key, value in headers.items()
        }
        normalized_headers["host"] = split_url.netloc
        normalized_headers["x-amz-date"] = amz_date
        normalized_headers["x-amz-content-sha256"] = payload_hash

        if self._config.session_token:
            normalized_headers["x-amz-security-token"] = self._config.session_token

        canonical_headers = dict(sorted(normalized_headers.items()))
        signed_headers = ";".join(canonical_headers.keys())
        canonical_request = "\n".join([
            method.upper(),
            self._canonical_uri(split_url.path),
            self._canonical_query(split_url.query),
            "\n".join(f"{key}:{value}" for key, value in canonical_headers.items()) + "\n",
            signed_headers,
            payload_hash,
        ])
        scope = f"{date_stamp}/{self._config.region}/{self._config.service}/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ])
        signature = self._signature(date_stamp, string_to_sign)
        canonical_headers["authorization"] = (
            "AWS4-HMAC-SHA256 "
            f"Credential={self._config.access_key_id}/{scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )
        return canonical_headers

    def _signature(self, date_stamp: str, string_to_sign: str) -> str:
        k_date = hmac.new(
            f"AWS4{self._config.secret_access_key}".encode("utf-8"),
            date_stamp.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        k_region = hmac.new(k_date, self._config.region.encode("utf-8"), hashlib.sha256).digest()
        k_service = hmac.new(k_region, self._config.service.encode("utf-8"), hashlib.sha256).digest()
        k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
        return hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    def _now(self) -> datetime:
        if self._config.now is not None:
            return self._config.now().astimezone(timezone.utc)
        return datetime.now(timezone.utc)

    @staticmethod
    def _format_amz_date(value: datetime) -> str:
        return value.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    @staticmethod
    def _canonical_uri(path: str) -> str:
        if not path:
            return "/"
        return "/".join(quote(unquote(segment), safe="-_.~") for segment in path.split("/"))

    @staticmethod
    def _canonical_query(query: str) -> str:
        encoded_pairs = [
            (quote(key, safe="-_.~"), quote(value, safe="-_.~"))
            for key, value in parse_qsl(query, keep_blank_values=True)
        ]
        encoded_pairs.sort()
        return "&".join(f"{key}={value}" for key, value in encoded_pairs)

    @staticmethod
    def _coerce_body_bytes(content: str | bytes | None) -> bytes:
        if content is None:
            return b""
        if isinstance(content, bytes):
            return content
        return content.encode("utf-8")


class AwsSigV4S3DIDDocumentSource:
    """Uses AWS SigV4 request signing on top of the S3-compatible DID document source."""

    def __init__(self, config: AwsSigV4S3DIDDocumentSourceConfig) -> None:
        signed_client = cast(httpx.AsyncClient, _AwsSigV4AsyncClient(config))
        self._source = S3CompatibleDIDDocumentSource(S3CompatibleDIDDocumentSourceConfig(
            bucket=config.bucket,
            endpoint=config.endpoint,
            public_base_url=config.public_base_url,
            did_log_public_base_url=config.did_log_public_base_url,
            key_prefix=config.key_prefix,
            did_log_key_prefix=config.did_log_key_prefix,
            force_path_style=config.force_path_style,
            reference_to_object_key=config.reference_to_object_key,
            reference_to_did_log_object_key=config.reference_to_did_log_object_key,
            reference_to_write_url=config.reference_to_write_url,
            did_log_reference_to_write_url=config.did_log_reference_to_write_url,
            http_client=signed_client,
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