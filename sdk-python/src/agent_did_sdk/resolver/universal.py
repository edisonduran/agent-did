"""Universal resolver with cache, registry lookup, document-source fetch and fallback."""

from __future__ import annotations

import time
from urllib.parse import quote, unquote, urlparse

from ..core.types import AgentDIDDocument
from ..crypto.hash import generate_agent_metadata_hash
from .http_source import HttpDIDDocumentSource
from .types import (
    ResolverCacheStats,
    ResolverResolutionEvent,
    UniversalResolverConfig,
)
from .webvh_source import WebvhDIDDocumentSource


class _CachedDocument:
    __slots__ = ("document", "expires_at")

    def __init__(self, document: AgentDIDDocument, expires_at: float) -> None:
        self.document = document
        self.expires_at = expires_at


class UniversalResolverClient:
    """Production-grade resolver: cache → registry → document source → fallback."""

    def __init__(self, config: UniversalResolverConfig) -> None:
        self._registry = config.registry
        self._source = config.document_source
        self._wba_source = config.wba_document_source or HttpDIDDocumentSource()
        self._webvh_source = config.webvh_document_source or WebvhDIDDocumentSource()
        self._fallback = config.fallback_resolver
        self._cache_ttl_ms = config.cache_ttl_ms
        self._on_event = config.on_resolution_event
        self._cache: dict[str, _CachedDocument] = {}
        self._hits = 0
        self._misses = 0

    # -- DIDResolver interface ------------------------------------------------

    def register_document(self, document: AgentDIDDocument) -> None:
        did = document.id
        clone = document.model_copy(deep=True)
        self._cache[did] = _CachedDocument(clone, self._now_ms() + self._cache_ttl_ms)

        store_fn = getattr(self._source, "store_by_reference", None)
        if callable(store_fn):
            doc_ref = self._compute_ref(document)
            # Fire-and-forget; cache already updated
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(store_fn(doc_ref, document.model_copy(deep=True)))
            except RuntimeError:
                pass

    async def resolve(self, did: str) -> AgentDIDDocument:
        started = self._now_ms()
        cached = self._cache.get(did)
        now = self._now_ms()

        if cached and cached.expires_at > now:
            self._hits += 1
            self._emit(did, "cache-hit", started)
            return cached.document.model_copy(deep=True)

        self._misses += 1
        self._emit(did, "cache-miss", started)

        if self._is_did_wba(did):
            return await self._resolve_did_wba(did, started, now)

        if self._is_did_webvh(did):
            return await self._resolve_did_webvh(did, started, now)

        self._emit(did, "registry-lookup", started)

        record = await self._registry.get_record(did)
        if record is None:
            return await self._fallback_resolve(did, f"DID not found in registry: {did}", started)
        if not record.document_ref:
            return await self._fallback_resolve(did, f"Missing documentRef for DID: {did}", started)

        self._emit(did, "source-fetch", started, message=f"documentRef={record.document_ref}")

        try:
            resolved = await self._source.get_by_reference(record.document_ref)
        except Exception as exc:
            msg = str(exc)
            self._emit(did, "error", started, message=msg)
            return await self._fallback_resolve(did, msg, started)

        if resolved is None:
            return await self._fallback_resolve(
                did, f"Document not found for reference: {record.document_ref}", started
            )

        if resolved.id != did:
            raise ValueError(f"Resolved document DID mismatch. Expected {did}, got {resolved.id}")

        self._emit(did, "source-fetched", started)
        self._cache[did] = _CachedDocument(resolved.model_copy(deep=True), now + self._cache_ttl_ms)
        self._emit(did, "resolved", started)
        return resolved.model_copy(deep=True)

    def remove(self, did: str) -> None:
        self._cache.pop(did, None)
        if self._fallback:
            self._fallback.remove(did)

    # -- Extra ----------------------------------------------------------------

    def get_cache_stats(self) -> ResolverCacheStats:
        return ResolverCacheStats(hits=self._hits, misses=self._misses, size=len(self._cache))

    # -- Private helpers ------------------------------------------------------

    async def _fallback_resolve(self, did: str, error_message: str, started: float) -> AgentDIDDocument:
        if self._fallback is None:
            self._emit(did, "error", started, message=error_message)
            raise ValueError(error_message)
        self._emit(did, "fallback", started, message=error_message)
        doc = await self._fallback.resolve(did)
        clone = doc.model_copy(deep=True)
        self._cache[did] = _CachedDocument(clone, self._now_ms() + self._cache_ttl_ms)
        self._emit(did, "resolved", started, message="fallback")
        return doc.model_copy(deep=True)

    async def _resolve_did_wba(self, did: str, started: float, now: float) -> AgentDIDDocument:
        document_url = self._derive_did_wba_document_url(did)
        self._emit(did, "source-fetch", started, message=f"url={document_url}")

        try:
            resolved = await self._wba_source.get_by_reference(document_url)
        except Exception as exc:
            msg = str(exc)
            self._emit(did, "error", started, message=msg)
            return await self._fallback_resolve(did, msg, started)

        if resolved is None:
            return await self._fallback_resolve(did, f"Document not found for did:wba URL: {document_url}", started)

        if resolved.id != did:
            raise ValueError(f"Resolved document DID mismatch. Expected {did}, got {resolved.id}")

        self._emit(did, "source-fetched", started)
        self._cache[did] = _CachedDocument(resolved.model_copy(deep=True), now + self._cache_ttl_ms)
        self._emit(did, "resolved", started)
        return resolved.model_copy(deep=True)

    async def _resolve_did_webvh(self, did: str, started: float, now: float) -> AgentDIDDocument:
        document_url = self._derive_did_webvh_document_url(did)
        self._emit(did, "source-fetch", started, message=f"url={document_url}")

        try:
            resolved = await self._webvh_source.get_by_reference(document_url)
        except Exception as exc:
            msg = str(exc)
            self._emit(did, "error", started, message=msg)
            return await self._fallback_resolve(did, msg, started)

        if resolved is None:
            return await self._fallback_resolve(
                did, f"Document not found for did:webvh URL: {document_url}", started
            )

        if resolved.id != did:
            raise ValueError(f"Resolved document DID mismatch. Expected {did}, got {resolved.id}")

        self._emit(did, "source-fetched", started)
        self._cache[did] = _CachedDocument(resolved.model_copy(deep=True), now + self._cache_ttl_ms)
        self._emit(did, "resolved", started)
        return resolved.model_copy(deep=True)

    def _emit(self, did: str, stage: str, started: float, *, message: str | None = None) -> None:
        if self._on_event:
            self._on_event(ResolverResolutionEvent(
                did=did, stage=stage, duration_ms=self._now_ms() - started, message=message  # type: ignore[arg-type]
            ))

    @staticmethod
    def _is_did_wba(did: str) -> bool:
        return did.startswith("did:wba:")

    @staticmethod
    def _is_did_webvh(did: str) -> bool:
        return did.startswith("did:webvh:")

    def _derive_did_wba_document_url(self, did: str) -> str:
        suffix = did[len("did:wba:"):]
        if not suffix:
            raise ValueError(f"Invalid did:wba DID: {did}")

        domain_segment, *path_segments = suffix.split(":")
        domain = self._decode_did_wba_segment(domain_segment, "domain")
        if not domain:
            raise ValueError(f"Invalid did:wba DID: missing domain in {did}")

        safe_segments = [
            quote(self._decode_did_wba_segment(segment, "path"), safe="")
            for segment in path_segments
            if segment
        ]
        if safe_segments:
            pathname = f"/{'/'.join(safe_segments)}/did.json"
        else:
            pathname = "/.well-known/did.json"

        url = f"https://{domain}{pathname}"
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError(f"Invalid did:wba DID: {did}")

        return url

    def _derive_did_webvh_document_url(self, did: str) -> str:
        suffix = did[len("did:webvh:"):]
        if not suffix:
            raise ValueError(f"Invalid did:webvh DID: {did}")

        scid_segment, *rest = suffix.split(":")
        if not scid_segment:
            raise ValueError(f"Invalid did:webvh DID: missing SCID in {did}")
        if not rest:
            raise ValueError(f"Invalid did:webvh DID: missing domain in {did}")

        domain_segment, *path_segments = rest
        domain = self._decode_did_wba_segment(domain_segment, "domain")
        if not domain:
            raise ValueError(f"Invalid did:webvh DID: missing domain in {did}")

        safe_segments = [
            quote(self._decode_did_wba_segment(segment, "path"), safe="")
            for segment in path_segments
            if segment
        ]
        if safe_segments:
            pathname = f"/{'/'.join(safe_segments)}/did.jsonl"
        else:
            pathname = "/.well-known/did.jsonl"

        url = f"https://{domain}{pathname}"
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError(f"Invalid did:webvh DID: {did}")

        return url

    @staticmethod
    def _decode_did_wba_segment(segment: str, segment_type: str) -> str:
        try:
            return unquote(segment)
        except Exception as exc:
            raise ValueError(f"Invalid did:wba {segment_type} segment: {segment}") from exc

    @staticmethod
    def _now_ms() -> float:
        return time.time() * 1000

    @staticmethod
    def _compute_ref(document: AgentDIDDocument) -> str:
        import json
        return generate_agent_metadata_hash(json.dumps(document.model_dump_jsonld(), sort_keys=True))
