"""Universal resolver with cache, registry lookup, document-source fetch and fallback."""

from __future__ import annotations

import time
from urllib.parse import quote, unquote, urlparse

from ..core.types import AgentDIDDocument
from ..crypto.hash import generate_canonical_document_hash
from ..webvh.adapter import DidWebvhError, derive_did_webvh_log_url, resolve_did_webvh_log
from .http_source import HttpDIDDocumentSource
from .types import (
    DocumentIntegrityError,
    ResolverCacheStats,
    ResolverResolutionEvent,
    UniversalResolverConfig,
)
from .webvh_source import WebvhDIDDocumentSource

_SHA256_DOCUMENT_REF_PREFIX = "hash://sha256/"


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
        max_entries = config.max_cache_entries
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
            raise TypeError("max_cache_entries must be a positive integer")
        self._max_cache_entries = max_entries
        self._on_event = config.on_resolution_event
        self._unverified_schemes = frozenset(
            scheme.lower() for scheme in (config.unverified_document_ref_schemes or [])
        )
        self._cache: dict[str, _CachedDocument] = {}
        self._hits = 0
        self._misses = 0

    # -- DIDResolver interface ------------------------------------------------

    def register_document(self, document: AgentDIDDocument) -> None:
        did = document.id
        clone = document.model_copy(deep=True)
        self._cache_put(did, clone, self._now_ms() + self._cache_ttl_ms)

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
            # Most recently used goes last, so eviction drops the least recently used first.
            self._cache[did] = self._cache.pop(did)
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

        # Only availability failures (source error, document missing) may fall back.
        # Integrity failures below raise and never degrade to another source.
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
            raise self._integrity_failure(
                did, f"Resolved document DID mismatch. Expected {did}, got {resolved.id}", started
            )

        self._assert_document_matches_reference(did, record.document_ref, resolved, started)

        self._emit(did, "source-fetched", started)
        self._cache_put(did, resolved.model_copy(deep=True), now + self._cache_ttl_ms)
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

    def _cache_put(self, did: str, document: AgentDIDDocument, expires_at: float) -> None:
        """Store ``document`` (already a copy), keeping the cache within ``max_cache_entries``."""
        self._cache.pop(did, None)
        self._cache[did] = _CachedDocument(document, expires_at)
        if len(self._cache) <= self._max_cache_entries:
            return
        now = self._now_ms()
        for key in [key for key, entry in self._cache.items() if entry.expires_at <= now]:
            del self._cache[key]
        while len(self._cache) > self._max_cache_entries:
            del self._cache[next(iter(self._cache))]

    async def _fallback_resolve(self, did: str, error_message: str, started: float) -> AgentDIDDocument:
        if self._fallback is None:
            self._emit(did, "error", started, message=error_message)
            raise ValueError(error_message)
        self._emit(did, "fallback", started, message=error_message)
        doc = await self._fallback.resolve(did)
        clone = doc.model_copy(deep=True)
        self._cache_put(did, clone, self._now_ms() + self._cache_ttl_ms)
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
        self._cache_put(did, resolved.model_copy(deep=True), now + self._cache_ttl_ms)
        self._emit(did, "resolved", started)
        return resolved.model_copy(deep=True)

    async def _resolve_did_webvh(self, did: str, started: float, now: float) -> AgentDIDDocument:
        """Fetch ``did.jsonl`` from the URL derived from the DID, verify it, return the latest state.

        Only availability failures (fetch error, log not found) may fall back; an invalid DID, a log
        that fails verification or a deactivated DID never does.
        """
        try:
            log_url = derive_did_webvh_log_url(did)
        except DidWebvhError as exc:
            self._emit(did, "error", started, message=str(exc))
            raise

        get_log = getattr(self._webvh_source, "get_did_log_by_reference", None)
        if not callable(get_log):
            msg = (
                "webvh_document_source must implement get_did_log_by_reference: "
                "did:webvh logs are verified, never trusted as plain documents"
            )
            self._emit(did, "error", started, message=msg)
            raise TypeError(msg)

        self._emit(did, "source-fetch", started, message=f"url={log_url}")
        try:
            log_text = await get_log(log_url)
        except Exception as exc:  # noqa: BLE001 - availability failure, may fall back
            msg = str(exc)
            self._emit(did, "error", started, message=msg)
            return await self._fallback_resolve(did, msg, started)

        if log_text is None:
            return await self._fallback_resolve(did, f"DID log not found for did:webvh URL: {log_url}", started)

        try:
            resolved = await resolve_did_webvh_log(log_text, did=did)
        except DidWebvhError as exc:
            raise self._integrity_failure(did, f"did:webvh log verification failed for {did}: {exc}", started) from None

        if resolved.metadata.deactivated:
            msg = f"DID is deactivated: {did}"
            self._emit(did, "error", started, message=msg)
            raise ValueError(msg)

        try:
            document = AgentDIDDocument.model_validate(resolved.state)
        except ValueError as exc:
            raise self._integrity_failure(
                did, f"did:webvh state for {did} is not an Agent-DID document: {exc}", started
            ) from None

        self._emit(did, "source-fetched", started, message=f"versionId={resolved.metadata.version_id}")
        self._cache_put(did, document.model_copy(deep=True), now + self._cache_ttl_ms)
        self._emit(did, "resolved", started)
        return document.model_copy(deep=True)

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

    @staticmethod
    def _decode_did_wba_segment(segment: str, segment_type: str) -> str:
        try:
            return unquote(segment)
        except Exception as exc:
            raise ValueError(f"Invalid did:wba {segment_type} segment: {segment}") from exc

    @staticmethod
    def _now_ms() -> float:
        return time.time() * 1000

    def _assert_document_matches_reference(
        self, did: str, document_ref: str, document: AgentDIDDocument, started: float
    ) -> None:
        if not document_ref.startswith(_SHA256_DOCUMENT_REF_PREFIX):
            scheme = document_ref.split("://", 1)[0].lower()
            if "://" in document_ref and scheme in self._unverified_schemes:
                self._emit(
                    did,
                    "source-fetched",
                    started,
                    message=f"integrity=unverified scheme={scheme} documentRef={document_ref}",
                )
                return
            raise self._integrity_failure(
                did,
                f"Unsupported documentRef scheme for {did}: {document_ref}. "
                f"Only {_SHA256_DOCUMENT_REF_PREFIX} references can be verified.",
                started,
            )

        computed_ref = self._compute_ref(document)
        if computed_ref != document_ref.lower():
            raise self._integrity_failure(
                did,
                f"Document integrity check failed for {did}: registry documentRef={document_ref}, "
                f"fetched document hashes to {computed_ref}",
                started,
            )

    def _integrity_failure(self, did: str, message: str, started: float) -> DocumentIntegrityError:
        self._emit(did, "error", started, message=message)
        return DocumentIntegrityError(message)

    @staticmethod
    def _compute_ref(document: AgentDIDDocument) -> str:
        return generate_canonical_document_hash(document.model_dump_jsonld())
