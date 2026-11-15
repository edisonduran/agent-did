"""Universal resolver with cache, registry lookup, document-source fetch and fallback."""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar
from urllib.parse import quote, unquote, urlsplit

from ..core.types import AgentDIDDocument
from ..crypto.hash import generate_canonical_document_hash
from ..webvh.adapter import (
    DidWebvhError,
    DidWebvhLogResult,
    compare_did_webvh_logs,
    derive_did_webvh_log_url,
    did_webvh_last_entry_signers,
    resolve_did_webvh_log,
)
from .http_source import HttpDIDDocumentSource
from .types import (
    DidWebvhResolution,
    DocumentIntegrityError,
    ResolutionLimits,
    ResolverCacheStats,
    ResolverResolutionEvent,
    UniversalResolverConfig,
)
from .webvh_source import WebvhDIDDocumentSource

_SHA256_DOCUMENT_REF_PREFIX = "hash://sha256/"

_T = TypeVar("_T")


class _FetchCapacityError(ValueError):
    """A resolution refused because the resolver is busy (the fetch queue is full, or no slot freed up before the
    deadline). It says nothing about the DID, so it is not remembered in the negative cache."""


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TypeError(f"{name} must be a positive integer")
    return value


def _consume_exception(task: asyncio.Future[Any]) -> None:
    """Mark a fetch's exception as retrieved when its caller stopped waiting at the deadline."""
    if not task.cancelled():
        task.exception()


# did:wba host grammar (parity: sdk/src/resolver/UniversalResolverClient.ts). After percent-decoding, the domain
# segment must be a DNS name with an optional port: ASCII letters, digits and hyphens in dot-separated labels.
# IP literals are rejected (did:web, which did:wba builds on, excludes them), and so is a numeric last label, which a
# URL parser would read as an IPv4 address.
_DID_WBA_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_DID_WBA_NUMERIC_LABEL = re.compile(r"0x[0-9a-f]*|[0-9]+", re.IGNORECASE)
_DID_WBA_PORT = re.compile(r"[1-9][0-9]{0,4}")
# Characters a path segment keeps unencoded: RFC 3986 unreserved.
_DID_WBA_UNRESERVED = "-._~"


def _parse_did_wba_domain(domain: str) -> tuple[str, int | None] | None:
    """Split a decoded did:wba domain into a lowercase host and a port (None for the default), or None if invalid."""
    host, separator, port_text = domain.partition(":")
    port: int | None = None
    if separator:
        if not _DID_WBA_PORT.fullmatch(port_text) or int(port_text) > 65535:
            return None
        port = int(port_text)
    labels = host.split(".")
    if len(host) > 253 or not all(_DID_WBA_LABEL.fullmatch(label) for label in labels):
        return None
    if _DID_WBA_NUMERIC_LABEL.fullmatch(labels[-1]):
        return None
    return host.lower(), (None if port == 443 else port)


def _derive_did_wba_document_url(did: str) -> str:
    """The HTTPS URL of a did:wba DID's ``did.json``. The URL is built from validated parts and parsed again, so
    the host, port and path that are fetched are exactly the ones derived from the DID."""
    suffix = did[len("did:wba:"):]
    if not did.startswith("did:wba:") or not suffix:
        raise ValueError(f"Invalid did:wba DID: {did}")

    domain_segment, *path_segments = suffix.split(":")
    try:
        domain = unquote(domain_segment, errors="strict")
    except UnicodeDecodeError:
        domain = None
    if domain == "":
        raise ValueError(f"Invalid did:wba DID: missing domain in {did}")
    parsed_domain = None if domain is None else _parse_did_wba_domain(domain)
    if parsed_domain is None:
        raise ValueError(f"Invalid did:wba domain segment: {domain_segment}")
    host, port = parsed_domain

    decoded_segments = [_decode_did_wba_path_segment(segment) for segment in path_segments if segment]
    if any(segment in (".", "..") for segment in decoded_segments):
        raise ValueError(f"Invalid did:wba DID: dot path segment in {did}")
    if decoded_segments:
        pathname = "/" + "/".join(quote(segment, safe=_DID_WBA_UNRESERVED) for segment in decoded_segments)
        pathname += "/did.json"
    else:
        pathname = "/.well-known/did.json"

    authority = host if port is None else f"{host}:{port}"
    url = f"https://{authority}{pathname}"

    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname != host
        or parts.port != port
        or parts.username is not None
        or parts.password is not None
        or parts.path != pathname
        or parts.query
        or parts.fragment
    ):
        raise ValueError(f"Invalid did:wba DID: {did}")
    return url


def _decode_did_wba_path_segment(segment: str) -> str:
    try:
        return unquote(segment, errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Invalid did:wba path segment: {segment}") from exc


def _host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    """*host* is listed, or a subdomain of a ``*.``-prefixed entry."""
    normalized = host.lower()
    for entry in allowed_hosts:
        if entry.startswith("*."):
            if normalized.endswith(entry[1:]) and len(normalized) > len(entry) - 1:
                return True
        elif normalized == entry:
            return True
    return False


class _CachedDocument:
    __slots__ = ("deactivated", "document", "expires_at", "webvh")

    def __init__(
        self,
        document: AgentDIDDocument,
        expires_at: float,
        webvh: DidWebvhResolution | None = None,
        deactivated: bool = False,
    ) -> None:
        self.document = document
        self.expires_at = expires_at
        self.webvh = webvh
        # The did:webvh log ends in a deactivation entry: ``resolve`` raises, ``resolve_did_webvh_log`` returns it.
        self.deactivated = deactivated


class UniversalResolverClient:
    """Production-grade resolver: cache → registry → document source → fallback."""

    def __init__(self, config: UniversalResolverConfig) -> None:
        self._registry = config.registry
        self._source = config.document_source
        self._wba_source = config.wba_document_source or HttpDIDDocumentSource()
        self._webvh_source = config.webvh_document_source or WebvhDIDDocumentSource()
        self._fallback = config.fallback_resolver
        self._did_webvh_local_log = config.did_webvh_local_log
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
        limits = config.resolution_limits or ResolutionLimits()
        ttl = limits.negative_cache_ttl_ms
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0:
            raise TypeError("negative_cache_ttl_ms must be a non-negative integer")
        self._negative_cache_ttl_ms = ttl
        self._max_concurrent_fetches = _positive_int(limits.max_concurrent_fetches, "max_concurrent_fetches")
        self._max_concurrent_fetches_per_host = _positive_int(
            limits.max_concurrent_fetches_per_host, "max_concurrent_fetches_per_host"
        )
        queued = limits.max_queued_fetches
        if isinstance(queued, bool) or not isinstance(queued, int) or queued < 0:
            raise TypeError("max_queued_fetches must be a non-negative integer")
        self._max_queued_fetches = queued
        self._fetch_deadline_ms = _positive_int(limits.fetch_deadline_ms, "fetch_deadline_ms")
        self._active_fetches = 0
        self._active_fetches_by_host: dict[str, int] = {}
        # Fetches waiting for a slot, oldest first: (host, future set when the slot is handed over)
        self._fetch_queue: list[tuple[str, asyncio.Future[None]]] = []
        self._allowed_hosts: list[str] | None = None
        if limits.allowed_hosts is not None:
            if any(not isinstance(host, str) or not host.strip() for host in limits.allowed_hosts):
                raise TypeError("allowed_hosts must be a list of host names")
            self._allowed_hosts = [host.strip().lower() for host in limits.allowed_hosts]
        # Recent did:webvh / did:wba failures, raised again without fetching until they expire
        self._negative_cache: dict[str, tuple[BaseException, float]] = {}
        # Fetches in progress, shared by concurrent resolutions of the same DID
        self._in_flight: dict[str, asyncio.Future[Any]] = {}
        self._store_tasks: set[asyncio.Task[None]] = set()
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
            # Fire-and-forget; the cache is already updated, so resolution here keeps working. A failed
            # remote write is reported through the resolution event instead of being swallowed.
            started = self._now_ms()
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                self._emit_quietly(did, started, "store_by_reference skipped: no running event loop")
                return

            async def _store() -> None:
                try:
                    await store_fn(doc_ref, document.model_copy(deep=True))
                except Exception as exc:  # noqa: BLE001
                    self._emit_quietly(did, started, f"store_by_reference failed: {exc}")

            task = loop.create_task(_store())
            self._store_tasks.add(task)
            task.add_done_callback(self._store_tasks.discard)

    async def resolve(self, did: str) -> AgentDIDDocument:
        started = self._now_ms()
        cached = self._cache.get(did)
        now = self._now_ms()

        if cached and cached.expires_at > now:
            # Most recently used goes last, so eviction drops the least recently used first.
            self._cache[did] = self._cache.pop(did)
            self._hits += 1
            self._emit(did, "cache-hit", started)
            if cached.deactivated:
                raise self._deactivated_error(did, started)
            return cached.document.model_copy(deep=True)

        self._misses += 1
        self._emit(did, "cache-miss", started)

        if self._is_did_wba(did):
            document = await self._guarded_fetch(did, started, lambda: self._resolve_did_wba(did, started, now))
            return document.model_copy(deep=True)

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

    async def resolve_did_webvh_log(self, did: str) -> DidWebvhResolution | None:
        """The verified did:webvh log behind *did*: from the cache while the entry is fresh, otherwise fetched and
        verified (raising when it cannot be, with no fallback). The log of a deactivated DID is returned with
        ``deactivated=True``. ``None`` when the cached entry holds only a document that was registered without its
        log."""
        if not self._is_did_webvh(did):
            return None
        started = self._now_ms()
        entry = self._cache.get(did)
        if entry is not None and entry.expires_at > started:
            self._cache[did] = self._cache.pop(did)
            self._hits += 1
            self._emit(did, "cache-hit", started)
        else:
            self._misses += 1
            self._emit(did, "cache-miss", started)
            entry = await self._guarded_fetch(did, started, lambda: self._load_did_webvh(did, started, started))
        return entry.webvh

    async def _guarded_fetch(self, did: str, started: float, load: Callable[[], Awaitable[_T]]) -> _T:
        """Run *load* (a did:webvh or did:wba fetch) under the resolution limits: the host allow-list, the negative
        cache, one shared fetch per DID, at most ``max_concurrent_fetches`` fetches at once
        (``max_concurrent_fetches_per_host`` per host), at most ``max_queued_fetches`` waiting, and
        ``fetch_deadline_ms`` for the wait and the fetch together."""
        self._assert_host_allowed(did, started)
        recent = self._negative_cache.get(did)
        if recent is not None and recent[1] > self._now_ms():
            self._emit(did, "error", started, message=f"recent failure: {recent[0]}")
            raise recent[0]
        pending = self._in_flight.get(did)
        if pending is None:
            pending = asyncio.ensure_future(self._run_fetch(did, started, load))
            self._in_flight[did] = pending
            pending.add_done_callback(lambda _: self._in_flight.pop(did, None))
        # shield: a caller that is cancelled does not cancel the fetch the others wait for
        result: _T = await asyncio.shield(pending)
        return result

    async def _run_fetch(self, did: str, started: float, load: Callable[[], Awaitable[_T]]) -> _T:
        try:
            value = await self._with_fetch_slot(self._fetch_host_of(did), load)
        except _FetchCapacityError as exc:
            self._emit(did, "error", started, message=str(exc))
            raise
        except Exception as exc:
            self._remember_failure(did, exc)
            raise
        self._negative_cache.pop(did, None)
        return value

    def _fetch_host_of(self, did: str) -> str:
        """The host name a did:webvh / did:wba DID is fetched from, or "" for a DID that does not derive a URL."""
        try:
            url = derive_did_webvh_log_url(did) if self._is_did_webvh(did) else self._derive_did_wba_document_url(did)
        except (DidWebvhError, ValueError):
            return ""
        return urlsplit(url).hostname or ""

    def _has_fetch_slot(self, host: str) -> bool:
        return (
            self._active_fetches < self._max_concurrent_fetches
            and self._active_fetches_by_host.get(host, 0) < self._max_concurrent_fetches_per_host
        )

    def _take_fetch_slot(self, host: str) -> None:
        self._active_fetches += 1
        self._active_fetches_by_host[host] = self._active_fetches_by_host.get(host, 0) + 1

    def _release_fetch_slot(self, host: str) -> None:
        self._active_fetches -= 1
        count = self._active_fetches_by_host.get(host, 1) - 1
        if count > 0:
            self._active_fetches_by_host[host] = count
        else:
            self._active_fetches_by_host.pop(host, None)
        # Start the oldest waiters whose host has room; a waiter for a busy host does not hold up the others.
        index = 0
        while index < len(self._fetch_queue) and self._active_fetches < self._max_concurrent_fetches:
            waiter_host, started = self._fetch_queue[index]
            if self._has_fetch_slot(waiter_host):
                del self._fetch_queue[index]
                self._take_fetch_slot(waiter_host)
                started.set_result(None)
            else:
                index += 1

    async def _with_fetch_slot(self, host: str, load: Callable[[], Awaitable[_T]]) -> _T:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._fetch_deadline_ms / 1000
        if self._has_fetch_slot(host):
            self._take_fetch_slot(host)
        else:
            if len(self._fetch_queue) >= self._max_queued_fetches:
                raise _FetchCapacityError(
                    "Resolution refused: too many DID fetches are waiting (max_queued_fetches)"
                )
            waiter: tuple[str, asyncio.Future[None]] = (host, loop.create_future())
            self._fetch_queue.append(waiter)
            try:
                await asyncio.wait_for(asyncio.shield(waiter[1]), self._fetch_deadline_ms / 1000)
            except asyncio.TimeoutError:
                if waiter in self._fetch_queue:
                    self._fetch_queue.remove(waiter)
                    raise _FetchCapacityError(
                        f"Resolution refused: no fetch slot freed up within {self._fetch_deadline_ms} ms"
                    ) from None
                # The slot was handed over as the wait timed out: use it.
            except asyncio.CancelledError:
                if waiter in self._fetch_queue:
                    self._fetch_queue.remove(waiter)
                elif waiter[1].done():
                    self._release_fetch_slot(host)
                raise

        # The slot is held until the fetch settles, even when the caller stops waiting at the deadline.
        task = asyncio.ensure_future(load())
        task.add_done_callback(lambda _: self._release_fetch_slot(host))
        task.add_done_callback(_consume_exception)
        try:
            return await asyncio.wait_for(asyncio.shield(task), max(0.0, deadline - loop.time()))
        except asyncio.TimeoutError:
            if task.done():
                return task.result()
            raise ValueError(
                f"DID fetch did not finish within {self._fetch_deadline_ms} ms (fetch_deadline_ms)"
            ) from None

    def _remember_failure(self, did: str, error: BaseException) -> None:
        if self._negative_cache_ttl_ms == 0:
            return
        self._negative_cache.pop(did, None)
        self._negative_cache[did] = (error, self._now_ms() + self._negative_cache_ttl_ms)
        while len(self._negative_cache) > self._max_cache_entries:
            del self._negative_cache[next(iter(self._negative_cache))]

    def _assert_host_allowed(self, did: str, started: float) -> None:
        """Raise before any request when ``allowed_hosts`` is set and the DID's host is not in it."""
        if self._allowed_hosts is None:
            return
        try:
            url = derive_did_webvh_log_url(did) if self._is_did_webvh(did) else self._derive_did_wba_document_url(did)
            host = urlsplit(url).hostname or ""
        except (DidWebvhError, ValueError):
            return  # an invalid DID fails in the fetch itself
        if not _host_allowed(host, self._allowed_hosts):
            msg = f"Resolution of {did} is not allowed: {host} is not in allowed_hosts"
            self._emit(did, "error", started, message=msg)
            raise ValueError(msg)

    def _deactivated_error(self, did: str, started: float) -> ValueError:
        msg = f"DID is deactivated: {did}"
        self._emit(did, "error", started, message=msg)
        return ValueError(msg)

    def remove(self, did: str) -> None:
        self._cache.pop(did, None)
        self._negative_cache.pop(did, None)
        if self._fallback:
            self._fallback.remove(did)

    def evict(self, did: str) -> None:
        """Drop the cached resolution of *did*, including a remembered failure (not the fallback resolver's
        documents): the next resolution fetches."""
        self._cache.pop(did, None)
        self._negative_cache.pop(did, None)

    # -- Extra ----------------------------------------------------------------

    def get_cache_stats(self) -> ResolverCacheStats:
        return ResolverCacheStats(hits=self._hits, misses=self._misses, size=len(self._cache))

    # -- Private helpers ------------------------------------------------------

    def _cache_put(
        self,
        did: str,
        document: AgentDIDDocument,
        expires_at: float,
        webvh: DidWebvhResolution | None = None,
        deactivated: bool = False,
    ) -> None:
        """Store ``document`` (already a copy), keeping the cache within ``max_cache_entries``."""
        self._cache.pop(did, None)
        self._cache[did] = _CachedDocument(document, expires_at, webvh, deactivated)
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

        # Like did:webvh, a did:wba DID is answered only by its own host: no fallback to another resolver, which could
        # keep serving a copy the host has since changed.
        try:
            resolved = await self._wba_source.get_by_reference(document_url)
        except Exception as exc:  # noqa: BLE001 - availability failure: fail closed
            msg = str(exc)
            self._emit(did, "error", started, message=msg)
            raise ValueError(f"did:wba document could not be fetched for {did}: {msg}") from exc

        if resolved is None:
            msg = f"Document not found for did:wba URL: {document_url}"
            self._emit(did, "error", started, message=msg)
            raise ValueError(msg)

        if resolved.id != did:
            raise self._integrity_failure(
                did, f"Resolved document DID mismatch. Expected {did}, got {resolved.id}", started
            )

        self._emit(did, "source-fetched", started)
        self._cache_put(did, resolved.model_copy(deep=True), now + self._cache_ttl_ms)
        self._emit(did, "resolved", started)
        return resolved.model_copy(deep=True)

    async def _resolve_did_webvh(self, did: str, started: float, now: float) -> AgentDIDDocument:
        """Fetch ``did.jsonl`` from the URL derived from the DID, verify it, return the latest state.

        There is no fallback to another resolver: a fetch error, a missing log, an invalid DID, a log that
        fails verification, a log that contradicts the one held locally and a deactivated DID all fail closed.
        """
        entry = await self._guarded_fetch(did, started, lambda: self._load_did_webvh(did, started, now))
        if entry.deactivated:
            raise self._deactivated_error(did, started)
        self._emit(did, "resolved", started)
        return entry.document.model_copy(deep=True)

    async def _load_did_webvh(self, did: str, started: float, now: float) -> _CachedDocument:
        """Fetch, verify and cache the did:webvh log behind *did*, deactivated or not; return the cache entry."""
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
        except Exception as exc:  # noqa: BLE001 - availability failure: fail closed
            msg = str(exc)
            self._emit(did, "error", started, message=msg)
            raise ValueError(f"did:webvh log could not be fetched for {did}: {msg}") from exc

        if log_text is None:
            msg = f"DID log not found for did:webvh URL: {log_url}"
            self._emit(did, "error", started, message=msg)
            raise ValueError(msg)

        try:
            resolved = await resolve_did_webvh_log(log_text, did=did)
        except DidWebvhError as exc:
            raise self._integrity_failure(did, f"did:webvh log verification failed for {did}: {exc}", started) from None

        resolved = await self._reconcile_with_local_log(did, resolved, started)
        deactivated = bool(resolved.metadata.deactivated)

        try:
            document = AgentDIDDocument.model_validate(resolved.state)
        except ValueError as exc:
            raise self._integrity_failure(
                did, f"did:webvh state for {did} is not an Agent-DID document: {exc}", started
            ) from None

        self._emit(did, "source-fetched", started, message=f"versionId={resolved.metadata.version_id}")
        self._cache_put(
            did,
            document.model_copy(deep=True),
            now + self._cache_ttl_ms,
            DidWebvhResolution(
                document=document.model_copy(deep=True),
                log=resolved.log,
                version_id=resolved.metadata.version_id,
                update_keys=list(resolved.metadata.update_keys),
                last_entry_signer_keys=did_webvh_last_entry_signers(resolved.log),
                deactivated=deactivated,
            ),
            deactivated,
        )
        return self._cache[did]

    async def _reconcile_with_local_log(
        self, did: str, fetched: DidWebvhLogResult, started: float
    ) -> DidWebvhLogResult:
        """The longer of the fetched and the locally held log wins; a log that is neither a prefix nor an
        extension of the other is an integrity failure (never a fallback)."""
        lookup = self._did_webvh_local_log
        local = lookup(did) if lookup is not None else None
        if local is None:
            return fetched
        try:
            relation = compare_did_webvh_logs(local, fetched.log)
        except DidWebvhError as exc:
            raise self._integrity_failure(did, f"did:webvh log comparison failed for {did}: {exc}", started) from None
        if relation == "diverged":
            raise self._integrity_failure(
                did,
                f"The did:webvh log fetched for {did} contradicts the log held locally (not a prefix or an extension)",
                started,
            )
        if relation == "prefix":
            self._emit(
                did,
                "source-fetched",
                started,
                message="fetched did:webvh log is older than the local one; using the local log",
            )
            try:
                return await resolve_did_webvh_log(local, did=did)
            except DidWebvhError as exc:
                raise self._integrity_failure(
                    did, f"did:webvh log verification failed for {did}: {exc}", started
                ) from None
        return fetched

    def _emit_quietly(self, did: str, started: float, message: str) -> None:
        """Emit an ``error`` event; an event handler that raises must not break the caller."""
        try:
            self._emit(did, "error", started, message=message)
        except Exception:  # noqa: BLE001
            pass

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

    @staticmethod
    def _derive_did_wba_document_url(did: str) -> str:
        return _derive_did_wba_document_url(did)

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
