"""Resolver protocol and supporting types."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from ..core.types import AgentDIDDocument
from ..registry.types import AgentRegistry


@runtime_checkable
class DIDResolver(Protocol):
    def register_document(self, document: AgentDIDDocument) -> None: ...
    async def resolve(self, did: str) -> AgentDIDDocument: ...
    def remove(self, did: str) -> None: ...


@runtime_checkable
class DIDDocumentSource(Protocol):
    async def get_by_reference(self, document_ref: str) -> AgentDIDDocument | None: ...
    async def get_did_log_by_reference(self, document_ref: str) -> str | None: ...
    async def store_did_log_by_reference(self, document_ref: str, did_log: str) -> None: ...


ResolverResolutionStage = Literal[
    "cache-hit",
    "cache-miss",
    "registry-lookup",
    "source-fetch",
    "source-fetched",
    "fallback",
    "resolved",
    "error",
]


@dataclass
class ResolverResolutionEvent:
    did: str
    stage: ResolverResolutionStage
    duration_ms: float
    message: str | None = None


@dataclass
class ResolverCacheStats:
    hits: int
    misses: int
    size: int


DEFAULT_RESOLVER_MAX_CACHE_ENTRIES = 1000
"""Default maximum number of documents in the ``UniversalResolverClient`` cache."""


@dataclass
class UniversalResolverConfig:
    registry: AgentRegistry
    document_source: DIDDocumentSource
    wba_document_source: DIDDocumentSource | None = None
    webvh_document_source: DIDDocumentSource | None = None
    fallback_resolver: DIDResolver | None = None
    cache_ttl_ms: int = 60_000
    max_cache_entries: int = DEFAULT_RESOLVER_MAX_CACHE_ENTRIES
    """Maximum documents kept in the cache. When it is full, expired entries are dropped first and
    then the least recently used."""
    on_resolution_event: Callable[[ResolverResolutionEvent], None] | None = None
    unverified_document_ref_schemes: list[str] | None = None
    """documentRef schemes (without ``://``, e.g. ``"ipfs"``) accepted without a content-hash check.

    Defaults to none: only ``hash://sha256/`` references, which the SDK always produces, are
    accepted, and they are always verified. Each unverified resolution emits a
    ``source-fetched`` event saying so.
    """


class DocumentIntegrityError(ValueError):
    """A resolved DID document cannot be trusted.

    Raised when the document ``id`` differs from the requested DID, its content does not
    hash to the registry ``documentRef``, or the ``documentRef`` uses a scheme that cannot
    be verified. Resolvers never fall back to another source on this error.
    """
