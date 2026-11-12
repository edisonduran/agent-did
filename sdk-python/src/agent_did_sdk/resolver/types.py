"""Resolver protocol and supporting types."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from ..core.types import AgentDIDDocument
from ..registry.types import AgentRegistry


@dataclass(frozen=True)
class DidWebvhResolution:
    """A verified did:webvh log and what is derived from it (see ADR-005 / RFC-001 §6.6 item 7)."""

    document: AgentDIDDocument
    """The document in force (the state of the last entry)."""
    log: str
    """The verified log text (``did.jsonl``)."""
    version_id: str
    update_keys: list[str]
    """The ``updateKeys`` in force after the last entry."""
    last_entry_signer_keys: list[str]
    """Multikeys (``z6Mk...``) that signed the last entry: the keys that endorsed the current document."""


@dataclass(frozen=True)
class DidWebvhState(DidWebvhResolution):
    """A :class:`DidWebvhResolution` and where the client got it from."""

    provenance: Literal["local", "imported", "fetched"] = "fetched"
    """``local``: created or changed in this client, authoritative here. ``imported``: a log loaded with
    ``import_did_webvh_history``, a cache of what the log host serves. ``fetched``: fetched and verified by the
    resolver."""


@runtime_checkable
class DIDResolver(Protocol):
    """A DID resolver. A resolver that fetches did:webvh logs may also implement
    ``async resolve_did_webvh_log(did) -> DidWebvhResolution | None`` so the controller binding can be checked;
    it rejects when the log cannot be fetched or verified (fail closed) and returns ``None`` when it holds only the
    document."""

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
    """Resolver used when the registry has no record or the document source cannot answer.

    Never used for did:webvh: a did:webvh DID that cannot be fetched fails closed, because falling back to
    an older copy would let whoever can block the log host keep a revoked or rotated-out state alive.
    """
    did_webvh_local_log: Callable[[str], str | None] | None = None
    """Returns the did:webvh log the caller already holds for a DID (``AgentDidClient`` passes its imported
    logs). A fetched log must equal it, extend it or be a prefix of it; when it is a prefix the longer local
    log wins (a stale host never rolls the DID back), and a log that diverges is an integrity failure."""
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
