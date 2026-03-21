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


@dataclass
class UniversalResolverConfig:
    registry: AgentRegistry
    document_source: DIDDocumentSource
    fallback_resolver: DIDResolver | None = None
    cache_ttl_ms: int = 60_000
    on_resolution_event: Callable[[ResolverResolutionEvent], None] | None = None
