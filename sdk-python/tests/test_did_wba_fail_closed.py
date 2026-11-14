"""did:wba resolution fails closed (parity: sdk/tests/DidWbaFailClosed.test.ts)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agent_did_sdk import DocumentIntegrityError, InMemoryAgentRegistry, InMemoryDIDResolver, UniversalResolverClient
from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.resolver.types import UniversalResolverConfig

DID = "did:wba:agents.example.com:bot"


def _document(did: str) -> AgentDIDDocument:
    return AgentDIDDocument.model_validate({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "controller": did,
        "created": "2026-01-01T00:00:00Z",
        "updated": "2026-01-01T00:00:00Z",
        "agentMetadata": {"name": "bot", "version": "1", "coreModelHash": "h", "systemPromptHash": "h"},
        "verificationMethod": [],
        "authentication": [],
    })


class _Source:
    def __init__(self, answer: Callable[[], Awaitable[Any]]) -> None:
        self._answer = answer

    async def get_by_reference(self, ref: str) -> Any:
        return await self._answer()


class _NoDocuments:
    async def get_by_reference(self, ref: str) -> None:
        return None


def _resolver(answer: Callable[[], Awaitable[Any]]) -> UniversalResolverClient:
    fallback = InMemoryDIDResolver()
    fallback.register_document(_document(DID))
    return UniversalResolverClient(UniversalResolverConfig(
        registry=InMemoryAgentRegistry(),
        document_source=_NoDocuments(),  # type: ignore[arg-type]
        wba_document_source=_Source(answer),  # type: ignore[arg-type]
        fallback_resolver=fallback,
    ))


async def test_does_not_answer_from_the_fallback_when_the_host_fails_or_has_no_document() -> None:
    async def unreachable() -> Any:
        raise RuntimeError("ECONNREFUSED")

    async def missing() -> Any:
        return None

    with pytest.raises(ValueError, match="could not be fetched"):
        await _resolver(unreachable).resolve(DID)
    with pytest.raises(ValueError, match="not found"):
        await _resolver(missing).resolve(DID)


async def test_reports_a_document_for_another_did_as_an_integrity_failure() -> None:
    async def other() -> Any:
        return _document("did:wba:evil.example:bot")

    with pytest.raises(DocumentIntegrityError):
        await _resolver(other).resolve(DID)
