"""Failure paths of the universal resolver that the resolution tests do not reach (C-QA-2).

TypeScript parity: sdk/tests/UniversalResolverEdgeCases.test.ts.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agent_did_sdk import InMemoryAgentRegistry, ResolutionLimits, UniversalResolverClient
from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver
from agent_did_sdk.resolver.types import ResolverResolutionEvent, UniversalResolverConfig

from .test_resolver_source_edge_cases import DOCUMENT
from .test_witnesses import _witnessed_log

OTHER = "did:example:edge"


class _Documents:
    def __init__(self, document: AgentDIDDocument | None = None) -> None:
        self.document = document
        self.stored: list[str] = []

    async def get_by_reference(self, ref: str) -> AgentDIDDocument | None:
        return self.document

    async def store_by_reference(self, ref: str, document: AgentDIDDocument) -> None:
        self.stored.append(ref)


class _Logs:
    def __init__(
        self,
        fetch: Callable[[str], Awaitable[str | None]],
        witness: Callable[[str], Awaitable[str | None]] | None = None,
    ) -> None:
        self.fetch = fetch
        if witness is not None:
            self.get_did_witness_file_by_reference = witness

    async def get_by_reference(self, ref: str) -> None:
        return None

    async def get_did_log_by_reference(self, url: str) -> str | None:
        return await self.fetch(url)


def _returning(text: str | None) -> Callable[[str], Awaitable[str | None]]:
    async def fetch(_url: str) -> str | None:
        return text

    return fetch


def _resolver(logs: Any = None, documents: Any = None, **extra: Any) -> UniversalResolverClient:
    return UniversalResolverClient(
        UniversalResolverConfig(
            registry=extra.pop("registry", InMemoryAgentRegistry()),
            document_source=documents or _Documents(),
            webvh_document_source=logs or _Logs(_returning(None)),
            **extra,
        )
    )


def _other_document() -> AgentDIDDocument:
    return AgentDIDDocument.model_validate({**DOCUMENT, "id": OTHER})


# --- Methods other than did:webvh -----------------------------------------------------------------------------


async def test_falls_back_when_the_record_has_no_reference_or_the_source_has_no_document() -> None:
    fallback = InMemoryDIDResolver()
    fallback.register_document(_other_document())
    registry = InMemoryAgentRegistry()
    await registry.register(OTHER, "did:example:controller")

    resolver = _resolver(registry=registry, fallback_resolver=fallback)
    assert (await resolver.resolve(OTHER)).id == OTHER

    with_ref = InMemoryAgentRegistry()
    await with_ref.register(OTHER, "did:example:controller", "hash://sha256/" + "0" * 64)
    resolver = _resolver(registry=with_ref, fallback_resolver=fallback)
    assert (await resolver.resolve(OTHER)).id == OTHER


async def test_resolve_document_and_log_of_another_method() -> None:
    fallback = InMemoryDIDResolver()
    fallback.register_document(_other_document())
    resolver = _resolver(fallback_resolver=fallback)

    assert (await resolver.resolve_document(OTHER)).id == OTHER
    assert await resolver.resolve_did_webvh_log(OTHER) is None

    resolver.remove(OTHER)
    with pytest.raises(Exception):
        await fallback.resolve(OTHER)


# --- did:webvh failures ---------------------------------------------------------------------------------------


async def test_a_log_that_is_not_json_is_an_integrity_failure() -> None:
    resolver = _resolver(_Logs(_returning("not json")))
    with pytest.raises(Exception, match="log verification failed"):
        await resolver.resolve_document("did:webvh:QmScid:edge.example")


async def test_reports_a_witness_file_that_cannot_be_fetched() -> None:
    _signer, _w, created = await _witnessed_log(1, 1)

    async def broken(_url: str) -> str | None:
        raise RuntimeError("connection reset")

    resolver = _resolver(_Logs(_returning(created.log), witness=broken))
    with pytest.raises(Exception, match="connection reset"):
        await resolver.resolve_document(created.did)


async def test_refuses_a_verified_log_whose_state_is_not_an_agent_did_document() -> None:
    _signer, _w, created = await _witnessed_log(1, 1)

    async def witness(_url: str) -> str | None:
        return created.witness_file

    resolver = _resolver(_Logs(_returning(created.log), witness=witness))
    with pytest.raises(ValueError, match="is not an Agent-DID document"):
        await resolver.resolve(created.did)
    assert (await resolver.resolve_document(created.did)).id == created.did


async def test_fails_closed_when_the_local_log_cannot_be_compared_or_does_not_verify() -> None:
    _signer, _w, created = await _witnessed_log(1, 1)
    files = {"log": created.log, "witness": created.witness_file}

    async def witness(_url: str) -> str | None:
        return files["witness"]

    empty = _resolver(_Logs(_returning(created.log), witness=witness), did_webvh_local_log=lambda _did: "")
    with pytest.raises(Exception, match="log comparison failed"):
        await empty.resolve_document(created.did)

    forged_log = created.log.rstrip("\n") + '\n{"versionId":"2-forged"}\n'
    forged = _resolver(_Logs(_returning(created.log), witness=witness), did_webvh_local_log=lambda _did: forged_log)
    with pytest.raises(Exception, match="log verification failed"):
        await forged.resolve_document(created.did)


# --- Cache, limits and events ---------------------------------------------------------------------------------


async def test_keeps_the_negative_cache_within_max_cache_entries() -> None:
    calls: list[str] = []

    async def failing(url: str) -> str | None:
        calls.append(url)
        raise RuntimeError("connect timeout")

    resolver = _resolver(_Logs(failing), max_cache_entries=1)
    for did in ("did:webvh:QmScid:one.example", "did:webvh:QmScid:two.example", "did:webvh:QmScid:one.example"):
        with pytest.raises(Exception):
            await resolver.resolve(did)
    assert len(calls) == 3


async def test_lets_an_invalid_did_fail_in_the_fetch_when_allowed_hosts_is_set() -> None:
    resolver = _resolver(resolution_limits=ResolutionLimits(allowed_hosts=["edge.example"]))
    with pytest.raises(Exception):
        await resolver.resolve("did:webvh:")


def test_register_document_outside_an_event_loop_reports_the_skipped_write_even_if_the_handler_raises() -> None:
    events: list[ResolverResolutionEvent] = []

    def handler(event: ResolverResolutionEvent) -> None:
        events.append(event)
        raise RuntimeError("handler bug")

    documents = _Documents()
    resolver = _resolver(documents=documents, on_resolution_event=handler)
    resolver.register_document(_other_document())

    assert documents.stored == []
    assert any("no running event loop" in (event.message or "") for event in events)


async def test_a_caller_that_stops_waiting_for_a_fetch_slot_does_not_break_the_resolver() -> None:
    release = asyncio.Event()

    async def slow(_url: str) -> str | None:
        await release.wait()
        return None

    resolver = _resolver(_Logs(slow), resolution_limits=ResolutionLimits(max_concurrent_fetches=1))
    first = asyncio.ensure_future(resolver.resolve("did:webvh:QmScid:one.example"))
    await asyncio.sleep(0.01)
    waiting = asyncio.ensure_future(resolver.resolve("did:webvh:QmScid:two.example"))
    await asyncio.sleep(0.01)
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    release.set()
    with pytest.raises(Exception):
        await first
