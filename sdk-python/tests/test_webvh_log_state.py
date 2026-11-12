"""did:webvh logs held by a client (parity: sdk/tests/WebvhLogState.test.ts)."""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import pytest

from agent_did_sdk import InMemoryAgentRegistry
from agent_did_sdk.core.client import AgentDidClient, ProductionResolverProfileConfig
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, UpdateAgentDocumentParams
from agent_did_sdk.resolver.types import ResolverResolutionEvent
from agent_did_sdk.webvh.adapter import DidWebvhError

PARAMS = CreateAgentParams(
    name="LogStateBot",
    description="Agent used to test how a client keeps did:webvh logs",
    core_model="gpt-4o-mini",
    system_prompt="You are a test assistant.",
)


async def _create_agent(client: AgentDidClient) -> tuple[Any, str]:
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    result = await identity.create(PARAMS)
    signature = await identity.sign_message("hello", result.agent_private_key)
    return result.document, signature


class _UnreachableHost:
    """did:webvh source double whose host is down."""

    async def get_by_reference(self, ref: str) -> None:
        return None

    async def get_did_log_by_reference(self, ref: str) -> str | None:
        raise RuntimeError("connect timeout")


class _Document:
    async def get_by_reference(self, ref: str) -> None:
        return None


class _FailingStore(_Document):
    async def store_by_reference(self, ref: str, document: object) -> None:
        raise RuntimeError("storage unavailable")


@pytest.fixture()
def clock_offset_ms(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[float]]:
    """The resolver cache reads ``time.time()``: moving it forward expires cache entries without waiting."""
    offset = [0.0]
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + offset[0] / 1000)
    yield offset


def _production(client: AgentDidClient, **overrides: Any) -> None:
    client.use_production_resolver(ProductionResolverProfileConfig(
        registry=InMemoryAgentRegistry(),
        document_source=overrides.pop("document_source", _Document()),  # type: ignore[arg-type]
        webvh_document_source=_UnreachableHost(),  # type: ignore[arg-type]
        cache_ttl_ms=60_000,
        **overrides,
    ))


class TestImportingALog:
    async def test_rejects_an_older_prefix_so_a_revoked_did_stays_revoked(self) -> None:
        client = AgentDidClient()
        document, signature = await _create_agent(client)
        before_revocation = client.export_did_webvh_history(document.id)
        await client.revoke_did(document.id)
        assert await client.verify_signature(document.id, "hello", signature) is False

        with pytest.raises(DidWebvhError):
            await client.import_did_webvh_history(before_revocation)

        assert await client.verify_signature(document.id, "hello", signature) is False
        with pytest.raises(ValueError, match="revoked"):
            await client.resolve(document.id)

    async def test_rejects_a_log_that_diverges_from_the_stored_one(self) -> None:
        client = AgentDidClient()
        document, _ = await _create_agent(client)
        other = AgentDidClient()
        await other.import_did_webvh_history(client.export_did_webvh_history(document.id))
        signer = client._did_webvh_signer_store[document.id]
        await client.update_did_document(document.id, UpdateAgentDocumentParams(description="branch A"))
        branch_a = client.export_did_webvh_history(document.id)
        await other.update_did_document(
            document.id, UpdateAgentDocumentParams(description="branch B"), controller_signer=signer
        )
        branch_b = other.export_did_webvh_history(document.id)

        with pytest.raises(DidWebvhError):
            await client.import_did_webvh_history(branch_b)

        assert client.export_did_webvh_history(document.id) == branch_a

    async def test_the_same_log_is_a_no_op_that_keeps_the_retained_controller_signer(self) -> None:
        client = AgentDidClient()
        document, _ = await _create_agent(client)
        stored = client.export_did_webvh_history(document.id)

        await client.import_did_webvh_history(stored)

        assert client.export_did_webvh_history(document.id) == stored
        # The controller signer was kept: the DID can still be changed without passing one
        await client.update_did_document(document.id, UpdateAgentDocumentParams(description="still mine"))

    async def test_accepts_a_log_that_extends_the_stored_one_and_keeps_the_signer_while_its_key_is_an_update_key(
        self,
    ) -> None:
        client = AgentDidClient()
        document, _ = await _create_agent(client)
        verifier = AgentDidClient()
        await verifier.import_did_webvh_history(client.export_did_webvh_history(document.id))
        await client.update_did_document(document.id, UpdateAgentDocumentParams(description="newer"))

        imported = await verifier.import_did_webvh_history(client.export_did_webvh_history(document.id))

        assert imported.agent_metadata.description == "newer"
        # The creator's own signer is still an updateKey of the log, so it keeps control after re-importing it
        await client.import_did_webvh_history(client.export_did_webvh_history(document.id))
        await client.update_did_document(document.id, UpdateAgentDocumentParams(description="newest"))


class TestResolvingWithAProductionResolver:
    async def test_keeps_resolving_an_agent_created_in_this_client_after_the_cache_expires(
        self, clock_offset_ms: list[float]
    ) -> None:
        client = AgentDidClient()
        _production(client)
        document, signature = await _create_agent(client)
        assert await client.verify_signature(document.id, "hello", signature) is True

        clock_offset_ms[0] += 120_000

        assert await client.verify_signature(document.id, "hello", signature) is True

    async def test_fails_closed_for_an_imported_did_whose_log_cannot_be_refreshed(
        self, clock_offset_ms: list[float]
    ) -> None:
        creator = AgentDidClient()
        document, signature = await _create_agent(creator)
        verifier = AgentDidClient()
        _production(verifier)
        await verifier.import_did_webvh_history(creator.export_did_webvh_history(document.controller))
        await verifier.import_did_webvh_history(creator.export_did_webvh_history(document.id))
        assert await verifier.verify_signature(document.id, "hello", signature) is True

        clock_offset_ms[0] += 120_000

        assert await verifier.verify_signature(document.id, "hello", signature) is False

    async def test_does_not_serve_a_revoked_did_from_an_older_copy_when_its_host_is_down(
        self, clock_offset_ms: list[float]
    ) -> None:
        creator = AgentDidClient()
        document, signature = await _create_agent(creator)
        before_revocation = creator.export_did_webvh_history(document.id)
        await creator.revoke_did(document.id)
        verifier = AgentDidClient()
        await verifier.import_did_webvh_history(creator.export_did_webvh_history(document.controller))
        await verifier.import_did_webvh_history(before_revocation)
        _production(verifier)
        clock_offset_ms[0] += 120_000

        assert await verifier.verify_signature(document.id, "hello", signature) is False

    async def test_reports_a_failed_remote_write_of_a_document_instead_of_swallowing_it(self) -> None:
        events: list[ResolverResolutionEvent] = []
        client = AgentDidClient()
        _production(client, document_source=_FailingStore(), on_resolution_event=events.append)

        await _create_agent(client)
        import asyncio

        await asyncio.sleep(0.02)

        assert any(
            e.stage == "error" and "store_by_reference failed: storage unavailable" in (e.message or "")
            for e in events
        )
