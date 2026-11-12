"""evict_cached_resolution (parity: sdk/tests/EvictResolution.test.ts)."""

from __future__ import annotations

from agent_did_sdk import InMemoryAgentRegistry
from agent_did_sdk.core.client import AgentDidClient, ProductionResolverProfileConfig
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams
from agent_did_sdk.webvh.adapter import derive_did_webvh_log_url


async def test_makes_the_next_resolution_fetch_again_and_keeps_documents_of_a_non_caching_resolver() -> None:
    owner = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=owner))
    created = await identity.create(CreateAgentParams(name="EvictBot", core_model="test", system_prompt="test"))
    did = created.document.id
    calls: list[str] = []

    class _Host:
        async def get_by_reference(self, ref: str) -> None:
            return None

        async def get_did_log_by_reference(self, url: str) -> str | None:
            calls.append(url)
            return owner.export_did_webvh_history(did) if url == derive_did_webvh_log_url(did) else None

    class _NoDocuments:
        async def get_by_reference(self, ref: str) -> None:
            return None

    verifier = AgentDidClient()
    verifier.use_production_resolver(ProductionResolverProfileConfig(
        registry=InMemoryAgentRegistry(),
        document_source=_NoDocuments(),  # type: ignore[arg-type]
        webvh_document_source=_Host(),  # type: ignore[arg-type]
    ))

    await verifier.resolve(did)
    await verifier.resolve(did)
    assert len(calls) == 1

    verifier.evict_cached_resolution(did)
    await verifier.resolve(did)
    assert len(calls) == 2

    # The default in-memory resolver is a store, not a cache: nothing is dropped
    owner.evict_cached_resolution(did)
    assert (await owner.resolve(did)).id == did
