"""Concurrent lifecycle operations on one DID (parity: sdk/tests/ConcurrentLifecycle.test.ts)."""

from __future__ import annotations

import asyncio

from nacl.signing import SigningKey

from agent_did_sdk.core.client import AgentDidClient
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, UpdateAgentDocumentParams
from agent_did_sdk.crypto.multibase import decode_public_key_multibase


async def _create_agent() -> tuple[AgentDidClient, str]:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    result = await identity.create(CreateAgentParams(name="RaceBot", core_model="test", system_prompt="test"))
    return client, result.document.id


def _entries(log: str) -> int:
    return len([line for line in log.split("\n") if line.strip()])


async def test_keeps_every_concurrent_update_in_the_log() -> None:
    client, did = await _create_agent()

    await asyncio.gather(
        client.update_did_document(did, UpdateAgentDocumentParams(description="first")),
        client.update_did_document(did, UpdateAgentDocumentParams(description="second")),
    )

    assert _entries(client.export_did_webvh_history(did)) == 3
    assert len(client.get_document_history(did)) == 3


async def test_returns_a_rotated_key_that_is_in_the_resolved_document_when_an_update_races() -> None:
    client, did = await _create_agent()

    rotated, _ = await asyncio.gather(
        client.rotate_verification_method(did),
        client.update_did_document(did, UpdateAgentDocumentParams(description="racing")),
    )

    document = await client.resolve(did)
    method = next(vm for vm in document.verification_method if vm.id == rotated.verification_method_id)
    assert method.public_key_multibase is not None
    expected = bytes(SigningKey(bytes.fromhex(rotated.agent_private_key)).verify_key)
    assert decode_public_key_multibase(method.public_key_multibase) == expected
    assert _entries(client.export_did_webvh_history(did)) == 3
