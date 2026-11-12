"""Controller key recovery with did:webvh pre-rotation. Parity: sdk/tests/ControllerKeyRotation.test.ts."""

from __future__ import annotations

import pytest

from agent_did_sdk import (
    AgentDidClient,
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    CreateDidWebvhOptions,
    LocalKeySigner,
    UpdateAgentDocumentParams,
)
from agent_did_sdk.webvh.adapter import DidWebvhError, did_webvh_update_key_for

# The controller key K0 is compromised; K1, K2 and K3 were committed in advance and kept offline.
K0 = LocalKeySigner("1" * 64)
K1 = LocalKeySigner("2" * 64)
K2 = LocalKeySigner("3" * 64)
K3 = LocalKeySigner("4" * 64)


async def key(signer: LocalKeySigner) -> str:
    return await did_webvh_update_key_for(signer)


async def create_agent(next_update_keys: list[str] | None = None) -> tuple[AgentDidClient, str]:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=K0, client=client))
    created = await identity.create(
        CreateAgentParams(
            name="RecoverableBot",
            core_model="test-model",
            system_prompt="test prompt",
            webvh=CreateDidWebvhOptions(
                domain="agents.example",
                path_segments=["agents", "recoverable-bot"],
                controller_did="{DID}",
                controller_signer=K0,
                next_update_keys=next_update_keys,
            ),
        )
    )
    return client, created.document.id


def patch(description: str) -> UpdateAgentDocumentParams:
    return UpdateAgentDocumentParams(description=description)


async def expect_unauthorized(awaitable: object) -> None:
    with pytest.raises(DidWebvhError) as excinfo:
        await awaitable  # type: ignore[misc]
    assert excinfo.value.code == "unauthorized"


class TestControllerKeyRotation:
    async def test_commits_to_the_next_keys_at_creation_and_exposes_the_commitments(self) -> None:
        client, did = await create_agent([await key(K1)])
        keys = await client.get_did_webvh_controller_keys(did)
        assert keys.update_keys == [await key(K0)]
        assert len(keys.next_key_hashes) == 1
        assert await key(K1) not in client.export_did_webvh_history(did)

    async def test_keeps_the_previous_behavior_without_commitments(self) -> None:
        client, did = await create_agent()
        assert (await client.get_did_webvh_controller_keys(did)).next_key_hashes == []
        await client.update_did_document(did, patch("still works with the controller key"))

    async def test_a_compromised_controller_key_cannot_change_or_revoke_the_did_the_committed_key_can(self) -> None:
        client, did = await create_agent([await key(K1)])

        # The attacker holds K0: every operation signed by it is refused.
        await expect_unauthorized(client.update_did_document(did, patch("taken over"), controller_signer=K0))
        await expect_unauthorized(client.revoke_did(did, controller_signer=K0))
        await expect_unauthorized(client.rotate_controller_key(did, K0, controller_signer=K0))

        # The owner recovers with the committed key and commits to the next one.
        rotated = await client.rotate_controller_key(did, K1, next_update_keys=[await key(K2)])
        assert rotated.update_keys == [await key(K1)]
        assert len(rotated.next_key_hashes) == 1

        # K0 is still refused; K1 is active but must not be reused, K2 is the next committed key.
        await expect_unauthorized(client.update_did_document(did, patch("taken over"), controller_signer=K0))
        await expect_unauthorized(client.update_did_document(did, patch("with K1"), controller_signer=K1))
        await client.update_did_document(did, patch("recovered"), controller_signer=K2)
        assert (await client.resolve(did)).agent_metadata.description == "recovered"
        assert (await client.get_did_webvh_controller_keys(did)).update_keys == [await key(K2)]

    async def test_retains_the_new_controller_signer_so_later_operations_need_no_explicit_signer(self) -> None:
        client, did = await create_agent([await key(K1)])
        await client.rotate_controller_key(did, K1, next_update_keys=[])
        await client.update_did_document(did, patch("signed by the retained K1"))
        await client.revoke_did(did)
        with pytest.raises(Exception, match="revoked"):
            await client.resolve(did)

    async def test_starts_pre_rotation_on_a_did_that_had_none(self) -> None:
        client, did = await create_agent()
        started = await client.rotate_controller_key(did, K0, next_update_keys=[await key(K1)])
        assert len(started.next_key_hashes) == 1
        await expect_unauthorized(client.update_did_document(did, patch("x"), controller_signer=K0))
        await client.rotate_controller_key(did, K1, next_update_keys=[await key(K3)])
        assert (await client.get_did_webvh_controller_keys(did)).update_keys == [await key(K1)]

    async def test_rejects_non_webvh_dids_and_dids_with_no_log_in_this_process(self) -> None:
        client = AgentDidClient()
        with pytest.raises(ValueError, match="did:webvh"):
            await client.rotate_controller_key("did:agent:polygon:0xabc", K1)
        with pytest.raises(ValueError, match="No did:webvh log"):
            await client.rotate_controller_key("did:webvh:QmX:agents.example", K1)
        with pytest.raises(ValueError, match="No did:webvh log"):
            await client.get_did_webvh_controller_keys("did:webvh:QmX:agents.example")
