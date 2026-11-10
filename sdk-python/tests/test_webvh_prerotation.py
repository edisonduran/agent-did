"""did:webvh pre-rotation (``nextKeyHashes``) in the adapter. Parity: sdk/tests/WebvhPreRotation.test.ts."""

from __future__ import annotations

import json
from typing import Any

import pytest

from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.webvh.adapter import (
    DID_WEBVH_PLACEHOLDER,
    DidWebvhError,
    create_did_webvh_log,
    deactivate_did_webvh_log,
    did_webvh_update_key_for,
    resolve_did_webvh_log,
    update_did_webvh_log,
)

# K0 is active at creation, K1..K3 are committed in advance (pre-rotation).
K0 = LocalKeySigner("1" * 64)
K1 = LocalKeySigner("2" * 64)
K2 = LocalKeySigner("3" * 64)
K3 = LocalKeySigner("4" * 64)
AGENT_PUBLIC_KEY = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


async def key(signer: LocalKeySigner) -> str:
    return await did_webvh_update_key_for(signer)


def agent_document(description: str | None = None, did: str = DID_WEBVH_PLACEHOLDER) -> dict[str, Any]:
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": did,
        "controller": "did:webvh:controller.example.com",
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": AGENT_PUBLIC_KEY,
            }
        ],
        "assertionMethod": [f"{did}#key-1"],
        "agentMetadata": {
            "name": "pre-rotation-test",
            "version": "1.0.0",
            **({"description": description} if description else {}),
        },
    }


async def create_committed(next_signers: list[LocalKeySigner] | None = None):
    return await create_did_webvh_log(
        domain="agents.example.com",
        path_segments=["fleet", "agent-1"],
        document=agent_document(),
        signer=K0,
        next_update_keys=[await key(s) for s in (next_signers if next_signers is not None else [K1])],
        created="2026-01-01T00:00:00Z",
    )


async def expect_code(awaitable: Any, code: str) -> None:
    with pytest.raises(DidWebvhError) as excinfo:
        await awaitable
    assert excinfo.value.code == code


class TestPreRotation:
    async def test_writes_only_the_hash_of_the_next_key_and_exposes_it(self) -> None:
        created = await create_committed()
        assert len(created.metadata.next_key_hashes) == 1
        assert created.metadata.next_key_hashes[0].startswith("Qm")
        assert await key(K1) not in created.log
        assert created.metadata.update_keys == [await key(K0)]

    async def test_has_no_commitments_unless_asked(self) -> None:
        created = await create_did_webvh_log(domain="agents.example.com", document=agent_document(), signer=K0)
        assert created.metadata.next_key_hashes == []

    async def test_only_a_committed_key_signs_and_the_active_key_no_longer_can(self) -> None:
        created = await create_committed()
        await expect_code(update_did_webvh_log(log=created.log, signer=K0), "unauthorized")
        await expect_code(update_did_webvh_log(log=created.log, signer=K2), "unauthorized")

        rotated = await update_did_webvh_log(log=created.log, signer=K1)
        assert rotated.metadata.update_keys == [await key(K1)]
        assert rotated.version_number == 2

    async def test_keeps_the_commitment_unless_the_entry_changes_it(self) -> None:
        created = await create_committed()
        kept = await update_did_webvh_log(log=created.log, signer=K1)
        assert kept.metadata.next_key_hashes == created.metadata.next_key_hashes

        chained = await update_did_webvh_log(log=kept.log, signer=K1, next_update_keys=[await key(K2)])
        assert len(chained.metadata.next_key_hashes) == 1
        assert chained.metadata.next_key_hashes != created.metadata.next_key_hashes

        # K1 is the active key but no longer committed: K2 must sign now.
        await expect_code(update_did_webvh_log(log=chained.log, signer=K1), "unauthorized")
        nxt = await update_did_webvh_log(log=chained.log, signer=K2, next_update_keys=[await key(K3)])
        assert nxt.metadata.update_keys == [await key(K2)]
        assert (await resolve_did_webvh_log(nxt.log)).version_number == 4

    async def test_an_empty_commitment_ends_pre_rotation(self) -> None:
        created = await create_committed()
        ended = await update_did_webvh_log(log=created.log, signer=K1, next_update_keys=[])
        assert ended.metadata.next_key_hashes == []
        ordinary = await update_did_webvh_log(
            log=ended.log, signer=K1, document=agent_document(did=ended.did)
        )
        assert ordinary.version_number == 3
        await expect_code(update_did_webvh_log(log=ended.log, signer=K0), "unauthorized")

    async def test_can_start_pre_rotation_on_a_log_that_had_none(self) -> None:
        plain = await create_did_webvh_log(domain="agents.example.com", document=agent_document(), signer=K0)
        started = await update_did_webvh_log(log=plain.log, signer=K0, next_update_keys=[await key(K1)])
        assert len(started.metadata.next_key_hashes) == 1
        await expect_code(update_did_webvh_log(log=started.log, signer=K0), "unauthorized")
        assert await update_did_webvh_log(log=started.log, signer=K1) is not None

    async def test_refuses_commitments_to_keys_that_are_not_new_malformed_or_repeated(self) -> None:
        common: dict[str, Any] = {"domain": "agents.example.com", "document": agent_document(), "signer": K0}
        await expect_code(create_did_webvh_log(**common, next_update_keys=[await key(K0)]), "invalidInput")
        await expect_code(create_did_webvh_log(**common, next_update_keys=["z6Mk-not-a-key"]), "invalidInput")
        await expect_code(
            create_did_webvh_log(**common, next_update_keys=[await key(K1), await key(K1)]), "invalidInput"
        )
        created = await create_committed()
        # Committing to the key that signs this very entry would make the commitment useless.
        await expect_code(
            update_did_webvh_log(log=created.log, signer=K1, next_update_keys=[await key(K1)]), "invalidInput"
        )

    async def test_refuses_update_keys_that_were_not_committed_even_when_the_signer_was(self) -> None:
        created = await create_committed()
        await expect_code(
            update_did_webvh_log(log=created.log, signer=K1, update_keys=[await key(K1), await key(K2)]),
            "unauthorized",
        )
        await expect_code(
            update_did_webvh_log(log=created.log, signer=K1, update_keys=[await key(K2)]), "invalidInput"
        )

    async def test_deactivates_only_with_a_committed_key(self) -> None:
        created = await create_committed()
        await expect_code(deactivate_did_webvh_log(log=created.log, signer=K0), "unauthorized")
        deactivated = await deactivate_did_webvh_log(log=created.log, signer=K1)
        assert deactivated.metadata.deactivated is True
        assert deactivated.metadata.next_key_hashes == []
        assert (await resolve_did_webvh_log(deactivated.log)).metadata.deactivated is True

    async def test_refuses_to_sign_with_the_active_key_once_it_committed_to_a_successor(self) -> None:
        plain = await create_did_webvh_log(domain="agents.example.com", document=agent_document(), signer=K0)
        committed = await update_did_webvh_log(log=plain.log, signer=K0, next_update_keys=[await key(K1)])
        await expect_code(
            update_did_webvh_log(
                log=committed.log, signer=K0, document=agent_document("forged", did=plain.did)
            ),
            "unauthorized",
        )

    async def test_rejects_on_resolution_updatekeys_swapped_for_the_old_key(self) -> None:
        created = await create_committed()
        rotated = await update_did_webvh_log(log=created.log, signer=K1)
        lines = rotated.log.rstrip().split("\n")
        last = json.loads(lines[-1])
        last["parameters"]["updateKeys"] = [await key(K0)]
        lines[-1] = json.dumps(last)
        await expect_code(resolve_did_webvh_log("\n".join(lines) + "\n"), "invalidDid")
