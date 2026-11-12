"""InMemoryNonceStore scopes and clock (parity: sdk/tests/NonceStore.test.ts, HttpVerificationVectors)."""

from __future__ import annotations

from agent_did_sdk.core.nonce_store import InMemoryNonceStore


async def test_bounds_the_live_entries_of_one_keyid_so_one_signer_cannot_lock_the_others_out() -> None:
    store = InMemoryNonceStore(max_entries=100, max_entries_per_scope=2, now=lambda: 1_000)

    assert await store.check_and_store("did:a#key-1 n1", 1_100) is True
    assert await store.check_and_store("did:a#key-1 n2", 1_100) is True
    assert await store.check_and_store("did:a#key-1 n3", 1_100) is False
    assert await store.check_and_store("did:b#key-1 n1", 1_100) is True


async def test_frees_a_scope_when_its_entries_expire() -> None:
    now = [1_000]
    store = InMemoryNonceStore(max_entries_per_scope=1, now=lambda: now[0])

    assert await store.check_and_store("did:a#key-1 n1", 1_005) is True
    assert await store.check_and_store("did:a#key-1 n2", 1_100) is False
    now[0] = 1_006
    assert await store.check_and_store("did:a#key-1 n2", 1_100) is True
