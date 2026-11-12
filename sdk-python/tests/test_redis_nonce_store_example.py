"""The Redis ``NonceStore`` reference (``sdk-python/examples/redis_nonce_store.py``) against a fake Redis with
the same ``SET NX EXAT`` semantics, plus the ``NonceStore`` contract shared with ``InMemoryNonceStore``."""

from __future__ import annotations

import asyncio
import importlib.util
import pathlib
import time
from collections.abc import Callable
from typing import Any

import pytest

from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.nonce_store import InMemoryNonceStore, NonceStore
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, SignHttpRequestParams, VerifyHttpRequestSignatureParams

_EXAMPLE = pathlib.Path(__file__).resolve().parents[1] / "examples" / "redis_nonce_store.py"
_spec = importlib.util.spec_from_file_location("redis_nonce_store_example", _EXAMPLE)
assert _spec is not None and _spec.loader is not None
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
RedisNonceStore = _module.RedisNonceStore


class FakeRedis:
    """``SET key value NX EXAT t``: atomic, and the key is gone from second ``t`` on."""

    def __init__(self, now: Callable[[], int]) -> None:
        self._now = now
        self._entries: dict[str, int] = {}
        self.failing = False
        self.keys_seen: list[str] = []

    async def set(self, name: str, value: Any, *, nx: bool, exat: int) -> Any:
        assert nx is True
        if self.failing:
            raise ConnectionError("ECONNREFUSED")
        self.keys_seen.append(name)
        expires_at = self._entries.get(name)
        if expires_at is not None and self._now() < expires_at:
            return None  # NX: the key exists
        self._entries[name] = exat
        return True


class Clock:
    def __init__(self, value: int = 1_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


@pytest.fixture()
def clock() -> Clock:
    return Clock()


def _stores(clock: Clock) -> list[tuple[str, NonceStore]]:
    return [
        ("in-memory", InMemoryNonceStore(now=clock)),
        ("redis-reference", RedisNonceStore(FakeRedis(clock))),
    ]


@pytest.mark.parametrize("index", [0, 1], ids=["in-memory", "redis-reference"])
class TestNonceStoreContract:
    async def test_accepts_a_key_once_and_refuses_its_replay(self, clock: Clock, index: int) -> None:
        store = _stores(clock)[index][1]
        assert await store.check_and_store("k1", 1_060) is True
        assert await store.check_and_store("k1", 1_060) is False
        assert await store.check_and_store("k2", 1_060) is True

    async def test_is_atomic_for_concurrent_submissions(self, clock: Clock, index: int) -> None:
        store = _stores(clock)[index][1]
        results = await asyncio.gather(*(store.check_and_store("same", 1_060) for _ in range(50)))
        assert sum(results) == 1

    async def test_keeps_the_key_through_the_second_expires_at_inclusive(self, clock: Clock, index: int) -> None:
        store = _stores(clock)[index][1]
        assert await store.check_and_store("edge", 1_030) is True
        clock.value = 1_030
        assert await store.check_and_store("edge", 1_030) is False


class TestRedisReference:
    async def test_shares_state_between_instances_that_share_redis(self, clock: Clock) -> None:
        redis = FakeRedis(clock)
        instance_a, instance_b = RedisNonceStore(redis), RedisNonceStore(redis)
        assert await instance_a.check_and_store("shared", 1_060) is True
        assert await instance_b.check_and_store("shared", 1_060) is False

    async def test_forgets_the_key_after_expires_at(self, clock: Clock) -> None:
        store = RedisNonceStore(FakeRedis(clock))
        assert await store.check_and_store("gone", 1_030) is True
        clock.value = 1_031
        assert await store.check_and_store("gone", 1_030) is True

    async def test_uses_the_prefix(self, clock: Clock) -> None:
        redis = FakeRedis(clock)
        await RedisNonceStore(redis, prefix="svc:").check_and_store("abc", 5)
        assert redis.keys_seen == ["svc:abc"]

    async def test_fails_closed_when_redis_is_down(self, clock: Clock) -> None:
        redis = FakeRedis(clock)
        store = RedisNonceStore(redis)
        redis.failing = True
        with pytest.raises(ConnectionError):
            await store.check_and_store("x", 1_060)

    async def test_rejects_a_replayed_signed_request_across_instances_and_refuses_on_outage(self) -> None:
        identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
        created = await identity.create(CreateAgentParams(name="RedisBot", core_model="test", system_prompt="test"))
        request = {"method": "POST", "url": "https://api.example.com/v1/data", "body": '{"redis":true}'}

        async def _headers() -> dict[str, str]:
            return await identity.sign_http_request(
                SignHttpRequestParams(
                    **request,
                    agent_private_key=created.agent_private_key,
                    agent_did=created.document.id, verification_method_id=f"{created.document.id}#key-1",
                    expires_in_seconds=120,
                )
            )

        def _params(headers: dict[str, str], store: NonceStore) -> VerifyHttpRequestSignatureParams:
            return VerifyHttpRequestSignatureParams(**request, headers=headers, nonce_store=store)

        # Real time: the verifier uses the system clock, so Redis does too.
        redis = FakeRedis(lambda: int(time.time()))
        instance_a, instance_b = RedisNonceStore(redis), RedisNonceStore(redis)
        headers = await _headers()

        assert await AgentIdentity.verify_http_request_signature(_params(headers, instance_a)) is True
        assert await AgentIdentity.verify_http_request_signature(_params(headers, instance_b)) is False

        fresh = await _headers()
        redis.failing = True
        with pytest.raises(ConnectionError):
            await AgentIdentity.verify_http_request_signature(_params(fresh, instance_a))
