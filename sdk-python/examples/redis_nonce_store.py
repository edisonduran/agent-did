"""Reference ``NonceStore`` backed by Redis, for several verifier instances (replicas, serverless
functions, Kubernetes) that serve the same agents. Copy it into your service; it is not part of the
SDK package, so the SDK has no Redis dependency.

    import redis.asyncio as redis

    nonce_store = RedisNonceStore(redis.from_url(os.environ["REDIS_URL"]))
    ok = await client.verify_http_request_signature(
        VerifyHttpRequestSignatureParams(method=method, url=url, body=body, headers=headers, nonce_store=nonce_store)
    )

Contract (see ``NonceStore`` in ``agent_did_sdk``):

* ``check_and_store(key, expires_at)`` is ATOMIC: one ``SET key value NX EXAT ...``, never a GET then a SET.
* It returns ``True`` for a key not seen before and ``False`` for a replay.
* It keeps the key through the second ``expires_at`` INCLUSIVE, because the verifier accepts a request while
  ``now <= expires``. Redis ``EXAT t`` removes the key at the start of second ``t``, so the expiry is
  ``expires_at + 1``. With ``EXAT expires_at`` a request replayed in the last second of its life would be
  accepted.
* It FAILS CLOSED: a Redis error raises, ``verify_http_request_signature`` raises with it, and the request
  must be refused (answer 5xx/401, never "accept because the store is down").

The tests in ``sdk-python/tests/test_redis_nonce_store_example.py`` run this class against a fake Redis that
has the same ``SET NX EXAT`` semantics.
"""

from __future__ import annotations

from typing import Any, Protocol


class _RedisLike(Protocol):
    async def set(self, name: str, value: Any, *, nx: bool, exat: int) -> Any: ...


class RedisNonceStore:
    def __init__(self, client: _RedisLike, *, prefix: str = "agent-did:nonce:") -> None:
        self._client = client
        self._prefix = prefix

    async def check_and_store(self, key: str, expires_at: int) -> bool:
        reply = await self._client.set(f"{self._prefix}{key}", 1, nx=True, exat=expires_at + 1)
        return bool(reply)
