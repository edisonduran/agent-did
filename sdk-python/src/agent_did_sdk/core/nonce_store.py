"""Replay protection for verified HTTP message signatures.

``AgentIdentity.verify_http_request_signature`` records each accepted signature's ``nonce``
(scoped to its ``keyid``) until the signature's ``expires`` time and rejects a second request
carrying the same pair. Use a shared store (for example Redis ``SET key 1 NX EXAT expires_at``)
when several verifier instances serve the same agents.

TypeScript parity: ``sdk/src/core/nonce-store.ts``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol, runtime_checkable


def _scope_of(key: str) -> str:
    """The scope of a nonce key: the part before its last space (the ``keyid``), or the whole key without a space."""
    space = key.rfind(" ")
    return key if space == -1 else key[:space]


@runtime_checkable
class NonceStore(Protocol):
    async def check_and_store(self, key: str, expires_at: int) -> bool:
        """Record *key* until *expires_at* (Unix seconds).

        Return ``True`` when the key was not recorded yet, ``False`` when it was (a replay).
        Must be atomic.
        """
        ...


class InMemoryNonceStore:
    """Process-local :class:`NonceStore`. Suitable for a single verifier instance.

    When the store holds ``max_entries`` live entries after purging expired ones, new nonces
    are refused (fail closed) instead of evicting live ones, which would reopen a replay window.
    ``max_entries_per_scope`` bounds the live entries of one scope: the part of the key before its
    last space, which is the ``keyid`` of an HTTP signature (``"<keyid> <nonce>"``), so one signer
    cannot fill the store and lock every other signer out.
    """

    def __init__(
        self,
        *,
        max_entries: int = 100_000,
        max_entries_per_scope: int = 10_000,
        now: Callable[[], int] | None = None,
    ) -> None:
        self._entries: dict[str, int] = {}
        self._scope_counts: dict[str, int] = {}
        self._max_entries = max_entries
        self._max_entries_per_scope = max_entries_per_scope
        self._now = now or (lambda: int(time.time()))

    async def check_and_store(self, key: str, expires_at: int) -> bool:
        now = self._now()
        existing = self._entries.get(key)
        if existing is not None and existing >= now:
            return False
        scope = _scope_of(key)
        if existing is None:
            if self._is_full(scope):
                self._purge(now)
                if self._is_full(scope):
                    return False
            self._scope_counts[scope] = self._scope_counts.get(scope, 0) + 1
        self._entries[key] = expires_at
        return True

    def _is_full(self, scope: str) -> bool:
        return (
            len(self._entries) >= self._max_entries
            or self._scope_counts.get(scope, 0) >= self._max_entries_per_scope
        )

    @property
    def size(self) -> int:
        """Number of live entries (expired ones may linger until the next purge)."""
        return len(self._entries)

    def _purge(self, now: int) -> None:
        for key in [key for key, expires_at in self._entries.items() if expires_at < now]:
            del self._entries[key]
            scope = _scope_of(key)
            count = self._scope_counts.get(scope, 1) - 1
            if count > 0:
                self._scope_counts[scope] = count
            else:
                self._scope_counts.pop(scope, None)
