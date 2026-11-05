"""Default ``httpx`` client for the SDK's HTTP sources.

Redirects are not followed (httpx default) and the host name of every request is resolved first
and rejected when any address is not globally routable, so a public name that points at a private
address is blocked like the literal address would be. A caller-supplied ``http_client`` owns its
own redirect and DNS policy. See ``assert_resolved_target_allowed`` for the residual rebinding risk.
TypeScript parity: ``sdk/src/core/safe-fetch.ts``.
"""

from __future__ import annotations

import httpx

from .http_security import HttpTargetValidationOptions, LookupFn, assert_resolved_target_allowed

__all__ = ["create_safe_client"]


class _ResolvingTransport(httpx.AsyncBaseTransport):
    def __init__(self, options: HttpTargetValidationOptions | None, lookup: LookupFn | None) -> None:
        self._options = options
        self._lookup = lookup
        self._inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await assert_resolved_target_allowed(str(request.url), self._options, self._lookup)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def create_safe_client(
    options: HttpTargetValidationOptions | None = None,
    lookup: LookupFn | None = None,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=_ResolvingTransport(options, lookup), follow_redirects=False)
