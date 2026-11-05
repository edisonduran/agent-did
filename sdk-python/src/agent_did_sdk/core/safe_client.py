"""Default ``httpx`` client for the SDK's HTTP sources.

Redirects are not followed (httpx default). The host name of every request is resolved once,
rejected when any address is not globally routable, and the connection is then made to one of
those validated addresses (TLS still verifies the original host name through ``sni_hostname``).
Because the name is never resolved a second time, a DNS answer that changes after the check
(rebinding) cannot redirect the request. A caller-supplied ``http_client`` owns its own redirect
and DNS policy. TypeScript parity: ``sdk/src/core/safe-fetch.ts``.
"""

from __future__ import annotations

import httpx

from .http_security import HttpTargetValidationOptions, LookupFn, resolve_allowed_addresses

__all__ = ["create_safe_client"]


class _PinningTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        options: HttpTargetValidationOptions | None,
        lookup: LookupFn | None,
        inner: httpx.AsyncBaseTransport | None,
    ) -> None:
        self._options = options
        self._lookup = lookup
        self._inner = inner or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        addresses = await resolve_allowed_addresses(str(request.url), self._options, self._lookup)
        if addresses is None:
            return await self._inner.handle_async_request(request)

        hostname = request.url.host
        # The Host header was set from the original URL when the request was built.
        request.extensions["sni_hostname"] = hostname
        last_error: httpx.ConnectError | httpx.ConnectTimeout | None = None
        for address in addresses:
            request.url = request.url.copy_with(host=address)
            try:
                return await self._inner.handle_async_request(request)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    async def aclose(self) -> None:
        await self._inner.aclose()


def create_safe_client(
    options: HttpTargetValidationOptions | None = None,
    lookup: LookupFn | None = None,
    inner: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=_PinningTransport(options, lookup, inner), follow_redirects=False)
