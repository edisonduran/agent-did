"""Default ``httpx`` client for the SDK's HTTP sources.

Redirects are not followed (httpx default). The host name of every request is resolved once,
rejected when any address is not globally routable, and the connection is then made to one of
those validated addresses (TLS still verifies the original host name through ``sni_hostname``).
Because the name is never resolved a second time, a DNS answer that changes after the check
(rebinding) cannot redirect the request.

Every request has one deadline (``timeout_ms``) covering lookup, connection and the whole body,
and a maximum body size (``max_response_bytes``); see ``HttpSecurityOptions``. The client asks for
an unencoded body and rejects any other ``Content-Encoding``, so the size limit applies to the bytes
that are parsed. A caller-supplied ``http_client`` owns its own redirect, DNS and limit policy.
TypeScript parity: ``sdk/src/core/safe-fetch.ts``.
"""

from __future__ import annotations

import asyncio

import httpx

from .http_security import (
    HttpTargetValidationOptions,
    LookupFn,
    resolve_allowed_addresses,
    resolve_http_client_limits,
)

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
        self._timeout_ms, self._max_response_bytes = resolve_http_client_limits(options)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # The Host header was set from the original URL when the request was built.
        authority = request.headers.get("host", request.url.host)
        request.headers["Accept-Encoding"] = "identity"
        try:
            # One deadline for the whole request: lookup, connection, headers and every body byte.
            return await asyncio.wait_for(self._send_and_read(request, authority), timeout=self._timeout_ms / 1000)
        except asyncio.TimeoutError as exc:
            raise httpx.TimeoutException(
                f"Request to {authority} exceeded the {self._timeout_ms} ms deadline", request=request
            ) from exc

    async def _send_and_read(self, request: httpx.Request, authority: str) -> httpx.Response:
        response = await self._send(request)
        try:
            encoding = response.headers.get("content-encoding")
            if encoding and encoding.strip().lower() != "identity":
                raise httpx.TransportError(
                    f'Response from {authority} uses Content-Encoding "{encoding}"; '
                    "the SDK HTTP client accepts only unencoded bodies"
                )
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > self._max_response_bytes:
                raise self._too_large(authority)
            body = bytearray()
            if response.is_stream_consumed:
                # An inner transport that reads the body itself (e.g. ``httpx.MockTransport``).
                body.extend(response.content)
            else:
                async for chunk in response.aiter_raw():
                    body.extend(chunk)
                    if len(body) > self._max_response_bytes:
                        raise self._too_large(authority)
            if len(body) > self._max_response_bytes:
                raise self._too_large(authority)
        finally:
            await response.aclose()
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            content=bytes(body),
            extensions=response.extensions,
        )

    def _too_large(self, authority: str) -> httpx.TransportError:
        return httpx.TransportError(f"Response from {authority} exceeds the {self._max_response_bytes}-byte limit")

    async def _send(self, request: httpx.Request) -> httpx.Response:
        addresses = await resolve_allowed_addresses(str(request.url), self._options, self._lookup)
        if addresses is None:
            return await self._inner.handle_async_request(request)

        request.extensions["sni_hostname"] = request.url.host
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
    """An ``httpx.AsyncClient`` with the SDK's HTTP policy. Pass ``HttpSecurityOptions`` to change the limits."""
    resolve_http_client_limits(options)
    # The transport enforces one total deadline, so httpx's per-operation timeouts are not used.
    return httpx.AsyncClient(
        transport=_PinningTransport(options, lookup, inner), follow_redirects=False, timeout=None
    )
