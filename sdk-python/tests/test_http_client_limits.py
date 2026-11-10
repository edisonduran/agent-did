"""Deadline and response-size limits of the default HTTP client.

TypeScript parity: ``limits, on both request paths`` in ``sdk/tests/safe-fetch.test.ts``.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable

import httpx
import pytest

from agent_did_sdk.core.http_security import (
    DEFAULT_HTTP_TIMEOUT_MS,
    DEFAULT_MAX_RESPONSE_BYTES,
    HttpSecurityOptions,
)
from agent_did_sdk.core.safe_client import create_safe_client

LIMIT = 1000
AT_LIMIT_BODY = json.dumps({"pad": "x" * (LIMIT - 10)}, separators=(",", ":")).encode()
assert len(AT_LIMIT_BODY) == LIMIT


def test_defaults() -> None:
    options = HttpSecurityOptions()
    assert (options.timeout_ms, options.max_response_bytes) == (DEFAULT_HTTP_TIMEOUT_MS, DEFAULT_MAX_RESPONSE_BYTES)
    assert (DEFAULT_HTTP_TIMEOUT_MS, DEFAULT_MAX_RESPONSE_BYTES) == (10_000, 1024 * 1024)
    assert options.allow_private_targets is False


@pytest.mark.parametrize(
    "kwargs",
    [{"timeout_ms": 0}, {"timeout_ms": 1.5}, {"max_response_bytes": -1}, {"max_response_bytes": True}],
)
def test_rejects_limits_that_are_not_positive_integers(kwargs: dict[str, object]) -> None:
    with pytest.raises(TypeError, match="must be a positive integer"):
        HttpSecurityOptions(**kwargs)  # type: ignore[arg-type]


# -- Two request paths ----------------------------------------------------------------------
#
# "pinned": a name resolved and validated by the client, served by an in-process transport that
# streams the body like a socket would. "socket": a real local server over TCP (allowed private
# target, so nothing is pinned), read by httpx's own transport.


class _Stream(httpx.AsyncByteStream):
    def __init__(self, chunks: Callable[[], AsyncIterator[bytes]]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._chunks():
            yield chunk


async def _once(*parts: bytes) -> AsyncIterator[bytes]:
    for part in parts:
        yield part


async def _trickle() -> AsyncIterator[bytes]:
    while True:
        await asyncio.sleep(0.02)
        yield b" "


class _StreamingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.accept_encodings: list[str | None] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.accept_encodings.append(request.headers.get("accept-encoding"))
        path = request.url.path
        if path == "/hang":
            await asyncio.sleep(3600)
        if path == "/trickle":
            return httpx.Response(200, stream=_Stream(_trickle))
        if path == "/declared-too-large":
            body = b"x" * (LIMIT + 1)
            return httpx.Response(200, headers={"content-length": str(len(body))}, stream=_Stream(lambda: _once(body)))
        if path == "/streamed-too-large":
            return httpx.Response(200, stream=_Stream(lambda: _once(b"x" * LIMIT, b"x")))
        if path == "/at-limit":
            return httpx.Response(200, stream=_Stream(lambda: _once(AT_LIMIT_BODY)))
        if path == "/gzip":
            return httpx.Response(200, headers={"content-encoding": "gzip"}, stream=_Stream(lambda: _once(b"not gzip")))
        return httpx.Response(404)


class _LocalServer:
    def __init__(self) -> None:
        self.accept_encodings: list[str | None] = []
        self.port = 0
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)  # type: ignore[arg-type]
        try:
            head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1").split("\r\n")
            path = head[0].split(" ")[1]
            headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in head[1:] if line)}
            self.accept_encodings.append(headers.get("accept-encoding"))
            await self._respond(path, writer)
        except (asyncio.CancelledError, ConnectionError):
            pass
        finally:
            writer.close()

    async def _respond(self, path: str, writer: asyncio.StreamWriter) -> None:
        def head(*lines: str) -> bytes:
            fields = "".join(f"{line}\r\n" for line in lines)
            return f"HTTP/1.1 200 OK\r\nconnection: close\r\n{fields}\r\n".encode()

        if path == "/hang":
            await asyncio.sleep(3600)
        elif path == "/trickle":
            writer.write(head())
            while True:
                await asyncio.sleep(0.02)
                writer.write(b" ")
                await writer.drain()
        elif path == "/declared-too-large":
            writer.write(head(f"content-length: {LIMIT + 1}") + b"x" * (LIMIT + 1))
        elif path == "/streamed-too-large":
            writer.write(head() + b"x" * (LIMIT + 1))
        elif path == "/at-limit":
            writer.write(head(f"content-length: {len(AT_LIMIT_BODY)}") + AT_LIMIT_BODY)
        elif path == "/gzip":
            writer.write(head("content-encoding: gzip", "content-length: 8") + b"not gzip")
        await writer.drain()


Request = Callable[[str, dict[str, int]], Awaitable[httpx.Response]]
PathUnderTest = tuple[Request, Callable[[], list[str | None]]]


@pytest.fixture(params=["pinned", "socket"])
async def path_under_test(request: pytest.FixtureRequest) -> AsyncIterator[PathUnderTest]:
    if request.param == "pinned":
        transport = _StreamingTransport()

        async def lookup(hostname: str) -> list[str]:
            return ["93.184.216.34"]

        async def pinned(path: str, limits: dict[str, int]) -> httpx.Response:
            client = create_safe_client(HttpSecurityOptions(**limits), lookup, transport)
            try:
                return await client.get(f"https://pinned.example{path}")
            finally:
                await client.aclose()

        yield pinned, lambda: transport.accept_encodings
        return

    server = _LocalServer()
    await server.start()

    async def socket(path: str, limits: dict[str, int]) -> httpx.Response:
        client = create_safe_client(HttpSecurityOptions(allow_private_targets=True, **limits))
        try:
            return await client.get(f"http://127.0.0.1:{server.port}{path}")
        finally:
            await client.aclose()

    try:
        yield socket, lambda: server.accept_encodings
    finally:
        await server.stop()


async def test_asks_for_an_unencoded_body_and_accepts_a_body_at_the_size_limit(
    path_under_test: PathUnderTest,
) -> None:
    request, accept_encodings = path_under_test
    response = await request("/at-limit", {"max_response_bytes": LIMIT})

    assert response.status_code == 200
    assert len(response.json()["pad"]) == LIMIT - 10
    assert accept_encodings() == ["identity"]


async def test_gives_up_when_the_server_does_not_answer_within_the_deadline(
    path_under_test: PathUnderTest,
) -> None:
    request, _ = path_under_test
    with pytest.raises(httpx.TimeoutException, match="exceeded the 200 ms deadline"):
        await request("/hang", {"timeout_ms": 200})


async def test_applies_the_deadline_to_the_whole_body(
    path_under_test: PathUnderTest,
) -> None:
    request, _ = path_under_test
    with pytest.raises(httpx.TimeoutException, match="exceeded the 300 ms deadline"):
        await request("/trickle", {"timeout_ms": 300})


@pytest.mark.parametrize("path", ["/declared-too-large", "/streamed-too-large"])
async def test_rejects_a_body_larger_than_the_limit(
    path_under_test: PathUnderTest, path: str
) -> None:
    request, _ = path_under_test
    with pytest.raises(httpx.TransportError, match=f"exceeds the {LIMIT}-byte limit"):
        await request(path, {"max_response_bytes": LIMIT})


async def test_rejects_an_encoded_body(path_under_test: PathUnderTest) -> None:
    request, _ = path_under_test
    with pytest.raises(httpx.TransportError, match='Content-Encoding "gzip"'):
        await request("/gzip", {})
