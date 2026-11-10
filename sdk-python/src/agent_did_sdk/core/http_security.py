"""SSRF protection — validates HTTP target URLs before requests."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

__all__ = [
    "DEFAULT_HTTP_TIMEOUT_MS",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "HttpSecurityOptions",
    "HttpTargetValidationOptions",
    "validate_http_target",
]

DEFAULT_HTTP_TIMEOUT_MS = 10_000
"""Default deadline of a request made by the SDK's default HTTP client: 10 s."""

DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
"""Default maximum response body accepted by the SDK's default HTTP client: 1 MiB."""


class HttpTargetValidationOptions:
    """Options for ``validate_http_target``."""

    def __init__(self, *, allow_private_targets: bool = False) -> None:
        self.allow_private_targets = allow_private_targets


class HttpSecurityOptions(HttpTargetValidationOptions):
    """Policy of the SDK's default HTTP client (``create_safe_client``): target validation plus limits.

    ``timeout_ms`` is the deadline for the whole request, from the DNS lookup to the last byte of
    the body; a server that sends the body slowly cannot extend it. ``max_response_bytes`` is the
    largest response body accepted. The client asks for an unencoded body (``Accept-Encoding:
    identity``) and rejects a response with any other ``Content-Encoding``, so the limit applies to
    the bytes that are parsed. A caller-supplied ``http_client`` owns its own limits.
    TypeScript parity: ``HttpSecurityOptions`` in ``sdk/src/core/http-security.ts``.
    """

    def __init__(
        self,
        *,
        allow_private_targets: bool = False,
        timeout_ms: int = DEFAULT_HTTP_TIMEOUT_MS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        super().__init__(allow_private_targets=allow_private_targets)
        for name, value in (("timeout_ms", timeout_ms), ("max_response_bytes", max_response_bytes)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise TypeError(f"{name} must be a positive integer")
        self.timeout_ms = timeout_ms
        self.max_response_bytes = max_response_bytes


def resolve_http_client_limits(options: HttpTargetValidationOptions | None) -> tuple[int, int]:
    """``(timeout_ms, max_response_bytes)`` of ``options``, with the defaults for plain target options."""
    if isinstance(options, HttpSecurityOptions):
        return options.timeout_ms, options.max_response_bytes
    return DEFAULT_HTTP_TIMEOUT_MS, DEFAULT_MAX_RESPONSE_BYTES


_LEGACY_IPV4_RE = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.IGNORECASE)
_NUMERIC_LABEL_RE = re.compile(r"^(0x[0-9a-f]*|\d+)$", re.IGNORECASE)
_FORBIDDEN_HOST_CHARS_RE = re.compile(r"[\x00-\x20\x7f#%/:<>?@\[\\\]^|]")


_NON_GLOBAL_IPV4 = tuple(
    ipaddress.IPv4Network(network)
    for network in (
        "0.0.0.0/8",  # this network
        "10.0.0.0/8",  # private
        "100.64.0.0/10",  # shared address space (CGNAT)
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local (cloud metadata)
        "172.16.0.0/12",  # private
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation
        "192.168.0.0/16",  # private
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # documentation
        "203.0.113.0/24",  # documentation
        "224.0.0.0/3",  # multicast, reserved and broadcast
    )
)
_GLOBAL_UNICAST_IPV6 = ipaddress.IPv6Network("2000::/3")
_NON_GLOBAL_IPV6 = tuple(
    ipaddress.IPv6Network(network)
    for network in (
        "2001::/23",  # IETF protocol assignments (Teredo, ORCHID, benchmarking, ...)
        "2001:db8::/32",  # documentation
        "3fff::/20",  # documentation
    )
)
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.IPv6Network("2002::/16")


def _is_non_global(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return *True* for any address that is not globally routable.

    The ranges are listed explicitly (not taken from ``ipaddress.is_global``, which changes between
    Python versions) so the result is identical on every supported interpreter and in the TypeScript SDK.
    """
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in network for network in _NON_GLOBAL_IPV4)

    # IPv4-mapped, NAT64 and 6to4 addresses are judged by the IPv4 address they embed.
    embedded = addr.ipv4_mapped
    if embedded is None and addr in _NAT64:
        embedded = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    if embedded is None and addr in _SIX_TO_FOUR:
        embedded = ipaddress.IPv4Address((int(addr) >> 80) & 0xFFFFFFFF)
    if embedded is not None:
        return _is_non_global(embedded)

    # Fail closed: only global unicast space (2000::/3) is allowed.
    return addr not in _GLOBAL_UNICAST_IPV6 or any(addr in network for network in _NON_GLOBAL_IPV6)


def _is_private_or_reserved(hostname: str) -> bool:
    """Return *True* if *hostname* is a loopback, private, shared, link-local or reserved target."""
    lower = hostname.lower().rstrip(".")
    if lower in ("localhost", "localhost.localdomain") or lower.endswith(".localhost"):
        return True

    # Strip IPv6 bracket notation
    bare = lower.strip("[]")
    try:
        return _is_non_global(ipaddress.ip_address(bare))
    except ValueError:
        pass

    # Legacy IPv4 spellings (``2130706433``, ``0x7f.1``) that resolvers accept.
    if _LEGACY_IPV4_RE.match(bare):
        try:
            return _is_non_global(ipaddress.IPv4Address(socket.inet_aton(bare)))
        except OSError:
            return True

    # Bracketed text that is not an IPv6 literal is never a valid host: fail closed.
    return lower.startswith("[")


def _assert_valid_host(hostname: str) -> None:
    """Reject hosts the TypeScript SDK's WHATWG URL parser rejects (parity), so both fail the same way."""
    if not hostname:
        raise ValueError("Invalid URL: missing host name")
    if ":" in hostname:  # IPv6 literal: classified by ``_is_private_or_reserved``
        return
    if _FORBIDDEN_HOST_CHARS_RE.search(hostname):
        raise ValueError(f"Invalid URL: forbidden character in host name: {hostname!r}")
    # A host whose last label is a number must be a valid IPv4 address ("1.2.3.4.5" is not a name).
    if _NUMERIC_LABEL_RE.match(hostname.rstrip(".").rsplit(".", 1)[-1]) and not _LEGACY_IPV4_RE.match(
        hostname.rstrip(".")
    ):
        raise ValueError(f"Invalid URL: malformed IPv4 address: {hostname}")


def validate_http_target(url: str, options: HttpTargetValidationOptions | None = None) -> None:
    """Validate *url* for SSRF safety.  Raises ``ValueError`` if the URL is unsafe."""
    opts = options or HttpTargetValidationOptions()

    parsed = urlparse(url)

    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"Unsupported protocol: {parsed.scheme}")

    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are not allowed")

    if opts.allow_private_targets:
        return

    hostname = parsed.hostname or ""
    _assert_valid_host(hostname)
    if _is_private_or_reserved(hostname):
        raise ValueError(f"Blocked request to private/reserved address: {hostname}")


LookupFn = Callable[[str], Awaitable[list[str]]]


async def _default_lookup(hostname: str) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def is_non_global_address(address: str) -> bool:
    """Return *True* if *address* (an IPv4 or IPv6 literal) is not globally routable."""
    try:
        return _is_non_global(ipaddress.ip_address(address.strip("[]").split("%", 1)[0]))
    except ValueError:
        return True


async def resolve_allowed_addresses(
    url: str,
    options: HttpTargetValidationOptions | None = None,
    lookup: LookupFn | None = None,
) -> list[str] | None:
    """Resolve the host of *url* and return its addresses, all of which are globally routable.

    Returns ``None`` when there is nothing to pin: the host is an IP literal (already classified by
    ``validate_http_target``) or private targets are allowed. An unresolvable name, or any
    non-global address, raises ``ValueError`` (fail closed). The caller must connect to one of the
    returned addresses instead of resolving the name again, so a DNS answer that changes after this
    check (rebinding) cannot redirect the connection.
    """
    opts = options or HttpTargetValidationOptions()
    if opts.allow_private_targets:
        return None

    hostname = (urlparse(url).hostname or "").strip("[]")
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass
    if _LEGACY_IPV4_RE.match(hostname):
        return None  # classified by validate_http_target

    try:
        addresses = await (lookup or _default_lookup)(hostname)
    except OSError as exc:
        raise ValueError(f"Blocked request: could not resolve {hostname}") from exc
    if not addresses or any(is_non_global_address(address) for address in addresses):
        raise ValueError(f"Blocked request to private/reserved address: {hostname}")
    return addresses


async def assert_resolved_target_allowed(
    url: str,
    options: HttpTargetValidationOptions | None = None,
    lookup: LookupFn | None = None,
) -> None:
    """Like ``resolve_allowed_addresses`` but only checks; it does not pin the connection."""
    await resolve_allowed_addresses(url, options, lookup)
