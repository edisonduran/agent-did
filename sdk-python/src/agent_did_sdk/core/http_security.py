"""SSRF protection — validates HTTP target URLs before requests."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

__all__ = ["HttpTargetValidationOptions", "validate_http_target"]


class HttpTargetValidationOptions:
    """Options for ``validate_http_target``."""

    def __init__(self, *, allow_private_targets: bool = False) -> None:
        self.allow_private_targets = allow_private_targets


_LEGACY_IPV4_RE = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.IGNORECASE)


def _is_non_global(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return *True* for any address that is not globally routable."""
    if isinstance(addr, ipaddress.IPv6Address):
        embedded = addr.ipv4_mapped
        if embedded is None and addr in _NAT64:
            embedded = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        if embedded is None and addr in _SIX_TO_FOUR:
            embedded = ipaddress.IPv4Address((int(addr) >> 80) & 0xFFFFFFFF)
        if embedded is not None:
            return _is_non_global(embedded)
        if addr in _IPV6_ZERO_SLASH_8 or addr.is_site_local:
            return True
    return (
        not addr.is_global
        or addr.is_multicast
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_reserved
    )


_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.IPv6Network("2002::/16")
_IPV6_ZERO_SLASH_8 = ipaddress.IPv6Network("::/8")


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
    if _is_private_or_reserved(hostname):
        raise ValueError(f"Blocked request to private/reserved address: {hostname}")
