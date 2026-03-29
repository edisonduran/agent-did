"""SSRF protection — validates HTTP target URLs before requests."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

__all__ = ["HttpTargetValidationOptions", "validate_http_target"]


class HttpTargetValidationOptions:
    """Options for ``validate_http_target``."""

    def __init__(self, *, allow_private_targets: bool = False) -> None:
        self.allow_private_targets = allow_private_targets


def _is_private_or_reserved(hostname: str) -> bool:
    """Return *True* if *hostname* resolves to a loopback, private, or link-local address."""
    lower = hostname.lower()
    if lower in ("localhost", "localhost.localdomain"):
        return True

    # Strip IPv6 bracket notation
    bare = hostname.strip("[]")
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        return False

    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_unspecified
    )


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
