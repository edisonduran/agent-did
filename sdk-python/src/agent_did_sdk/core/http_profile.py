"""Constants and helpers of the Agent-DID HTTP Message Signature profile (RFC 9421)."""

from __future__ import annotations

import base64
import hashlib

AGENT_DID_HTTP_SIGNATURE_COMPONENTS: tuple[str, ...] = (
    "@method",
    "@authority",
    "@path",
    "@query",
    "content-digest",
    "date",
    "signature-agent",
)
"""Components every Agent-DID HTTP Message Signature covers (RFC 9421)."""

AGENT_DID_HTTP_SIGNATURE_TAG = "agent-did"
"""RFC 9421 ``tag`` parameter of Agent-DID HTTP Message Signatures."""


def compute_content_digest(body: str | bytes | None) -> str:
    """RFC 9530 ``Content-Digest`` with SHA-256 of the body bytes (a string is hashed as UTF-8)."""
    raw = body.encode("utf-8") if isinstance(body, str) else (body or b"")
    digest = hashlib.sha256(raw).digest()
    b64 = base64.b64encode(digest).decode("ascii")
    return f"sha-256=:{b64}:"
