"""Domain separation for payload signatures (RFC-001 §7).

``sign_message`` signs ``AGENT_DID_MESSAGE_SIGNING_PREFIX + payload``, and ``verify_signature`` /
``verify_signature_at_time`` verify against that same input. The agent key also signs HTTP requests (RFC 9421
signature bases, which start with ``"@method"``) and the controller key signs did:webvh log proofs (JSON
documents): the prefix keeps a payload signature, which a caller may let an agent produce over text it does
not control, from being valid as one of those. TypeScript parity: ``sdk/src/core/message-signing.ts``.
"""

from __future__ import annotations

AGENT_DID_MESSAGE_SIGNING_PREFIX = "agent-did/v1/message\n"
"""Domain tag signed in front of every ``sign_message`` payload."""


def message_signing_input(payload: str) -> bytes:
    """The bytes a payload signature covers: the UTF-8 prefix followed by the UTF-8 payload."""
    return f"{AGENT_DID_MESSAGE_SIGNING_PREFIX}{payload}".encode()
