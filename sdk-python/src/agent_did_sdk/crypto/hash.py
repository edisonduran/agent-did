"""Cryptographic hash utilities for Agent-DID metadata."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import Any, cast

import rfc8785


def hash_payload(payload: str) -> str:
    """Generate a deterministic SHA-256 hash of a string payload.

    Used to protect intellectual property (like system prompts) while allowing verification.
    Returns a hex string with ``0x`` prefix.
    """
    if not payload:
        raise ValueError("Payload cannot be empty")
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"0x{digest}"


def format_hash_uri(hash_hex: str) -> str:
    """Format a raw hex hash into a ``hash://sha256/…`` URI."""
    clean = hash_hex.removeprefix("0x")
    return f"hash://sha256/{clean}"


def generate_agent_metadata_hash(payload: str) -> str:
    """Hash *payload* and return it as a ``hash://`` URI in one step."""
    return format_hash_uri(hash_payload(payload))


def canonicalize_json(value: object) -> str:
    """Return the RFC 8785 (JCS) canonical JSON serialization of *value*.

    Values are hashed exactly as given: no field (timestamps included) is rewritten
    before canonicalization, and ``None`` serializes as ``null``.

    Raises:
        rfc8785.CanonicalizationError: for values JCS cannot represent, such as
            non-finite floats or integers outside the IEEE-754 safe integer range.
    """
    # rfc8785 validates the value tree itself and raises on unsupported types.
    return rfc8785.dumps(cast(Any, value)).decode("utf-8")


def generate_canonical_document_hash(document: object) -> str:
    """Return the ``hash://sha256/<hex>`` reference of a DID document.

    The digest is SHA-256 over the UTF-8 bytes of the document's RFC 8785 (JCS)
    canonical form.
    """
    return generate_agent_metadata_hash(canonicalize_json(document))


_HMAC_SHA256_COMMITMENT_PREFIX = "hash://hmac-sha256/"
_SHA256_COMMITMENT_PREFIX = "hash://sha256/"
_COMMITMENT_SALT_BYTES = 32
_SALT_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _parse_commitment_salt(salt_hex: str) -> bytes:
    if not isinstance(salt_hex, str) or not _SALT_HEX_RE.match(salt_hex):
        raise ValueError(
            f"Commitment salt must be {_COMMITMENT_SALT_BYTES} bytes encoded as 64 hex characters"
        )
    return bytes.fromhex(salt_hex)


def generate_commitment_salt() -> str:
    """Return a random 32-byte salt (64 lowercase hex characters) for a metadata commitment.

    The controller keeps the salt private and reveals it only to parties allowed to verify
    the committed value.
    """
    return secrets.token_hex(_COMMITMENT_SALT_BYTES)


def create_metadata_commitment(value: str, salt_hex: str) -> str:
    """Commit to a metadata value (system prompt, model identifier) without making it guessable.

    Returns ``hash://hmac-sha256/<hex(HMAC-SHA256(key = salt, message = UTF-8(value)))>``.
    """
    if not value:
        raise ValueError("Commitment value cannot be empty")
    digest = hmac.new(_parse_commitment_salt(salt_hex), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{_HMAC_SHA256_COMMITMENT_PREFIX}{digest}"


def verify_metadata_commitment(commitment_uri: str, value: str, salt_hex: str | None = None) -> bool:
    """Check a revealed value (and salt) against a metadata commitment URI.

    ``hash://hmac-sha256/...`` requires the salt used at commitment time.
    ``hash://sha256/...`` (unsalted, produced by ``1.0.0rc2`` and earlier) ignores the salt.
    Returns ``False`` for a mismatch, an unknown scheme, or a missing or malformed salt.
    """
    if not value or not isinstance(commitment_uri, str):
        return False

    normalized_uri = commitment_uri.lower()
    if normalized_uri.startswith(_HMAC_SHA256_COMMITMENT_PREFIX):
        if salt_hex is None:
            return False
        try:
            expected = create_metadata_commitment(value, salt_hex)
        except ValueError:
            return False
    elif normalized_uri.startswith(_SHA256_COMMITMENT_PREFIX):
        expected = generate_agent_metadata_hash(value)
    else:
        return False

    return hmac.compare_digest(expected.encode("utf-8"), normalized_uri.encode("utf-8"))
