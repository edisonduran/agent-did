"""Cryptographic hash utilities for Agent-DID metadata."""

from __future__ import annotations

import hashlib
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
