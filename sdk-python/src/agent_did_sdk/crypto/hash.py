"""Cryptographic hash utilities for Agent-DID metadata."""

from __future__ import annotations

import hashlib


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
