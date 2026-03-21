"""Cryptographic hash utilities for Agent-DID metadata."""

from __future__ import annotations

import hashlib
import json


def _is_timestamp_key(key: str | None) -> bool:
    return key in {"created", "updated", "timestamp"}


def _normalize_timestamp_value(value: str) -> str:
    from agent_did_sdk.core.time_utils import normalize_timestamp_to_iso

    normalized = normalize_timestamp_to_iso(value)
    return normalized if normalized is not None else value


def _canonicalize_json_value(value: object, key: str | None = None) -> object:
    if isinstance(value, str) and _is_timestamp_key(key):
        return _normalize_timestamp_value(value)

    if isinstance(value, list):
        return [_canonicalize_json_value(item) for item in value]

    if isinstance(value, dict):
        return {
            entry_key: _canonicalize_json_value(entry_value, entry_key)
            for entry_key, entry_value in sorted(value.items())
            if entry_value is not None
        }

    return value


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
    """Return a deterministic JSON string with sorted keys and normalized timestamps."""
    return json.dumps(_canonicalize_json_value(value), separators=(",", ":"), ensure_ascii=False)


def generate_canonical_document_hash(document: object) -> str:
    """Return the canonical ``hash://`` reference for a DID document-like payload."""
    return generate_agent_metadata_hash(canonicalize_json(document))
