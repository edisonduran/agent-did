"""Sanitization helpers for middleware and observability payloads."""

from __future__ import annotations

from typing import Any

from agent_did_sdk import (
    SENSITIVE_FIELD_NAMES,
    SENSITIVE_HEADER_NAMES,
    is_redacted_marker,
    is_sensitive_field_name,
    redact_value,
    sanitize_headers,
    sanitize_observability_attributes,
    sanitize_url,
)

__all__ = [
    "SENSITIVE_FIELD_NAMES",
    "SENSITIVE_HEADER_NAMES",
    "is_redacted_marker",
    "redact_value",
    "sanitize_headers",
    "sanitize_observability_attributes",
    "sanitize_callback_payload",
    "sanitize_url",
]

def sanitize_callback_payload(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if is_sensitive_field_name(key):
                sanitized[key] = "[REDACTED]"
            elif key.lower() == "url" and isinstance(item, str):
                sanitized[key] = sanitize_url(item)
            else:
                sanitized[key] = sanitize_callback_payload(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_callback_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_callback_payload(item) for item in value)
    return value
