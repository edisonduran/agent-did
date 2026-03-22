"""Sanitization helpers for middleware and observability payloads."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

SENSITIVE_FIELD_NAMES = {
    "payload",
    "body",
    "signature",
    "signatures",
    "private_key",
    "agent_private_key",
    "seed",
    "mnemonic",
    "authorization",
    "token",
    "api_key",
}
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "signature",
    "signature-input",
    "cookie",
    "set-cookie",
    "x-api-key",
}


def _redacted_length(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, (str, bytes, list, tuple, dict, set)):
        return len(value)
    return len(str(value))


def redact_value(value: Any) -> dict[str, Any]:
    return {"redacted": True, "length": _redacted_length(value)}


def is_redacted_marker(value: Any) -> bool:
    return isinstance(value, dict) and value.get("redacted") is True and isinstance(value.get("length"), int)


def sanitize_url(url: str) -> str:
    parsed = urlsplit(url)
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def sanitize_observability_attributes(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = key.lower()
            if normalized_key in SENSITIVE_FIELD_NAMES:
                sanitized[key] = item if is_redacted_marker(item) else redact_value(item)
            elif normalized_key == "url" and isinstance(item, str):
                sanitized[key] = sanitize_url(item)
            elif normalized_key == "headers" and isinstance(item, dict):
                sanitized[key] = sanitize_headers(item)
            else:
                sanitized[key] = sanitize_observability_attributes(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_observability_attributes(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_observability_attributes(item) for item in value)
    return value


def sanitize_headers(headers: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADER_NAMES:
            sanitized[key] = redact_value(value)
        else:
            sanitized[key] = value
    return sanitized


def sanitize_callback_payload(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in SENSITIVE_FIELD_NAMES:
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
