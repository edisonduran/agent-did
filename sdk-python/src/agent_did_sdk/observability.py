"""Sanitization of observability data shared by the SDK's framework integrations.

One implementation, used by every integration before an event leaves it (callbacks, loggers, exporters).
TypeScript parity: ``sdk/src/core/observability.ts``.

* A field whose name is sensitive (``payload``, ``body``, ``signature``, ``private_key``, ``token``…; snake_case,
  camelCase and kebab-case spellings alike) is replaced by ``{"redacted": True, "length": n}`` whatever its type.
* A ``url`` keeps scheme, host, port and path; user information, query and fragment are dropped.
* ``headers`` keep their names; sensitive headers (``Authorization``, ``Signature``, ``Cookie``…) are redacted.
* Mappings, lists, tuples, sets, pydantic models and dataclasses are walked recursively. Other objects become
  ``"<TypeName>"``, so their content (for example a framework's output object) never reaches a log by accident.
* The result is JSON-serializable.
"""

from __future__ import annotations

import dataclasses
import enum
import math
from collections.abc import Mapping
from datetime import date, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

__all__ = [
    "SENSITIVE_FIELD_NAMES",
    "SENSITIVE_HEADER_NAMES",
    "is_redacted_marker",
    "is_sensitive_field_name",
    "redact_value",
    "sanitize_headers",
    "sanitize_observability_attributes",
    "sanitize_url",
]

SENSITIVE_FIELD_NAMES: tuple[str, ...] = (
    "accesstoken",
    "agentprivatekey",
    "apikey",
    "authorization",
    "body",
    "clientsecret",
    "cookie",
    "mnemonic",
    "password",
    "payload",
    "privatekey",
    "refreshtoken",
    "secret",
    "seed",
    "signature",
    "signatures",
    "signedpayload",
    "token",
)
"""Sensitive field names, lowercase without ``_`` / ``-`` (see :func:`is_sensitive_field_name`)."""

SENSITIVE_HEADER_NAMES: tuple[str, ...] = (
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "signature",
    "signature-input",
    "x-api-key",
)
"""Sensitive HTTP header names, lowercase."""

_MAX_DEPTH = 32


def is_sensitive_field_name(name: object) -> bool:
    """Whether *name* is a sensitive field name, in any of ``private_key``, ``privateKey``, ``private-key``."""
    return str(name).lower().replace("_", "").replace("-", "") in SENSITIVE_FIELD_NAMES


def redact_value(value: Any) -> dict[str, Any]:
    """The marker that replaces a sensitive value: ``{"redacted": True, "length": n}``."""
    if value is None:
        length = 0
    elif isinstance(value, (str, bytes, bytearray, list, tuple, dict, set, frozenset)):
        length = len(value)
    else:
        length = len(str(value))
    return {"redacted": True, "length": length}


def is_redacted_marker(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("redacted") is True
        and isinstance(value.get("length"), int)
        and len(value) == 2
    )


def sanitize_url(url: str) -> str:
    """*url* without user information, query and fragment.

    A value without scheme and host becomes ``"<invalid url>"``.
    """
    try:
        parsed = urlsplit(url)
        if not parsed.scheme or not parsed.hostname:
            return "<invalid url>"
        netloc = parsed.hostname
        if ":" in netloc:
            netloc = f"[{netloc}]"
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
    except ValueError:
        return "<invalid url>"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def sanitize_headers(headers: Mapping[Any, Any]) -> dict[str, Any]:
    """*headers* with the sensitive ones redacted and the other values sanitized."""
    return {
        str(name): redact_value(value) if str(name).lower() in SENSITIVE_HEADER_NAMES else _sanitize(value, 1, set())
        for name, value in headers.items()
    }


def sanitize_observability_attributes(value: Any) -> Any:
    """Sanitize *value* (usually a mapping of event attributes) as described in the module docstring."""
    return _sanitize(value, 0, set())


def _sanitize(value: Any, depth: int, seen: set[int]) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return "NaN" if math.isnan(value) else ("Infinity" if value > 0 else "-Infinity")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, enum.Enum):
        return _sanitize(value.value, depth, seen)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return redact_value(value)
    if depth >= _MAX_DEPTH:
        return "<max depth>"
    if id(value) in seen:
        return "<cycle>"
    seen = seen | {id(value)}

    mapping = _as_mapping(value)
    if mapping is not None:
        sanitized: dict[str, Any] = {}
        for key, item in mapping.items():
            name = str(key)
            lowered = name.lower()
            if is_sensitive_field_name(name):
                sanitized[name] = item if is_redacted_marker(item) else redact_value(item)
            elif lowered == "url" and isinstance(item, str):
                sanitized[name] = sanitize_url(item)
            elif lowered == "headers" and isinstance(item, Mapping):
                sanitized[name] = sanitize_headers(item)
            else:
                sanitized[name] = _sanitize(item, depth + 1, seen)
        return sanitized
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_sanitize(item, depth + 1, seen) for item in value]
    return f"<{type(value).__name__}>"


def _as_mapping(value: Any) -> Mapping[Any, Any] | None:
    if isinstance(value, Mapping):
        return value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump) and not isinstance(value, type):
        try:
            dumped = model_dump()
        except Exception:
            return None
        return dumped if isinstance(dumped, Mapping) else None
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: getattr(value, field.name) for field in dataclasses.fields(value)}
    return None
