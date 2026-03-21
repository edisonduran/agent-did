"""Timestamp normalisation utilities (ISO-8601 ↔ Unix seconds)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

_UNIX_RE = re.compile(r"^\d+$")


def is_unix_timestamp_string(value: str) -> bool:
    """Return ``True`` if *value* looks like a plain Unix-seconds string."""
    return bool(_UNIX_RE.match(value.strip()))


def unix_string_to_iso(value: str) -> str:
    """Convert a Unix-seconds string to an ISO-8601 UTC string."""
    if not is_unix_timestamp_string(value):
        raise ValueError(f"Invalid unix timestamp string: {value}")
    seconds = int(value)
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def iso_to_unix_string(value: str) -> str:
    """Convert an ISO-8601 string to Unix-seconds (integer) string."""
    # Handle the Z suffix
    normalized = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO timestamp: {value}") from exc
    return str(int(dt.timestamp()))


def normalize_timestamp_to_iso(value: str | None) -> str | None:
    """If *value* is a Unix-seconds string convert it, otherwise return as-is."""
    if not value:
        return None

    if is_unix_timestamp_string(value):
        return unix_string_to_iso(value)

    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid ISO timestamp: {value}") from exc

    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt_utc.microsecond // 1000:03d}Z"
