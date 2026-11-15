"""Sanitization helpers for CrewAI callbacks and output guardrails."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from typing import Any

from agent_did_sdk import is_sensitive_field_name
from pydantic import BaseModel


def normalize_output(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(exclude_none=True)
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, Mapping):
        return {str(key): normalize_output(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [normalize_output(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "__dict__"):
        return normalize_output(vars(value))
    return repr(value)


def sanitize_output(value: Any) -> Any:
    normalized = normalize_output(value)
    if isinstance(normalized, dict):
        sanitized: dict[str, Any] = {}
        for key, item in normalized.items():
            if is_sensitive_field_name(key):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_output(item)
        return sanitized
    if isinstance(normalized, list):
        return [sanitize_output(item) for item in normalized]
    return normalized


def find_sensitive_paths(value: Any, prefix: str = "") -> list[str]:
    normalized = normalize_output(value)
    if isinstance(normalized, dict):
        paths: list[str] = []
        for key, item in normalized.items():
            current_path = f"{prefix}.{key}" if prefix else key
            if is_sensitive_field_name(key):
                paths.append(current_path)
            paths.extend(find_sensitive_paths(item, current_path))
        return paths
    if isinstance(normalized, list):
        indexed_paths: list[str] = []
        for index, item in enumerate(normalized):
            current_path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            indexed_paths.extend(find_sensitive_paths(item, current_path))
        return indexed_paths
    return []
