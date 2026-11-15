"""Observability primitives for the Agent-DID CrewAI integration."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agent_did_sdk import sanitize_observability_attributes as _sdk_sanitize_observability_attributes


def sanitize_observability_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Redact sensitive values before events leave the integration boundary.

    Delegates to :func:`agent_did_sdk.sanitize_observability_attributes`, the one sanitizer every integration uses.
    """

    sanitized = _sdk_sanitize_observability_attributes(dict(attributes))
    return sanitized if isinstance(sanitized, dict) else {}


@dataclass(frozen=True, slots=True)
class AgentDidCrewAIObservabilityEvent:
    """Structured event emitted by the CrewAI integration."""

    event_type: str
    attributes: dict[str, Any] = field(default_factory=dict)
    level: str = "info"


AgentDidCrewAIEventHandler = Callable[[AgentDidCrewAIObservabilityEvent], None]


def compose_event_handlers(*handlers: AgentDidCrewAIEventHandler | None) -> AgentDidCrewAIEventHandler:
    """Fan out a sanitized event to multiple handlers."""

    active_handlers = [handler for handler in handlers if handler is not None]

    def composite_handler(event: AgentDidCrewAIObservabilityEvent) -> None:
        for handler in active_handlers:
            try:
                handler(event)
            except Exception:
                continue

    return composite_handler


def serialize_observability_event(
    event: AgentDidCrewAIObservabilityEvent,
    *,
    source: str = "agent_did_crewai",
    include_timestamp: bool = True,
    extra_fields: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert an event into a JSON-serializable structured record."""

    record: dict[str, Any] = {
        "source": source,
        "event_type": event.event_type,
        "level": event.level,
        "attributes": sanitize_observability_attributes(event.attributes),
    }
    if include_timestamp:
        record["timestamp"] = datetime.now(timezone.utc).isoformat()
    if extra_fields:
        record.update(sanitize_observability_attributes(extra_fields))
    return record


def create_json_logger_event_handler(
    logger: logging.Logger,
    *,
    source: str = "agent_did_crewai",
    include_timestamp: bool = True,
    extra_fields: Mapping[str, Any] | None = None,
) -> AgentDidCrewAIEventHandler:
    """Create an event handler that writes sanitized JSON records to a logger."""

    def log_event(event: AgentDidCrewAIObservabilityEvent) -> None:
        record = serialize_observability_event(
            event,
            source=source,
            include_timestamp=include_timestamp,
            extra_fields=extra_fields,
        )
        logger.log(_to_logging_level(event.level), json.dumps(record, sort_keys=True))

    return log_event


class AgentDidObserver:
    """No-op capable observer for callback and logger based instrumentation."""

    def __init__(
        self,
        *,
        event_handler: AgentDidCrewAIEventHandler | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._event_handler = event_handler
        self._logger = logger

    def emit(self, event_type: str, *, attributes: Mapping[str, Any] | None = None, level: str = "info") -> None:
        sanitized_attributes = sanitize_observability_attributes(attributes or {})
        event = AgentDidCrewAIObservabilityEvent(
            event_type=event_type,
            attributes=sanitized_attributes,
            level=level,
        )

        if self._event_handler is not None:
            try:
                self._event_handler(event)
            except Exception:
                pass

        if self._logger is not None:
            try:
                self._logger.log(
                    _to_logging_level(level),
                    "agent_did_crewai event=%s attributes=%s",
                    event.event_type,
                    event.attributes,
                )
            except Exception:
                pass


def _to_logging_level(level: str) -> int:
    normalized_level = level.lower()
    if normalized_level == "debug":
        return logging.DEBUG
    if normalized_level == "warning":
        return logging.WARNING
    if normalized_level == "error":
        return logging.ERROR
    return logging.INFO
