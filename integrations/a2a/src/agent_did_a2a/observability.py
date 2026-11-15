"""Observability primitives for the Agent-DID A2A integration."""

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
class AgentDidA2AObservabilityEvent:
    """Structured event emitted by the A2A integration."""

    event_type: str
    attributes: dict[str, Any] = field(default_factory=dict)
    level: str = "info"


AgentDidA2AEventHandler = Callable[[AgentDidA2AObservabilityEvent], None]


def compose_event_handlers(*handlers: AgentDidA2AEventHandler | None) -> AgentDidA2AEventHandler:
    """Fan out a sanitized event to multiple handlers."""

    active_handlers = [handler for handler in handlers if handler is not None]

    def composite_handler(event: AgentDidA2AObservabilityEvent) -> None:
        for handler in active_handlers:
            try:
                handler(event)
            except Exception:
                continue

    return composite_handler


def serialize_observability_event(
    event: AgentDidA2AObservabilityEvent,
    *,
    source: str = "agent_did_a2a",
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
        record.update(extra_fields)
    return record


def create_json_logger_event_handler(
    logger_name: str = "agent_did_a2a",
) -> AgentDidA2AEventHandler:
    """Create a handler that logs events as JSON to the named logger."""

    logger = logging.getLogger(logger_name)

    def handler(event: AgentDidA2AObservabilityEvent) -> None:
        record = serialize_observability_event(event)
        log_method = getattr(logger, event.level, logger.info)
        log_method(json.dumps(record, default=str))

    return handler


@dataclass(slots=True)
class AgentDidObserver:
    """Dispatches events to registered handlers."""

    handler: AgentDidA2AEventHandler

    def emit(self, event_type: str, attributes: dict[str, Any] | None = None, level: str = "info") -> None:
        event = AgentDidA2AObservabilityEvent(
            event_type=event_type,
            attributes=attributes or {},
            level=level,
        )
        self.handler(event)
