"""Structured observability primitives for the Microsoft Agent Framework integration."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .sanitization import sanitize_observability_attributes

AgentDidEventHandler = Callable[["AgentDidMicrosoftAgentFrameworkObservabilityEvent"], None]


class AgentDidMicrosoftAgentFrameworkObservabilityEvent(BaseModel):
    """Typed event emitted by tools, middleware and context helpers."""

    model_config = ConfigDict(extra="forbid")

    event_type: str
    level: str = "info"
    attributes: dict[str, Any] = Field(default_factory=dict)
    source: str = "agent_did_microsoft_agent_framework"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))


@dataclass(slots=True)
class AgentDidObserver:
    event_handler: AgentDidEventHandler | None = None
    logger: logging.Logger | None = None

    def emit(self, event_type: str, *, attributes: dict[str, Any] | None = None, level: str = "info") -> None:
        event = AgentDidMicrosoftAgentFrameworkObservabilityEvent(
            event_type=event_type,
            level=level,
            attributes=sanitize_observability_attributes(attributes or {}),
        )
        if self.event_handler is not None:
            self.event_handler(event)
        if self.logger is not None:
            log_method = getattr(self.logger, level.lower(), self.logger.info)
            log_method(json.dumps(serialize_observability_event(event), sort_keys=True))


def compose_event_handlers(*handlers: AgentDidEventHandler | None) -> AgentDidEventHandler:
    active_handlers = [handler for handler in handlers if handler is not None]

    def _composed(event: AgentDidMicrosoftAgentFrameworkObservabilityEvent) -> None:
        for handler in active_handlers:
            handler(event)

    return _composed


def serialize_observability_event(event: AgentDidMicrosoftAgentFrameworkObservabilityEvent) -> dict[str, Any]:
    payload = event.model_dump(exclude_none=True)
    payload["attributes"] = sanitize_observability_attributes(payload.get("attributes", {}))
    return payload


def create_json_logger_event_handler(
    logger: logging.Logger,
    *,
    include_timestamp: bool = True,
    extra_fields: dict[str, Any] | None = None,
) -> AgentDidEventHandler:
    sanitized_extra_fields = sanitize_observability_attributes(extra_fields or {})

    def _handler(event: AgentDidMicrosoftAgentFrameworkObservabilityEvent) -> None:
        payload = serialize_observability_event(event)
        if not include_timestamp:
            payload.pop("timestamp", None)
        payload.update(sanitized_extra_fields)
        logger.info(json.dumps(payload, sort_keys=True))

    return _handler


__all__ = [
    "AgentDidEventHandler",
    "AgentDidMicrosoftAgentFrameworkObservabilityEvent",
    "AgentDidObserver",
    "compose_event_handlers",
    "create_json_logger_event_handler",
    "sanitize_observability_attributes",
    "serialize_observability_event",
]
