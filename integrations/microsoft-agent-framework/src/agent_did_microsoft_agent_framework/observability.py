"""Structured observability primitives for the Microsoft Agent Framework integration."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from pydantic import BaseModel, ConfigDict, Field

from .sanitization import sanitize_observability_attributes

AgentDidEventHandler = Callable[["AgentDidMicrosoftAgentFrameworkObservabilityEvent"], None]


class AgentDidMicrosoftAgentFrameworkObservabilityEvent(BaseModel):
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
            try:
                handler(event)
            except Exception:
                continue

    return _composed


def serialize_observability_event(
    event: AgentDidMicrosoftAgentFrameworkObservabilityEvent,
    *,
    include_timestamp: bool = True,
    extra_fields: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload = event.model_dump(exclude_none=True)
    payload["attributes"] = sanitize_observability_attributes(payload.get("attributes", {}))
    if not include_timestamp:
        payload.pop("timestamp", None)
    if extra_fields:
        payload.update(sanitize_observability_attributes(dict(extra_fields)))
    return payload


def create_json_logger_event_handler(
    logger: logging.Logger,
    *,
    include_timestamp: bool = True,
    extra_fields: Mapping[str, Any] | None = None,
) -> AgentDidEventHandler:
    sanitized_extra_fields = sanitize_observability_attributes(dict(extra_fields or {}))

    def _handler(event: AgentDidMicrosoftAgentFrameworkObservabilityEvent) -> None:
        payload = serialize_observability_event(
            event,
            include_timestamp=include_timestamp,
            extra_fields=sanitized_extra_fields,
        )
        logger.info(json.dumps(payload, sort_keys=True))

    return _handler


def create_opentelemetry_tracer(
    *,
    name: str = "agent_did_microsoft_agent_framework",
    version: str | None = None,
    tracer_provider: Any | None = None,
) -> Any:
    if version is None:
        return trace.get_tracer(name, tracer_provider=tracer_provider)
    return trace.get_tracer(name, version, tracer_provider=tracer_provider)


def create_opentelemetry_event_handler(
    tracer: Any,
    *,
    include_timestamp: bool = True,
    extra_fields: Mapping[str, Any] | None = None,
    attributes_namespace: str = "agent_did",
) -> AgentDidEventHandler:
    sanitized_extra_fields = sanitize_observability_attributes(dict(extra_fields or {}))

    def _handler(event: AgentDidMicrosoftAgentFrameworkObservabilityEvent) -> None:
        record = serialize_observability_event(
            event,
            include_timestamp=include_timestamp,
            extra_fields=sanitized_extra_fields,
        )
        with tracer.start_as_current_span(event.event_type) as span:
            for key, value in _flatten_span_attributes(record, namespace=attributes_namespace).items():
                span.set_attribute(key, value)
            span.add_event(event.event_type, _coerce_event_attributes(record, namespace=attributes_namespace))
            if event.level.lower() == "error":
                span.set_status(
                    Status(StatusCode.ERROR, str(record.get("attributes", {}).get("error") or event.event_type))
                )
            else:
                span.set_status(Status(StatusCode.OK))

    return _handler


def _flatten_span_attributes(record: Mapping[str, Any], *, namespace: str) -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in record.items():
        normalized = str(key).replace("-", "_")
        _flatten_value(f"{namespace}.{normalized}", value, flattened)
    return flattened


def _flatten_value(prefix: str, value: Any, flattened: dict[str, Any]) -> None:
    if value is None:
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _flatten_value(f"{prefix}.{str(key).replace('-', '_')}", item, flattened)
        return
    if isinstance(value, (list, tuple)):
        if all(isinstance(item, (str, int, float, bool)) for item in value):
            flattened[prefix] = list(value)
            return
        for index, item in enumerate(value):
            _flatten_value(f"{prefix}.{index}", item, flattened)
        return
    if isinstance(value, (str, int, float, bool)):
        flattened[prefix] = value
        return
    flattened[prefix] = json.dumps(value, sort_keys=True, default=str)


def _coerce_event_attributes(record: Mapping[str, Any], *, namespace: str) -> dict[str, Any]:
    attributes: dict[str, Any] = {}
    for key, value in _flatten_span_attributes(record, namespace=namespace).items():
        if isinstance(value, list):
            attributes[key] = [str(item) for item in value]
        else:
            attributes[key] = value
    return attributes
