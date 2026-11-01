"""Observability primitives for the Agent-DID LangChain integration."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REDACTED_VALUE = "<redacted>"
SENSITIVE_FIELD_NAMES = {
    "agent_private_key",
    "body",
    "payload",
    "signature",
}
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "signature",
    "signature-input",
    "x-api-key",
}


@dataclass(frozen=True, slots=True)
class AgentDidObservabilityEvent:
    """Structured event emitted by the integration and tools."""

    event_type: str
    attributes: dict[str, Any] = field(default_factory=dict)
    level: str = "info"


AgentDidEventHandler = Callable[[AgentDidObservabilityEvent], None]


def compose_event_handlers(*handlers: AgentDidEventHandler | None) -> AgentDidEventHandler:
    """Fan out a sanitized event to multiple handlers."""

    active_handlers = [handler for handler in handlers if handler is not None]

    def composite_handler(event: AgentDidObservabilityEvent) -> None:
        for handler in active_handlers:
            try:
                handler(event)
            except Exception:
                continue

    return composite_handler


def serialize_observability_event(
    event: AgentDidObservabilityEvent,
    *,
    source: str = "agent_did_langchain",
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
    source: str = "agent_did_langchain",
    include_timestamp: bool = True,
    extra_fields: Mapping[str, Any] | None = None,
) -> AgentDidEventHandler:
    """Create an event handler that writes sanitized JSON records to a logger."""

    def log_event(event: AgentDidObservabilityEvent) -> None:
        record = serialize_observability_event(
            event,
            source=source,
            include_timestamp=include_timestamp,
            extra_fields=extra_fields,
        )
        logger.log(_to_logging_level(event.level), json.dumps(record, sort_keys=True))

    return log_event


def create_langsmith_run_tree(
    *,
    name: str,
    project_name: str = "agent-did-langchain",
    run_type: str = "chain",
    inputs: Mapping[str, Any] | None = None,
    tags: list[str] | None = None,
    extra: Mapping[str, Any] | None = None,
    client: Any | None = None,
) -> Any:
    """Create a LangSmith RunTree with sanitized root inputs and metadata."""

    try:
        from langsmith.run_trees import RunTree
    except ImportError as error:  # pragma: no cover - depends on optional runtime package
        raise RuntimeError("LangSmith is required for the LangSmith observability adapter") from error

    return RunTree(
        name=name,
        run_type=run_type,
        project_name=project_name,
        inputs=sanitize_observability_attributes(inputs or {}),
        tags=list(tags or []),
        extra=sanitize_observability_attributes(extra or {}),
        ls_client=client,
    )


def create_langsmith_event_handler(
    run_tree: Any,
    *,
    source: str = "agent_did_langchain",
    include_timestamp: bool = True,
    extra_fields: Mapping[str, Any] | None = None,
    tags: list[str] | None = None,
    post_immediately: bool = False,
) -> AgentDidEventHandler:
    """Create a LangSmith handler that maps Agent-DID events into a RunTree."""

    active_tool_runs: dict[tuple[str, str], Any] = {}
    normalized_tags = list(tags or [])

    def handle_event(event: AgentDidObservabilityEvent) -> None:
        record = serialize_observability_event(
            event,
            source=source,
            include_timestamp=include_timestamp,
            extra_fields=extra_fields,
        )
        attributes = record["attributes"]
        tool_name = attributes.get("tool_name")
        did = attributes.get("did")
        event_type = event.event_type

        try:
            run_tree.add_event(record)
        except Exception:
            pass

        if _is_langsmith_tool_event(tool_name, did, event_type):
            _handle_langsmith_tool_event(
                run_tree,
                active_tool_runs,
                normalized_tags,
                source,
                post_immediately,
                tool_name,
                did,
                event_type,
                attributes,
                record,
            )
            return

        _handle_langsmith_generic_event(
            run_tree,
            normalized_tags,
            source,
            post_immediately,
            event_type,
            attributes,
            record,
        )

    return handle_event


def _is_langsmith_tool_event(tool_name: Any, did: Any, event_type: str) -> bool:
    return isinstance(tool_name, str) and isinstance(did, str) and event_type.startswith("agent_did.tool.")


def _create_langsmith_child_run(
    run_tree: Any,
    *,
    name: str,
    run_type: str,
    inputs: dict[str, Any],
    tags: list[str],
    source: str,
    event_type: str,
) -> Any:
    child_run = run_tree.create_child(
        name=name,
        run_type=run_type,
        inputs=inputs,
        tags=tags,
        extra={"source": source, "agent_did_event_type": event_type},
    )
    # langsmith>=0.14 appends inside create_child; older releases do not.
    if not any(existing is child_run for existing in run_tree.child_runs):
        run_tree.child_runs.append(child_run)
    return child_run


def _handle_langsmith_tool_event(
    run_tree: Any,
    active_tool_runs: dict[tuple[str, str], Any],
    normalized_tags: list[str],
    source: str,
    post_immediately: bool,
    tool_name: str,
    did: str,
    event_type: str,
    attributes: dict[str, Any],
    record: dict[str, Any],
) -> None:
    run_key = (tool_name, did)
    child_run = active_tool_runs.get(run_key)

    if event_type.endswith(".started"):
        child_run = _create_langsmith_child_run(
            run_tree,
            name=tool_name,
            run_type="tool",
            inputs={"did": did, "inputs": attributes.get("inputs", {}), "event_type": event_type},
            tags=[*normalized_tags, "agent-did", "tool"],
            source=source,
            event_type=event_type,
        )
        child_run.add_event(record)
        active_tool_runs[run_key] = child_run
        return

    if child_run is None:
        child_run = _create_langsmith_child_run(
            run_tree,
            name=tool_name,
            run_type="tool",
            inputs={"did": did, "event_type": event_type},
            tags=[*normalized_tags, "agent-did", "tool"],
            source=source,
            event_type=event_type,
        )

    child_run.add_event(record)
    _finalize_langsmith_child_run(child_run, did=did, event_type=event_type, attributes=attributes)

    active_tool_runs.pop(run_key, None)
    if post_immediately:
        child_run.post()


def _finalize_langsmith_child_run(
    child_run: Any,
    *,
    did: str,
    event_type: str,
    attributes: dict[str, Any],
) -> None:
    outputs = {"did": did, "event_type": event_type, "attributes": attributes}
    if event_type.endswith(".failed"):
        child_run.end(error=str(attributes.get("error") or "unknown error"), outputs=outputs)
        return
    child_run.end(outputs=outputs)


def _handle_langsmith_generic_event(
    run_tree: Any,
    normalized_tags: list[str],
    source: str,
    post_immediately: bool,
    event_type: str,
    attributes: dict[str, Any],
    record: dict[str, Any],
) -> None:
    child_run = _create_langsmith_child_run(
        run_tree,
        name=event_type,
        run_type="chain",
        inputs={"event_type": event_type, "attributes": attributes},
        tags=[*normalized_tags, "agent-did", "event"],
        source=source,
        event_type=event_type,
    )
    child_run.add_event(record)
    child_run.end(outputs={"event_type": event_type, "attributes": attributes})
    if post_immediately:
        child_run.post()


def sanitize_observability_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Redact sensitive values before events leave the integration boundary."""

    return {str(key): _sanitize_value(str(key), value) for key, value in attributes.items()}


class AgentDidObserver:
    """No-op capable observer for callback and logger based instrumentation."""

    def __init__(
        self,
        *,
        event_handler: AgentDidEventHandler | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._event_handler = event_handler
        self._logger = logger

    def emit(self, event_type: str, *, attributes: Mapping[str, Any] | None = None, level: str = "info") -> None:
        sanitized_attributes = sanitize_observability_attributes(attributes or {})
        event = AgentDidObservabilityEvent(
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
                    "agent_did_langchain event=%s attributes=%s",
                    event.event_type,
                    event.attributes,
                )
            except Exception:
                pass


def _sanitize_value(field_name: str, value: Any) -> Any:
    normalized_field_name = field_name.lower()

    if normalized_field_name in SENSITIVE_FIELD_NAMES and isinstance(value, str):
        return {"redacted": True, "length": len(value)}

    if normalized_field_name == "url" and isinstance(value, str):
        return _sanitize_url(value)

    if isinstance(value, Mapping):
        if normalized_field_name == "headers":
            return _sanitize_headers(value)
        return {str(key): _sanitize_value(str(key), nested_value) for key, nested_value in value.items()}

    if isinstance(value, list):
        return [_sanitize_value(field_name, item) for item in value]

    if isinstance(value, tuple):
        return tuple(_sanitize_value(field_name, item) for item in value)

    return value


def _sanitize_headers(headers: Mapping[str, Any]) -> dict[str, Any]:
    sanitized_headers: dict[str, Any] = {}
    for header_name, header_value in headers.items():
        normalized_header_name = str(header_name).lower()
        if normalized_header_name in SENSITIVE_HEADER_NAMES:
            sanitized_headers[str(header_name)] = REDACTED_VALUE
        else:
            sanitized_headers[str(header_name)] = _sanitize_value(str(header_name), header_value)
    return sanitized_headers


def _sanitize_url(url: str) -> str:
    parsed = urlsplit(url)
    netloc = parsed.hostname or ""
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def _to_logging_level(level: str) -> int:
    normalized_level = level.lower()
    if normalized_level == "debug":
        return logging.DEBUG
    if normalized_level == "warning":
        return logging.WARNING
    if normalized_level == "error":
        return logging.ERROR
    return logging.INFO
