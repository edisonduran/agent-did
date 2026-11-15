"""Observability tests for the Agent-DID A2A integration."""

from __future__ import annotations

from agent_did_a2a.observability import (
    AgentDidA2AObservabilityEvent,
    compose_event_handlers,
    sanitize_observability_attributes,
    serialize_observability_event,
)


def test_sanitize_observability_attributes_redacts_sensitive() -> None:
    attrs = {
        "did": "did:agent:0x123",
        "private_key": "secret-key-value",
        "url": "https://user:password@example.com/path",
        "headers": {
            "content-type": "application/json",
            "authorization": "Bearer token123",
            "signature": "sig-value",
        },
    }

    sanitized = sanitize_observability_attributes(attrs)

    assert sanitized["did"] == "did:agent:0x123"
    assert sanitized["private_key"] == {"redacted": True, "length": 16}
    # URL credentials stripped
    assert "user" not in sanitized["url"]
    assert "password" not in sanitized["url"]
    # Headers
    assert sanitized["headers"]["content-type"] == "application/json"
    assert sanitized["headers"]["authorization"] == {"redacted": True, "length": 15}
    assert sanitized["headers"]["signature"] == {"redacted": True, "length": 9}


def test_serialize_observability_event_includes_required_fields() -> None:
    event = AgentDidA2AObservabilityEvent(
        event_type="agent_did.a2a.test",
        attributes={"did": "did:agent:0x999"},
    )

    record = serialize_observability_event(event)

    assert record["source"] == "agent_did_a2a"
    assert record["event_type"] == "agent_did.a2a.test"
    assert record["level"] == "info"
    assert "timestamp" in record
    assert record["attributes"]["did"] == "did:agent:0x999"


def test_compose_event_handlers_fans_out() -> None:
    collected: list[str] = []

    def handler_a(event: AgentDidA2AObservabilityEvent) -> None:
        collected.append(f"a:{event.event_type}")

    def handler_b(event: AgentDidA2AObservabilityEvent) -> None:
        collected.append(f"b:{event.event_type}")

    composite = compose_event_handlers(handler_a, None, handler_b)
    composite(AgentDidA2AObservabilityEvent(event_type="test.event"))

    assert collected == ["a:test.event", "b:test.event"]


def test_compose_event_handlers_survives_handler_error() -> None:
    collected: list[str] = []

    def bad_handler(event: AgentDidA2AObservabilityEvent) -> None:
        raise RuntimeError("boom")

    def good_handler(event: AgentDidA2AObservabilityEvent) -> None:
        collected.append(event.event_type)

    composite = compose_event_handlers(bad_handler, good_handler)
    composite(AgentDidA2AObservabilityEvent(event_type="survived"))

    assert collected == ["survived"]
