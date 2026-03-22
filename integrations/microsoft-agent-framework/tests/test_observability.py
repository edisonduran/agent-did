from __future__ import annotations

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agent_did_microsoft_agent_framework.observability import (
    AgentDidMicrosoftAgentFrameworkObservabilityEvent,
    create_opentelemetry_event_handler,
    create_opentelemetry_tracer,
    serialize_observability_event,
)


def test_serialize_observability_event_redacts_sensitive_attributes() -> None:
    event = AgentDidMicrosoftAgentFrameworkObservabilityEvent(
        event_type="agent_did.tool.started",
        attributes={
            "payload": "secret-body",
            "signature": "super-secret-signature",
            "headers": {"Authorization": "Bearer secret-token"},
            "url": "https://user:pass@example.com/demo?token=hidden",
        },
    )

    payload = serialize_observability_event(event, include_timestamp=False)

    assert payload["attributes"]["payload"]["redacted"] is True
    assert payload["attributes"]["signature"]["redacted"] is True
    assert payload["attributes"]["headers"]["Authorization"]["redacted"] is True
    assert payload["attributes"]["url"] == "https://example.com/demo"


def test_opentelemetry_event_handler_projects_redacted_attributes_into_spans() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = create_opentelemetry_tracer(tracer_provider=provider)
    handler = create_opentelemetry_event_handler(tracer)

    handler(
        AgentDidMicrosoftAgentFrameworkObservabilityEvent(
            event_type="agent_did.tool.started",
            attributes={
                "tool_name": "agent_did_sign_payload",
                "did": "did:example:123",
                "payload": "very-secret",
            },
        )
    )

    spans = exporter.get_finished_spans()

    assert len(spans) == 1
    assert spans[0].attributes["agent_did.attributes.payload.redacted"] is True
    assert spans[0].attributes["agent_did.attributes.payload.length"] == len("very-secret")
