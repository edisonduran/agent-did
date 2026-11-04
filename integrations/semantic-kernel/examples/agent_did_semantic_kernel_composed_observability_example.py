from __future__ import annotations

import asyncio
import json
import logging

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agent_did_semantic_kernel import create_agent_did_semantic_kernel_integration
from agent_did_semantic_kernel.observability import (
    compose_event_handlers,
    create_json_logger_event_handler,
    create_opentelemetry_event_handler,
    create_opentelemetry_tracer,
    serialize_observability_event,
)


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("agent_did_semantic_kernel.composed_observability")

    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="semantic_kernel_composed_observability",
            description="Composed observability demo for semantic-kernel",
            core_model="gpt-4.1-mini",
            system_prompt="Demuestra observabilidad compuesta y saneada.",
            capabilities=["identity:resolve", "signature:sign"],
        )
    )

    local_events: list[dict[str, object]] = []
    tracer = create_opentelemetry_tracer(tracer_provider=provider)
    integration = create_agent_did_semantic_kernel_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "sign_http": True},
        observability_handler=compose_event_handlers(
            lambda event: local_events.append(serialize_observability_event(event, include_timestamp=False)),
            create_json_logger_event_handler(logger, include_timestamp=False, extra_fields={"sink": "json"}),
            create_opentelemetry_event_handler(tracer, include_timestamp=False, extra_fields={"sink": "otel"}),
        ),
    )

    tools_by_name = {tool.name: tool for tool in integration.tools}
    await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": "payload-sensitive-demo"})
    await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {
            "method": "POST",
            "url": "https://api.example.com/observability?debug=true",
            "body": '{"secret":"value"}',
        }
    )

    print("Local events:")
    print(json.dumps(local_events, indent=2))
    print("\nFinished spans:")
    print(
        json.dumps(
            [
                {
                    "name": span.name,
                    "attributes": dict(span.attributes),
                }
                for span in exporter.get_finished_spans()
            ],
            indent=2,
            default=str,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
