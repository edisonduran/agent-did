from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

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


def _require_env(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


async def main() -> None:
    if os.environ.get("RUN_SEMANTIC_KERNEL_PRODUCTION_EXAMPLE") != "1":
        print("Set RUN_SEMANTIC_KERNEL_PRODUCTION_EXAMPLE=1 to run this operational recipe.")
        return

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("agent_did_semantic_kernel.production")

    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = create_opentelemetry_tracer(tracer_provider=provider)

    local_events: list[dict[str, Any]] = []
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], network="polygon"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="semantic_kernel_production_recipe",
            description="Production-oriented Semantic Kernel recipe for Agent-DID",
            core_model="gpt-4.1-mini",
            system_prompt="Actua como un agente verificable y conservador con operaciones sensibles.",
            capabilities=["identity:inspect", "signature:verify", "key:rotate", "audit:events"],
        )
    )

    integration = create_agent_did_semantic_kernel_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "rotate_keys": True, "document_history": True, "sign_http": True},
        observability_handler=compose_event_handlers(
            lambda event: local_events.append(serialize_observability_event(event, include_timestamp=False)),
            create_json_logger_event_handler(
                logger,
                include_timestamp=False,
                extra_fields={"service": "agent-did-demo", "environment": "local-prod-sim"},
            ),
            create_opentelemetry_event_handler(
                tracer,
                include_timestamp=False,
                extra_fields={"service": "agent-did-demo", "environment": "local-prod-sim"},
            ),
        ),
    )

    try:
        from semantic_kernel.agents.chat_completion.chat_completion_agent import ChatCompletionAgent
        from semantic_kernel.kernel import Kernel
    except ImportError as error:
        raise RuntimeError(
            "Install runtime and observability extras first: python -m pip install -e .[runtime,observability]"
        ) from error

    plugin = integration.create_semantic_kernel_plugin(plugin_name="agent_did_runtime")
    kernel = Kernel()
    kernel.add_plugin(plugin)
    ChatCompletionAgent(
        name="ProductionVerifier",
        instructions=integration.compose_instructions(
            "Antes de firmar o rotar claves, inspecciona el estado Agent-DID y conserva trazabilidad saneada."
        ),
        kernel=kernel,
        plugins=[plugin],
    )

    context_middleware = integration.create_context_middleware(context_key="runtime_agent_did")
    initial_context = context_middleware({"environment": "prod-sim", "session_id": "demo"})
    signed_payload = await kernel.invoke(
        function_name="agent_did_sign_payload",
        plugin_name="agent_did_runtime",
        payload="production-sensitive-payload",
    )
    verification = await kernel.invoke(
        function_name="agent_did_verify_signature",
        plugin_name="agent_did_runtime",
        did=runtime_identity.document.id,
        key_id=signed_payload.value["key_id"],
        payload=signed_payload.value["payload"],
        signature=signed_payload.value["signature"],
    )
    rotation = await kernel.invoke(
        function_name="agent_did_rotate_key",
        plugin_name="agent_did_runtime",
    )
    rotated_context = context_middleware({"environment": "prod-sim", "session_id": "demo", "step": "rotated"})
    history = await kernel.invoke(
        function_name="agent_did_get_document_history",
        plugin_name="agent_did_runtime",
    )
    signed_http = await kernel.invoke(
        function_name="agent_did_sign_http_request",
        plugin_name="agent_did_runtime",
        method="POST",
        url="https://api.example.com/tasks?debug=true",
        body='{"taskId": 42}',
    )

    print("Initial context:")
    print(json.dumps(initial_context, indent=2))
    print("\nVerification result:")
    print(json.dumps(verification.value, indent=2))
    print("\nRotation result:")
    print(json.dumps(rotation.value, indent=2))
    print("\nRotated context:")
    print(json.dumps(rotated_context, indent=2))
    print("\nDocument history entries:", len(history.value))
    print("Signed HTTP headers:")
    print(json.dumps(signed_http.value["headers"], indent=2))
    print("\nCaptured local events:")
    print(json.dumps(local_events, indent=2))
    print("\nFinished spans:")
    print(
        json.dumps(
            [
                {"name": span.name, "attributes": dict(span.attributes)}
                for span in exporter.get_finished_spans()
            ],
            indent=2,
            default=str,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
