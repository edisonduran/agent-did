from __future__ import annotations

import asyncio
import logging

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry
from agent_framework import BaseChatClient, ChatResponse, Message
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agent_did_microsoft_agent_framework import create_agent_did_microsoft_agent_framework_integration
from agent_did_microsoft_agent_framework.observability import (
    compose_event_handlers,
    create_json_logger_event_handler,
    create_opentelemetry_event_handler,
    create_opentelemetry_tracer,
)


def _extract_message_text(message: object) -> str:
    legacy_text = getattr(message, "text", None)
    if isinstance(legacy_text, str) and legacy_text:
        return legacy_text

    contents = getattr(message, "contents", None) or ()
    text_parts: list[str] = []
    for content in contents:
        if isinstance(content, str):
            text_parts.append(content)
            continue

        text_value = getattr(content, "text", None)
        if isinstance(text_value, str) and text_value:
            text_parts.append(text_value)

    return "".join(text_parts) or "none"


class DummyChatClient(BaseChatClient):
    def __init__(self, label: str):
        super().__init__()
        self.label = label

    async def _inner_get_response(self, *, messages, stream, options, **kwargs):  # type: ignore[override]
        text = _extract_message_text(messages[-1]) if messages else "none"
        response_text = f"{self.label}:{text}"
        return ChatResponse(
            messages=Message("assistant", [response_text]),
            finish_reason="stop",
            value=response_text,
        )


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    logger = logging.getLogger("agent_did_microsoft_agent_framework.production")
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())

    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = create_opentelemetry_tracer(tracer_provider=tracer_provider)
    events = []

    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x5959595959595959595959595959595959595959"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="MicrosoftAgentFrameworkProductionBot",
            description="Production-style recipe for Agent-DID + Microsoft Agent Framework",
            core_model="gpt-4.1-mini",
            system_prompt="Coordinate verifiable identity operations in production style.",
            capabilities=["identity:resolve", "signature:verify", "workflow:run", "http:sign", "key:rotate"],
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "sign_http": True, "rotate_keys": True, "document_history": True},
        observability_handler=compose_event_handlers(
            events.append,
            create_json_logger_event_handler(logger, extra_fields={"service": "agent-gateway"}),
            create_opentelemetry_event_handler(tracer, extra_fields={"service": "agent-gateway"}),
        ),
    )

    verifier = integration.create_agent(
        DummyChatClient("verifier"),
        name="Verifier",
        description="Identity verifier",
        base_instructions="Use Agent-DID tools when identity evidence matters.",
    )
    reviewer = integration.create_agent(
        DummyChatClient("reviewer"),
        name="Reviewer",
        description="Final reviewer",
        base_instructions="Review verifier output and finalize the answer.",
    )

    session = verifier.create_session(session_id="production-recipe")
    first_run = await verifier.run("draft a verifiable identity statement", session=session)
    second_run = await verifier.run("refine the statement with evidence", session=session)

    sign_payload_tool = integration.get_tool("agent_did_sign_payload")
    sign_http_tool = integration.get_tool("agent_did_sign_http_request")
    rotate_key_tool = integration.get_tool("agent_did_rotate_key")
    document_history_tool = integration.get_tool("agent_did_get_document_history")

    signature = await sign_payload_tool.func(payload="production-payload")
    signed_request = await sign_http_tool.func(method="POST", url="https://example.com/agent-did", body="{}")
    rotated = await rotate_key_tool.func()
    history = await document_history_tool.func()

    workflow = integration.build_workflow_chain(
        [
            integration.create_agent_executor(verifier, session=session, executor_id="verifier_executor"),
            integration.create_agent_executor(reviewer, executor_id="reviewer_executor"),
        ],
        name="production_identity_workflow",
        description="Production-style workflow recipe",
    )
    workflow_result = await workflow.run("produce a final verifiable identity report")

    print("first_run", first_run.value)
    print("second_run", second_run.value)
    print("signature_key", signature["key_id"])
    print("signed_request_headers", sorted(key for key in signed_request.keys() if "signature" in key.lower()))
    print("rotated_key", rotated["verificationMethodId"])
    print("document_history_entries", len(history))
    print("workflow_output", workflow_result.get_outputs()[0].value)
    print("events_emitted", len(events))
    print("spans_emitted", len(exporter.get_finished_spans()))


if __name__ == "__main__":
    asyncio.run(main())
