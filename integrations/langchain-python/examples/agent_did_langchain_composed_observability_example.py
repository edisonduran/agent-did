"""Composed observability example for Agent-DID LangChain Python."""

from __future__ import annotations

import asyncio
import io
import json
import logging

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_langchain import create_agent_did_langchain_integration
from agent_did_langchain.observability import (
    AgentDidObservabilityEvent,
    compose_event_handlers,
    create_json_logger_event_handler,
    create_langsmith_event_handler,
    create_langsmith_run_tree,
)


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    event_buffer: list[dict[str, object]] = []
    log_stream = io.StringIO()
    logger = logging.getLogger("agent_did_langchain.composed")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(logging.StreamHandler(log_stream))

    root_run = create_langsmith_run_tree(
        name="agent_did_composed_observability_demo",
        inputs={"scenario": "composed-observability"},
        tags=["example", "composed"],
    )

    def capture_event(event: AgentDidObservabilityEvent) -> None:
        event_buffer.append(
            {
                "event_type": event.event_type,
                "level": event.level,
                "attributes": event.attributes,
            }
        )

    composed_handler = compose_event_handlers(
        capture_event,
        create_json_logger_event_handler(
            logger,
            include_timestamp=False,
            extra_fields={"sink": "json-logger", "service": "example"},
        ),
        create_langsmith_event_handler(
            root_run,
            include_timestamp=False,
            extra_fields={"sink": "langsmith", "service": "example"},
            tags=["fanout"],
        ),
    )

    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="composed_observer_bot",
            description="Composed observability demo for Agent-DID tools",
            core_model="gpt-4.1-mini",
            system_prompt="Fan out observability to local memory, JSON logs and LangSmith.",
            capabilities=["audit:events", "http:sign"],
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "sign_http": True},
        observability_handler=composed_handler,
    )

    tools_by_name = {tool.name: tool for tool in integration.tools}
    await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": "compose-demo-payload"})
    await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {
            "method": "POST",
            "url": "https://api.example.com/compose?debug=true",
            "body": '{"secret":"hidden"}',
        }
    )

    root_run.end(outputs={"child_run_count": len(root_run.child_runs)})

    print(
        json.dumps(
            {
                "captured_events": event_buffer,
                "json_logs": [line for line in log_stream.getvalue().splitlines() if line.strip()],
                "langsmith_child_run_count": len(root_run.child_runs),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
