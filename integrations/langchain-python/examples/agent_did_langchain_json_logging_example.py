"""Structured JSON logging example for Agent-DID LangChain Python observability."""

from __future__ import annotations

import asyncio
import logging

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_langchain import create_agent_did_langchain_integration
from agent_did_langchain.observability import create_json_logger_event_handler


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    logger = logging.getLogger("agent_did_langchain.json")
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())

    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="json_log_bot",
            description="JSON logging demo for Agent-DID tools",
            core_model="gpt-4.1-mini",
            system_prompt="Emit sanitized JSON observability records.",
            capabilities=["audit:events", "http:sign"],
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True, "sign_payload": True},
        observability_handler=create_json_logger_event_handler(
            logger,
            extra_fields={"component": "example", "package": "agent-did-langchain"},
        ),
    )

    tools_by_name = {tool.name: tool for tool in integration.tools}
    await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": "json-logging-demo"})
    await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {
            "method": "POST",
            "url": "https://api.example.com/trace?debug=true",
            "body": '{"secret":"hidden"}',
        }
    )


if __name__ == "__main__":
    asyncio.run(main())
