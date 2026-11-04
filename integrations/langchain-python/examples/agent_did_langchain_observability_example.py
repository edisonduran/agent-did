"""Observability example for Agent-DID LangChain Python tools."""

from __future__ import annotations

import asyncio
import json

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_langchain import create_agent_did_langchain_integration


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="observer_bot",
            description="Observability demo for Agent-DID tools",
            core_model="gpt-4.1-mini",
            system_prompt="Observe every tool call without leaking secrets.",
            capabilities=["audit:events", "verify:signature"],
        )
    )

    events: list[dict[str, object]] = []
    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "sign_http": True},
        observability_handler=lambda event: events.append(
            {
                "event_type": event.event_type,
                "level": event.level,
                "attributes": event.attributes,
            }
        ),
    )

    tools_by_name = {tool.name: tool for tool in integration.tools}
    await tools_by_name["agent_did_get_current_identity"].ainvoke({})
    await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": "demo:traceable-payload"})
    await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {
            "method": "POST",
            "url": "https://api.example.com/v1/tasks?debug=true",
            "body": '{"taskId":42,"secret":"hidden"}',
        }
    )

    print(json.dumps(events, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
