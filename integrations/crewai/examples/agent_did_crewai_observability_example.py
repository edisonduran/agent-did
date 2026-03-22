from __future__ import annotations

import asyncio
import logging
from pprint import pprint

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_crewai import create_agent_did_crewai_integration
from agent_did_crewai.observability import compose_event_handlers, create_json_logger_event_handler


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9797979797979797979797979797979797979797"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="crewai_observable_bot",
            description="CrewAI observability demo for Agent-DID tools",
            core_model="gpt-4.1-mini",
            system_prompt="Emit sanitized observability events for every relevant operation.",
            capabilities=["audit:trace", "sign:http"],
        )
    )

    local_events = []
    logger = logging.getLogger("agent_did_crewai.example")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.addHandler(logging.StreamHandler())

    integration = create_agent_did_crewai_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True, "sign_payload": True},
        observability_handler=compose_event_handlers(
            local_events.append,
            create_json_logger_event_handler(logger, extra_fields={"example": "observability"}),
        ),
    )
    tools_by_name = {tool.name: tool for tool in integration.tools}

    integration.get_current_identity()
    await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": "approve:ticket:123"})
    await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {"method": "POST", "url": "https://api.example.com/tasks?debug=true", "body": '{"task":7}'}
    )
    step_callback = integration.create_crew_kwargs()["step_callback"]
    step_callback({"payload": "secret", "result": "ok"})

    pprint(
        {
            "captured_event_types": [event.event_type for event in local_events],
            "last_event": local_events[-1].attributes if local_events else None,
        }
    )


if __name__ == "__main__":
    asyncio.run(main())
