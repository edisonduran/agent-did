from __future__ import annotations

import asyncio
import importlib
from pprint import pprint

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_crewai import create_agent_did_crewai_integration


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="crewai_demo_bot",
            description="CrewAI-style Agent-DID integration demo",
            core_model="gpt-4.1-mini",
            system_prompt="Use tools when they improve traceability.",
            capabilities=["research:web", "sign:http"],
        )
    )

    integration = create_agent_did_crewai_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True, "sign_payload": True},
        additional_system_context="Keep private material outside model-visible output.",
    )
    tools_by_name = {tool.name: tool for tool in integration.tools}

    current_identity = await tools_by_name["agent_did_get_current_identity"].ainvoke({})
    signed_payload = await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": "approve:ticket:123"})
    signed_http = await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {"method": "POST", "url": "https://api.example.com/tasks", "body": '{"task":7}'}
    )
    agent_kwargs = integration.create_agent_kwargs("CrewAI role context")
    task_kwargs = integration.create_task_kwargs(required_output_fields=["result"])
    crew_kwargs = integration.create_crew_kwargs()

    try:
        crewai_module = importlib.import_module("crewai")
        crewai_agent_cls = getattr(crewai_module, "Agent")
        crewai_crew_cls = getattr(crewai_module, "Crew")
        crewai_task_cls = getattr(crewai_module, "Task")
    except ImportError:
        crewai_agent_cls = crewai_crew_cls = crewai_task_cls = None

    result = {
        "did": current_identity["did"],
        "payload_key_id": signed_payload["key_id"],
        "http_headers": list(signed_http["headers"].keys()),
        "agent_kwargs": agent_kwargs,
        "task_kwargs_keys": sorted(task_kwargs.keys()),
        "crew_kwargs_keys": sorted(crew_kwargs.keys()),
        "crewai_runtime_available": crewai_agent_cls is not None,
    }

    if crewai_agent_cls is not None and crewai_crew_cls is not None and crewai_task_cls is not None:
        agent = crewai_agent_cls(role="Verifier", goal="Return verifiable output", **agent_kwargs)
        task = crewai_task_cls(
            description="Return a JSON object with fields did and result.",
            expected_output="A dictionary with did and result.",
            agent=agent,
            **task_kwargs,
        )
        crew = crewai_crew_cls(agents=[agent], tasks=[task], **crew_kwargs)
        result["crewai_objects"] = {
            "agent_type": type(agent).__name__,
            "task_type": type(task).__name__,
            "crew_type": type(crew).__name__,
        }

    pprint(result)


if __name__ == "__main__":
    asyncio.run(main())
