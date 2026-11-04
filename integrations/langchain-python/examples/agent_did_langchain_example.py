"""Minimal Agent-DID + LangChain Python assembly example."""

from __future__ import annotations

import asyncio
import json
import os

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, LocalKeySigner
from langchain.agents import create_agent

from agent_did_langchain import create_agent_did_langchain_integration


async def main() -> None:
    model = os.environ.get("LANGCHAIN_MODEL", "openai:gpt-4.1-mini")
    run_model_example = os.environ.get("RUN_LANGCHAIN_MODEL_EXAMPLE") == "1"
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], network="polygon"))
    emitted_events: list[tuple[str, dict[str, object]]] = []

    runtime_identity = await identity.create(
        CreateAgentParams(
            name="research_assistant",
            description="Agente de investigacion con identidad verificable",
            core_model="gpt-4.1-mini",
            system_prompt="Eres un agente de investigacion preciso y trazable.",
            capabilities=["research:web", "report:write"],
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True, "sign_payload": True},
        additional_system_context="Never sign arbitrary payloads.",
        observability_handler=lambda event: emitted_events.append((event.event_type, event.attributes)),
    )

    tools_by_name = {tool.name: tool for tool in integration.tools}
    current_identity = await tools_by_name["agent_did_get_current_identity"].ainvoke({})
    signed_payload = await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": "proof-of-origin:demo"})

    print("Current identity snapshot:")
    print(json.dumps(current_identity, indent=2))
    print("\nSigned payload summary:")
    print(json.dumps({"did": signed_payload["did"], "key_id": signed_payload["key_id"]}, indent=2))
    print("\nObserved events:")
    print(json.dumps(emitted_events, indent=2))

    if not run_model_example:
        print("\nSet RUN_LANGCHAIN_MODEL_EXAMPLE=1 to execute the full model-backed LangChain agent demo.")
        return

    agent = create_agent(
        model=model,
        tools=integration.tools,
        system_prompt=integration.compose_system_prompt(
            "Responde con precision y usa herramientas solo cuando aporten evidencia verificable."
        ),
    )

    result = await agent.ainvoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": "Muestrame tu DID actual y explica cuando deberias usar la firma HTTP.",
                }
            ]
        }
    )
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
