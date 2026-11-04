"""Production-oriented opt-in example for Agent-DID LangChain Python."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, LocalKeySigner
from langchain.agents import create_agent

from agent_did_langchain import create_agent_did_langchain_integration
from agent_did_langchain.observability import (
    compose_event_handlers,
    create_json_logger_event_handler,
    create_langsmith_event_handler,
    create_langsmith_run_tree,
)


def _require_env(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _should_enable_langsmith() -> bool:
    return os.environ.get("LANGSMITH_TRACING") == "1"


async def main() -> None:
    if os.environ.get("RUN_LANGCHAIN_PRODUCTION_EXAMPLE") != "1":
        print("Set RUN_LANGCHAIN_PRODUCTION_EXAMPLE=1 to run this example against a real model.")
        return

    model = _require_env("LANGCHAIN_MODEL") or "openai:gpt-4.1-mini"

    if model.startswith("openai:") and _require_env("OPENAI_API_KEY") is None:
        print("OPENAI_API_KEY is required when LANGCHAIN_MODEL uses the openai: provider.")
        sys.exit(1)

    logger = logging.getLogger("agent_did_langchain.production")
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())

    local_events: list[dict[str, Any]] = []
    handlers = [
        lambda event: local_events.append(
            {
                "event_type": event.event_type,
                "level": event.level,
                "attributes": event.attributes,
            }
        ),
        create_json_logger_event_handler(
            logger,
            extra_fields={"service": "agent-did-demo", "environment": "local-prod-sim"},
        ),
    ]

    if _should_enable_langsmith():
        root_run = create_langsmith_run_tree(
            name="agent_did_production_recipe",
            project_name="agent-did-langchain",
            inputs={"scenario": "production-recipe"},
            tags=["agent-did", "production-example"],
        )
        handlers.append(create_langsmith_event_handler(root_run))

    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], network="polygon"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="production_recipe_bot",
            description="Production-oriented Agent-DID LangChain example",
            core_model="gpt-4.1-mini",
            system_prompt="Actua como un agente verificable, preciso y conservador con operaciones sensibles.",
            capabilities=["identity:inspect", "http:sign", "audit:events"],
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True},
        additional_system_context=(
            "Only sign explicit outbound HTTP requests for trusted destinations and explain why the action is needed."
        ),
        observability_handler=compose_event_handlers(*handlers),
    )

    agent = create_agent(
        model=model,
        tools=integration.tools,
        system_prompt=integration.compose_system_prompt(
            "Antes de reclamar identidad o preparar una firma HTTP, inspecciona la identidad Agent-DID activa."
        ),
    )

    result = await agent.ainvoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Primero indica tu DID actual. Luego explica cuando procede firmar una peticion HTTP y "
                        "prepara los headers para un POST a https://api.example.com/tasks con body {\"taskId\": 42}."
                    ),
                }
            ]
        }
    )

    print("Agent result:")
    print(json.dumps(result, indent=2, default=str))
    print("\nCaptured local events:")
    print(json.dumps(local_events, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
