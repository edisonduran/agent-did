"""create_agent multi-tool example for Agent-DID LangChain Python."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner
from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage

from agent_did_langchain import create_agent_did_langchain_integration


class ToolReadyFakeMessagesListChatModel(FakeMessagesListChatModel):
    """Fake chat model that satisfies create_agent tool binding for local demos."""

    def bind_tools(self, tools: list[Any], **kwargs: Any) -> ToolReadyFakeMessagesListChatModel:
        return self


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="multitool_demo_bot",
            description="create_agent local demo with multiple Agent-DID tools",
            core_model="gpt-4.1-mini",
            system_prompt="Use identity tools before making trust claims.",
            capabilities=["identity:inspect", "signature:verify", "http:sign"],
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "sign_http": True, "document_history": True},
        additional_system_context=(
            "Before making any trust statement, inspect the current DID identity "
            "and only sign explicit outbound requests."
        ),
    )

    fake_model = ToolReadyFakeMessagesListChatModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "agent_did_get_current_identity",
                        "args": {},
                        "id": "call_identity",
                        "type": "tool_call",
                    },
                    {
                        "name": "agent_did_sign_http_request",
                        "args": {
                            "method": "POST",
                            "url": "https://api.example.com/tasks",
                            "body": '{"taskId":7}',
                        },
                        "id": "call_http",
                        "type": "tool_call",
                    },
                ],
            ),
            AIMessage(
                content=(
                    "Revise la identidad actual del agente y prepare headers de firma HTTP "
                    "para un POST a la API de tareas."
                )
            ),
        ]
    )

    agent = create_agent(
        model=fake_model,
        tools=integration.tools,
        system_prompt=integration.compose_system_prompt(
            "Inspecciona la identidad Agent-DID y usa herramientas antes de responder."
        ),
    )

    result = await agent.ainvoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Primero verifica tu identidad actual y luego prepara una firma HTTP para "
                        "POST https://api.example.com/tasks "
                        "con body {\"taskId\":7}."
                    ),
                }
            ]
        }
    )

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
