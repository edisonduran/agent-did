from __future__ import annotations

import asyncio
import inspect

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry
from agent_framework import BaseChatClient, ChatResponse, Message

from agent_did_microsoft_agent_framework import create_agent_did_microsoft_agent_framework_integration


class DummyChatClient(BaseChatClient):
    async def _inner_get_response(self, *, messages, stream, options, **kwargs):  # type: ignore[override]
        return ChatResponse(
            messages=Message("assistant", ["local-stub-response"]),
            finish_reason="stop",
            value="local-stub-response",
        )


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x5656565656565656565656565656565656565656"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="MicrosoftAgentFrameworkExampleBot",
            description="MVP example for Agent-DID + Microsoft Agent Framework",
            core_model="gpt-4.1-mini",
            system_prompt="Use Agent-DID tools when identity evidence is required.",
            capabilities=["identity:resolve", "signature:verify"],
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "sign_http": True},
    )

    agent = integration.create_agent(
        DummyChatClient(),
        name="Verifier",
        description="Local stubbed Microsoft Agent Framework host",
        base_instructions="Use Agent-DID tools when verifiable identity evidence is required.",
    )
    current_identity_tool = next(tool for tool in integration.tools if tool.name == "agent_did_get_current_identity")

    print(type(agent).__name__)
    print(agent.name)
    current_identity = current_identity_tool.func()
    if inspect.isawaitable(current_identity):
        current_identity = await current_identity
    print(current_identity)


if __name__ == "__main__":
    asyncio.run(main())
