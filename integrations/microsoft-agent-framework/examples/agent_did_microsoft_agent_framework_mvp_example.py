from __future__ import annotations

import asyncio
import json

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_microsoft_agent_framework import create_agent_did_microsoft_agent_framework_integration


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x7373737373737373737373737373737373737373"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="maf_demo_bot",
            description="Microsoft Agent Framework integration example",
            core_model="gpt-4.1-mini",
            system_prompt="Use Agent-DID tools when identity evidence matters.",
            capabilities=["identity:resolve", "signature:verify"],
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        additional_instructions="Keep private key material outside model-visible context.",
        expose={"sign_http": True, "document_history": True},
    )

    agent_kwargs = integration.create_agent_kwargs("You are a traceable Microsoft Agent Framework agent.")
    context_middleware = integration.create_context_middleware()
    resolved_context = context_middleware({"session_id": "demo-session"})

    print("Instructions:\n")
    print(agent_kwargs["instructions"])
    print("\nTool names:")
    print([tool["name"] for tool in agent_kwargs["tools"]])
    print("\nSession context:")
    print(json.dumps(resolved_context, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
