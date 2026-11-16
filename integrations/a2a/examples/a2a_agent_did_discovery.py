"""Example: A2A 1.0 Agent Discovery with a signed Agent Card carrying the Agent-DID extension.

This example shows how an agent publishes a signed A2A 1.0 Agent Card
and how a client agent checks it against the agent's DID document.

Usage:
    python -m examples.a2a_agent_did_discovery
"""

from __future__ import annotations

import asyncio
import json

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_a2a import A2AAgentCapabilities, A2ASkill, create_agent_did_a2a_integration


async def main() -> None:
    # --- Server agent: creates identity and publishes AgentCard ---
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime = await identity.create(
        CreateAgentParams(
            name="ResearchAssistant",
            core_model="gpt-4.1",
            system_prompt="You are a research assistant that helps with literature review.",
            capabilities=["text-generation", "summarization", "citation-lookup"],
        )
    )

    integration = create_agent_did_a2a_integration(
        agent_identity=identity,
        runtime_identity=runtime,
    )

    # Build and sign the A2A 1.0 Agent Card (served at /.well-known/agent-card.json)
    card_json = await integration.signed_agent_card_json(
        agent_url="https://research-agent.example.com/a2a",
        skills=[
            A2ASkill(
                id="literature-review",
                name="Literature Review",
                description="Search and summarize academic papers on a given topic.",
                input_modes=["text/plain"],
                output_modes=["text/plain", "application/json"],
                tags=["research", "academic"],
            ),
            A2ASkill(
                id="citation-check",
                name="Citation Verification",
                description="Verify the accuracy of citations in a document.",
                input_modes=["text/plain"],
                output_modes=["application/json"],
                tags=["verification", "academic"],
            ),
        ],
        capabilities=A2AAgentCapabilities(streaming=True, push_notifications=False),
    )

    print("=== A2A 1.0 Agent Card (signed, Agent-DID extension) ===")
    print(json.dumps(card_json, indent=2))
    print()

    # --- Client agent: discovers and verifies ---
    print("=== Discovery verification ===")
    extension = card_json["capabilities"]["extensions"][-1]
    print(f"Agent DID: {extension['params']['did']}")
    print(f"Published keys: {extension['params']['keyIds']}")
    print(f"Skills: {[s['name'] for s in card_json['skills']]}")
    result = await identity.client.verify_agent_card(card_json)
    print(f"Card signature verified against the DID document: {result.ok}")
    print()

    # Show the A2A context that can be injected into LLM prompts
    print("=== A2A Identity Context (for system prompts) ===")
    print(integration.get_a2a_context())


if __name__ == "__main__":
    asyncio.run(main())
