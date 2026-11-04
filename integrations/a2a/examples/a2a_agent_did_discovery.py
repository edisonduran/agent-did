"""Example: A2A Agent Discovery with DID-enriched AgentCard.

This example shows how an agent publishes a DID-enriched AgentCard
and how a client agent would discover and verify its identity.

Usage:
    python -m examples.a2a_agent_did_discovery
"""

from __future__ import annotations

import asyncio
import json

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_a2a import A2ASkill, create_agent_did_a2a_integration


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

    # Build the A2A AgentCard (would be served at /.well-known/agent.json)
    card_json = integration.agent_card_json(
        agent_url="https://research-agent.example.com",
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
        capabilities={"streaming": True, "pushNotifications": False},
        verification_endpoint="https://research-agent.example.com/.well-known/did.json",
    )

    print("=== A2A AgentCard (DID-enriched) ===")
    print(json.dumps(card_json, indent=2))
    print()

    # --- Client agent: discovers and verifies ---
    print("=== Discovery verification ===")
    print(f"Agent DID: {card_json['did']}")
    print(f"Controller: {card_json['controller']}")
    print(f"Auth schemes: {card_json['authentication']['schemes']}")
    print(f"Skills: {[s['name'] for s in card_json['skills']]}")
    print(f"Verification endpoint: {card_json.get('verification_endpoint', 'none')}")
    print()

    # Show the A2A context that can be injected into LLM prompts
    print("=== A2A Identity Context (for system prompts) ===")
    print(integration.get_a2a_context())


if __name__ == "__main__":
    asyncio.run(main())
