"""Example: Mutual DID-based authentication between two A2A agents.

This example demonstrates:
  1. Two agents create their own DID identities
  2. Each publishes a DID-enriched AgentCard
  3. Agent A sends a signed tasks/send request to Agent B
  4. Agent B verifies the incoming request's HTTP Signature

Usage:
    python -m examples.a2a_mutual_auth_demo
"""

from __future__ import annotations

import asyncio
import json

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_a2a import A2ASkill, create_agent_did_a2a_integration


async def main() -> None:
    # Shared registry for both agents (in production, each agent has its own)
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    # --- Agent A: the requesting agent ---
    identity_a = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_a = await identity_a.create(
        CreateAgentParams(
            name="OrchestratorAgent",
            core_model="gpt-4.1",
            system_prompt="You orchestrate multi-agent workflows.",
            capabilities=["task-delegation", "workflow-management"],
        )
    )
    integration_a = create_agent_did_a2a_integration(
        agent_identity=identity_a,
        runtime_identity=runtime_a,
    )

    # --- Agent B: the service agent ---
    identity_b = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_b = await identity_b.create(
        CreateAgentParams(
            name="DataAnalystAgent",
            core_model="gpt-4.1-mini",
            system_prompt="You analyze datasets and produce insights.",
            capabilities=["data-analysis", "visualization"],
        )
    )
    integration_b = create_agent_did_a2a_integration(
        agent_identity=identity_b,
        runtime_identity=runtime_b,
    )

    # --- Step 1: Both agents publish AgentCards ---
    card_a = integration_a.agent_card_json(agent_url="https://orchestrator.example.com")
    card_b = integration_b.agent_card_json(
        agent_url="https://data-analyst.example.com",
        skills=[
            A2ASkill(
                id="analyze-csv",
                name="Analyze CSV",
                description="Analyze a CSV dataset and produce summary statistics.",
            ),
        ],
    )

    print("=== Agent A (Orchestrator) AgentCard ===")
    print(json.dumps(card_a, indent=2))
    print()
    print("=== Agent B (Data Analyst) AgentCard ===")
    print(json.dumps(card_b, indent=2))
    print()

    # --- Step 2: Agent A sends a signed task to Agent B ---
    print("=== Agent A sends signed tasks/send to Agent B ===")
    signed_request = await integration_a.send_task(
        target_url="https://data-analyst.example.com/a2a",
        request_id=1,
        task_id="task-mutual-001",
        message={
            "role": "user",
            "parts": [{"type": "text", "text": "Analyze Q4 revenue data and produce a summary."}],
        },
    )

    print(f"Signed request URL: {signed_request.url}")
    print(f"Signed request method: {signed_request.method}")
    print(f"Signed headers: {list(signed_request.headers.keys())}")
    print(f"Body preview: {signed_request.body[:120]}...")
    print()

    # --- Step 3: Agent B verifies the incoming request ---
    print("=== Agent B verifies incoming request ===")
    is_valid = await integration_b.verify_request(
        method=signed_request.method,
        url=signed_request.url,
        headers=signed_request.headers,
        body=signed_request.body,
    )
    print(f"Signature valid: {is_valid}")
    print()

    # --- Summary ---
    print("=== Mutual Authentication Summary ===")
    print(f"Agent A DID: {card_a['did']}")
    print(f"Agent B DID: {card_b['did']}")
    print("Request signed by Agent A: ✓")
    print(f"Signature verified by Agent B: {'✓' if is_valid else '✗'}")


if __name__ == "__main__":
    asyncio.run(main())
