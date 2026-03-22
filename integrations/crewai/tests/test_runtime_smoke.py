from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_crewai import create_agent_did_crewai_integration


@pytest.mark.asyncio
async def test_real_crewai_runtime_accepts_agent_did_bundle() -> None:
    crewai_module = pytest.importorskip("crewai")
    crewai_agent_cls = getattr(crewai_module, "Agent")
    crewai_task_cls = getattr(crewai_module, "Task")
    crewai_crew_cls = getattr(crewai_module, "Crew")

    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9898989898989898989898989898989898989898"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="CrewRuntimeBot",
            description="Real CrewAI runtime smoke test",
            core_model="gpt-4.1-mini",
            system_prompt="Validate wiring against a real CrewAI install without executing an LLM run.",
            capabilities=["audit:trace"],
        )
    )

    integration = create_agent_did_crewai_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True, "sign_payload": True},
    )

    agent = crewai_agent_cls(
        role="Verifier",
        goal="Return verifiable output",
        **integration.create_agent_kwargs("CrewAI runtime smoke prompt"),
    )
    task = crewai_task_cls(
        description="Return a JSON object with did and result.",
        expected_output="A dictionary with did and result.",
        agent=agent,
        **integration.create_task_kwargs(required_output_fields=["result"]),
    )
    crew = crewai_crew_cls(
        agents=[agent],
        tasks=[task],
        **integration.create_crew_kwargs(),
    )

    assert type(agent).__name__ == "Agent"
    assert type(task).__name__ == "Task"
    assert type(crew).__name__ == "Crew"
    assert any(tool.name == "agent_did_get_current_identity" for tool in agent.tools)
    assert task.callback is not None
    assert task.guardrail is not None
    assert crew.step_callback is not None
    assert crew.task_callback is not None
