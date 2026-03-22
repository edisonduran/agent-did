from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_crewai import PACKAGE_STATUS, create_agent_did_crewai_integration


@pytest.mark.asyncio
async def test_factory_returns_expected_integration_object() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9191919191919191919191919191919191919191"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="CrewBot",
            core_model="gpt-4.1-mini",
            system_prompt="Crew integration test",
        )
    )

    integration = create_agent_did_crewai_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        additional_system_context="Use verifiable tools when they improve traceability.",
    )

    assert PACKAGE_STATUS == "functional"
    assert integration.get_current_identity()["did"] == runtime_identity.document.id
    assert integration.get_current_document().id == runtime_identity.document.id

    composed = integration.compose_system_prompt("Base role context")
    agent_kwargs = integration.create_agent_kwargs("CrewAI base prompt")
    task_kwargs = integration.create_task_kwargs(required_output_fields=["result"])
    crew_kwargs = integration.create_crew_kwargs()

    assert "Base role context" in composed
    assert "Use verifiable tools when they improve traceability." in composed
    assert agent_kwargs["tools"] == integration.tools
    assert "CrewAI base prompt" in agent_kwargs["backstory"]
    assert task_kwargs["tools"] == integration.tools
    assert task_kwargs["output_pydantic"].model_fields["did"].is_required()
    assert task_kwargs["output_pydantic"].model_fields["result"].is_required()
    assert "step_callback" in crew_kwargs
    assert "task_callback" in crew_kwargs


@pytest.mark.asyncio
async def test_tool_set_tracks_requested_exposure() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9292929292929292929292929292929292929292"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="CrewExposureBot",
            core_model="gpt-4.1-mini",
            system_prompt="Exposure test",
        )
    )

    integration = create_agent_did_crewai_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True, "document_history": True, "sign_payload": True, "rotate_keys": True},
    )
    tool_names = {tool.name for tool in integration.tools}

    assert "agent_did_get_current_identity" in tool_names
    assert "agent_did_resolve_did" in tool_names
    assert "agent_did_verify_signature" in tool_names
    assert "agent_did_sign_http_request" in tool_names
    assert "agent_did_get_document_history" in tool_names
    assert "agent_did_sign_payload" in tool_names
    assert "agent_did_rotate_key" in tool_names
