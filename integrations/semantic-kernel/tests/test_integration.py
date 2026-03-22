from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_semantic_kernel import (
    PACKAGE_STATUS,
    create_agent_did_semantic_kernel_integration,
    createAgentDidSemanticKernelIntegration,
)


@pytest.mark.asyncio
async def test_factory_returns_expected_integration_object() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x5656565656565656565656565656565656565656"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="SemanticKernelBot",
            core_model="gpt-4.1-mini",
            system_prompt="Integration test",
        )
    )

    integration = create_agent_did_semantic_kernel_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        additional_instructions="Prefer verifiable tools over unverifiable assertions.",
    )

    assert PACKAGE_STATUS == "functional"
    assert createAgentDidSemanticKernelIntegration is create_agent_did_semantic_kernel_integration
    assert integration.get_current_identity()["did"] == runtime_identity.document.id
    assert integration.get_current_document().id == runtime_identity.document.id

    composed = integration.compose_instructions("Base instructions")
    agent_kwargs = integration.create_agent_kwargs("Base instructions")

    assert "Base instructions" in composed
    assert "Prefer verifiable tools over unverifiable assertions." in composed
    assert composed.startswith("Base instructions")
    assert agent_kwargs["context"]["agent_did"]["did"] == runtime_identity.document.id
    assert {tool["name"] for tool in agent_kwargs["tools"]} == {tool.name for tool in integration.tools}


@pytest.mark.asyncio
async def test_tool_set_tracks_requested_exposure() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x5757575757575757575757575757575757575757"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="SemanticKernelExposureBot",
            core_model="gpt-4.1-mini",
            system_prompt="Exposure test",
        )
    )

    integration = create_agent_did_semantic_kernel_integration(
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
