from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_langchain import PACKAGE_STATUS, create_agent_did_langchain_integration


@pytest.mark.asyncio
async def test_factory_returns_expected_integration_object() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="IntegrationBot",
            core_model="gpt-4.1-mini",
            system_prompt="Integration test",
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        additional_system_context="Never impersonate another DID.",
    )

    assert PACKAGE_STATUS == "mvp"
    assert integration.get_current_identity()["did"] == runtime_identity.document.id
    assert integration.get_current_document().id == runtime_identity.document.id

    composed = integration.compose_system_prompt("Base system prompt")
    composed_without_base = integration.compose_system_prompt()

    assert "Base system prompt" in composed
    assert "Never impersonate another DID." in composed
    assert composed_without_base.startswith("Agent-DID identity context:")


@pytest.mark.asyncio
async def test_tool_set_tracks_requested_exposure() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="ExposureBot",
            core_model="gpt-4.1-mini",
            system_prompt="Exposure test",
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={
            "resolve_did": True,
            "verify_signatures": True,
            "sign_http": True,
            "document_history": True,
            "sign_payload": True,
            "rotate_keys": True,
        },
    )
    tool_names = {tool.name for tool in integration.tools}

    assert "agent_did_get_current_identity" in tool_names
    assert "agent_did_resolve_did" in tool_names
    assert "agent_did_verify_signature" in tool_names
    assert "agent_did_sign_http_request" in tool_names
    assert "agent_did_get_document_history" in tool_names
    assert "agent_did_sign_payload" in tool_names
    assert "agent_did_rotate_key" in tool_names
