"""Wiring tests for the Agent-DID A2A integration assembly."""

from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_a2a import (
    PACKAGE_STATUS,
    A2ASkill,
    create_agent_did_a2a_integration,
)


@pytest.mark.asyncio
async def test_factory_returns_expected_integration_object() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xA2A0A2A0A2A0A2A0A2A0A2A0A2A0A2A0A2A0A2A0"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="A2ABot",
            core_model="gpt-4.1-mini",
            system_prompt="A2A integration test",
        )
    )

    integration = create_agent_did_a2a_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
    )

    assert PACKAGE_STATUS == "functional"
    assert integration.get_current_identity()["did"] == runtime_identity.document.id
    assert integration.runtime_identity == runtime_identity


@pytest.mark.asyncio
async def test_build_agent_card_contains_did_identity() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xA2A1A2A1A2A1A2A1A2A1A2A1A2A1A2A1A2A1A2A1"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="CardBot",
            core_model="gpt-4.1-mini",
            system_prompt="AgentCard test",
            capabilities=["text-generation", "code-review"],
        )
    )

    integration = create_agent_did_a2a_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
    )

    card = integration.build_agent_card(
        agent_url="https://agents.example.com/cardbot",
        skills=[
            A2ASkill(id="gen-text", name="Generate Text", description="Generate text from a prompt"),
        ],
        capabilities={"streaming": True, "pushNotifications": False},
    )

    assert card.did == runtime_identity.document.id
    assert card.controller == runtime_identity.document.controller
    assert card.url == "https://agents.example.com/cardbot"
    assert card.name == "CardBot"
    assert len(card.skills) == 1
    assert card.skills[0].id == "gen-text"
    assert "http-signature-did" in card.authentication.schemes
    assert card.capabilities["streaming"] is True


@pytest.mark.asyncio
async def test_agent_card_json_serialization() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xA2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="JsonBot",
            core_model="gpt-4.1-mini",
            system_prompt="JSON serialization test",
        )
    )

    integration = create_agent_did_a2a_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
    )

    card_json = integration.agent_card_json(agent_url="https://agents.example.com/jsonbot")

    assert isinstance(card_json, dict)
    assert card_json["did"] == runtime_identity.document.id
    assert card_json["name"] == "JsonBot"
    assert "authentication" in card_json
    assert "http-signature-did" in card_json["authentication"]["schemes"]


@pytest.mark.asyncio
async def test_a2a_context_block_contains_identity() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xA2A3A2A3A2A3A2A3A2A3A2A3A2A3A2A3A2A3A2A3"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="ContextBot",
            core_model="gpt-4.1-mini",
            system_prompt="Context test",
        )
    )

    integration = create_agent_did_a2a_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
    )

    context = integration.get_a2a_context()

    assert "DID:" in context
    assert "ContextBot" in context
    assert "HTTP Message Signatures" in context


@pytest.mark.asyncio
async def test_exposure_config_applies_defaults() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xA2A4A2A4A2A4A2A4A2A4A2A4A2A4A2A4A2A4A2A4"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="ConfigBot",
            core_model="gpt-4.1-mini",
            system_prompt="Config test",
        )
    )

    integration = create_agent_did_a2a_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"rotate_keys": True, "document_history": True},
    )

    assert integration.config.expose.sign_requests is True
    assert integration.config.expose.verify_requests is True
    assert integration.config.expose.rotate_keys is True
    assert integration.config.expose.document_history is True
