"""Tests for A2A AgentCard generation with DID enrichment."""

from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_a2a.agent_card import A2ASkill, agent_card_to_json, build_agent_card
from agent_did_a2a.config import AgentDidA2AAuthScheme, AgentDidA2AConfig
from agent_did_a2a.snapshot import build_agent_did_identity_snapshot


@pytest.mark.asyncio
async def test_agent_card_has_required_a2a_fields() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xCA0DCA0DCA0DCA0DCA0DCA0DCA0DCA0DCA0DCA0D"))
    result = await identity.create(
        CreateAgentParams(name="CardAgent", core_model="gpt-4.1-mini", system_prompt="test")
    )
    snapshot = build_agent_did_identity_snapshot(result)

    card = build_agent_card(
        identity_snapshot=snapshot,
        agent_url="https://example.com/agent",
        skills=[A2ASkill(id="s1", name="Skill One", description="Does something")],
    )

    assert card.name == "CardAgent"
    assert card.url == "https://example.com/agent"
    assert card.did == result.document.id
    assert len(card.skills) == 1
    assert card.skills[0].id == "s1"
    assert "http-signature-did" in card.authentication.schemes


@pytest.mark.asyncio
async def test_agent_card_with_additional_auth_schemes() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xCA1DCA1DCA1DCA1DCA1DCA1DCA1DCA1DCA1DCA1D"))
    result = await identity.create(
        CreateAgentParams(name="MultiAuthAgent", core_model="gpt-4.1-mini", system_prompt="test")
    )
    snapshot = build_agent_did_identity_snapshot(result)

    config = AgentDidA2AConfig(
        additional_auth_schemes=[
            AgentDidA2AAuthScheme(scheme="oauth2"),
            AgentDidA2AAuthScheme(scheme="mtls"),
        ]
    )

    card = build_agent_card(identity_snapshot=snapshot, agent_url="https://example.com/agent", config=config)

    assert "http-signature-did" in card.authentication.schemes
    assert "oauth2" in card.authentication.schemes
    assert "mtls" in card.authentication.schemes


@pytest.mark.asyncio
async def test_agent_card_to_json_excludes_none() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xCA2DCA2DCA2DCA2DCA2DCA2DCA2DCA2DCA2DCA2D"))
    result = await identity.create(
        CreateAgentParams(name="JsonAgent", core_model="gpt-4.1-mini", system_prompt="test")
    )
    snapshot = build_agent_did_identity_snapshot(result)

    card = build_agent_card(identity_snapshot=snapshot, agent_url="https://example.com/agent")
    card_json = agent_card_to_json(card)

    assert isinstance(card_json, dict)
    assert "did" in card_json
    assert "name" in card_json
    # description is None by default in CreateAgentParams, so it should be excluded
    if card.description is None:
        assert "description" not in card_json


@pytest.mark.asyncio
async def test_agent_card_includes_verification_endpoint() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xCA3DCA3DCA3DCA3DCA3DCA3DCA3DCA3DCA3DCA3D"))
    result = await identity.create(
        CreateAgentParams(name="VerifyAgent", core_model="gpt-4.1-mini", system_prompt="test")
    )
    snapshot = build_agent_did_identity_snapshot(result)

    card = build_agent_card(
        identity_snapshot=snapshot,
        agent_url="https://example.com/agent",
        verification_endpoint="https://example.com/.well-known/did.json",
    )

    assert card.verification_endpoint == "https://example.com/.well-known/did.json"


@pytest.mark.asyncio
async def test_agent_card_skill_defaults() -> None:
    skill = A2ASkill(id="test-skill", name="Test", description="A test skill")

    assert skill.input_modes == ["text/plain"]
    assert skill.output_modes == ["text/plain"]
    assert skill.tags == []
