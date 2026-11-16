"""Wiring tests for the Agent-DID A2A integration assembly."""

from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_a2a import (
    PACKAGE_STATUS,
    A2AAgentCapabilities,
    A2ASkill,
    create_agent_did_a2a_integration,
    text_message,
)
from agent_did_a2a.config import AgentDidA2AConfig


@pytest.mark.asyncio
async def test_factory_returns_expected_integration_object() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
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
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
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
            A2ASkill(id="gen-text", name="Generate Text", description="Generate text from a prompt", tags=["text"]),
        ],
        capabilities=A2AAgentCapabilities(streaming=True, push_notifications=False),
    )

    extension = card.agent_did_extension()
    assert extension is not None and extension.params is not None
    assert extension.params["did"] == runtime_identity.document.id
    assert extension.params["keyIds"] == runtime_identity.document.assertion_method
    assert card.supported_interfaces[0].url == "https://agents.example.com/cardbot"
    assert card.name == "CardBot"
    assert len(card.skills) == 1
    assert card.skills[0].id == "gen-text"
    assert card.capabilities.streaming is True


@pytest.mark.asyncio
async def test_agent_card_json_serialization() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
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

    card_json = integration.agent_card_json(
        agent_url="https://agents.example.com/jsonbot",
        skills=[A2ASkill(id="json", name="JSON", description="Answers in JSON", tags=["json"])],
    )

    assert isinstance(card_json, dict)
    assert card_json["name"] == "JsonBot"
    assert card_json["capabilities"]["extensions"][0]["params"]["did"] == runtime_identity.document.id
    assert card_json["supportedInterfaces"][0]["protocolVersion"] == "1.0"
    assert "did" not in card_json and "authentication" not in card_json


@pytest.mark.asyncio
async def test_a2a_context_block_contains_identity() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
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


async def _runtime() -> tuple[AgentIdentity, object]:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(name="GateBot", core_model="gpt-4.1-mini", system_prompt="Gate test")
    )
    return identity, runtime_identity


@pytest.mark.asyncio
async def test_disabled_operations_raise() -> None:
    identity, runtime_identity = await _runtime()
    integration = create_agent_did_a2a_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,  # type: ignore[arg-type]
        expose={"sign_requests": False, "verify_requests": False, "enrich_agent_card": False},
    )

    with pytest.raises(PermissionError, match="sign_requests"):
        await integration.send_message(
            target_url="https://remote-agent.example.com/a2a", request_id=1, message=text_message("hi")
        )
    with pytest.raises(PermissionError, match="verify_requests"):
        await integration.verify_request(method="POST", url="https://me.example.com/a2a", headers={})
    with pytest.raises(PermissionError, match="enrich_agent_card"):
        integration.build_agent_card(agent_url="https://me.example.com", skills=[])


@pytest.mark.asyncio
async def test_private_targets_are_refused_unless_allowed() -> None:
    identity, runtime_identity = await _runtime()
    default = create_agent_did_a2a_integration(
        agent_identity=identity, runtime_identity=runtime_identity  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="Blocked request to private/reserved address"):
        await default.send_message(target_url="http://127.0.0.1:8080/a2a", request_id=1, message=text_message("hi"))

    allowed = create_agent_did_a2a_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,  # type: ignore[arg-type]
        config=AgentDidA2AConfig(allow_private_network_targets=True),
    )
    signed = await allowed.send_message(
        target_url="http://127.0.0.1:8080/a2a", request_id=1, message=text_message("hi")
    )
    assert "Signature" in signed.headers


@pytest.mark.asyncio
async def test_exposure_config_applies_defaults() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
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
        expose={"enrich_agent_card": False},
    )

    assert integration.config.expose.sign_requests is True
    assert integration.config.expose.verify_requests is True
    assert integration.config.expose.enrich_agent_card is False
