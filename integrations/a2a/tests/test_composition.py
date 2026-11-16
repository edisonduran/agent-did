"""Signed Agent Cards and requests checked against them (composition contract), end to end through the integration."""

from __future__ import annotations

from typing import Any

import pytest
from agent_did_sdk import (
    AGENT_DID_A2A_EXTENSION_URI,
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryAgentRegistry,
    LocalKeySigner,
    parse_signed_agent_card,
)

from agent_did_a2a import A2ASkill, create_agent_did_a2a_integration, text_message
from agent_did_a2a.integration import AgentDidA2AIntegration

AGENT_URL = "https://agents.example.com/cardbot"
TARGET = "https://remote-agent.example.com/a2a"
SKILLS = [A2ASkill(id="cards", name="Cards", description="Answers questions about cards", tags=["cards"])]


async def _integration() -> tuple[AgentIdentity, AgentDidA2AIntegration]:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(name="CardBot", core_model="gpt-4.1-mini", system_prompt="composition test")
    )
    return identity, create_agent_did_a2a_integration(agent_identity=identity, runtime_identity=runtime_identity)


async def _signed_task(integration: AgentDidA2AIntegration) -> dict[str, Any]:
    signed = await integration.send_message(target_url=TARGET, request_id=1, message=text_message("hi"))
    return {"method": signed.method, "url": signed.url, "headers": signed.headers, "body": signed.body}


@pytest.mark.asyncio
async def test_signed_card_publishes_the_did_and_the_signing_key() -> None:
    _, integration = await _integration()
    card = await integration.signed_agent_card_json(agent_url=AGENT_URL, skills=SKILLS)
    did = integration.runtime_identity.document.id
    parsed = parse_signed_agent_card(card)
    assert parsed is not None and parsed.did == did
    extension = next(e for e in card["capabilities"]["extensions"] if e["uri"] == AGENT_DID_A2A_EXTENSION_URI)
    assert extension["params"]["did"] == did
    assert parsed.published_key_ids == tuple(extension["params"]["keyIds"])
    assert (await integration.agent_identity.client.verify_agent_card(card)).ok


@pytest.mark.asyncio
async def test_a_request_verifies_against_the_senders_card() -> None:
    _, integration = await _integration()
    card = await integration.signed_agent_card_json(agent_url=AGENT_URL, skills=SKILLS)
    result = await integration.verify_request_against_card(**await _signed_task(integration), agent_card=card)
    assert result.ok and result.did == integration.runtime_identity.document.id


@pytest.mark.asyncio
async def test_a_changed_card_is_tampered_and_a_retired_key_is_rotation_window_closed() -> None:
    identity, integration = await _integration()
    card = await integration.signed_agent_card_json(agent_url=AGENT_URL, skills=SKILLS)
    tampered = await integration.verify_request_against_card(
        **await _signed_task(integration), agent_card={**card, "name": "Impostor"}
    )
    assert (tampered.ok, tampered.stage, tampered.reason) == (False, "agent_card", "tampered")

    did = integration.runtime_identity.document.id
    old_key = integration.runtime_identity.document.assertion_method[0]  # type: ignore[index]
    request = await _signed_task(integration)
    await identity.client.add_verification_method(did, relationships=["authentication", "assertionMethod"])
    await identity.client.retire_verification_method(did, old_key)
    retired = await integration.verify_request_against_card(**request, agent_card=card)
    assert (retired.ok, retired.reason) == (False, "rotation_window_closed")


@pytest.mark.asyncio
async def test_verify_request_against_card_respects_the_expose_flag() -> None:
    identity, integration = await _integration()
    gated = create_agent_did_a2a_integration(
        agent_identity=identity, runtime_identity=integration.runtime_identity, expose={"verify_requests": False}
    )
    with pytest.raises(PermissionError):
        await gated.verify_request_against_card(method="POST", url=TARGET, headers={}, agent_card={})
