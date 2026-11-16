"""Tests for A2A 1.0 Agent Card generation with the Agent-DID extension."""

from __future__ import annotations

import pytest
from agent_did_sdk import (
    AGENT_DID_A2A_EXTENSION_URI,
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    CreateAgentResult,
    InMemoryAgentRegistry,
    LocalKeySigner,
)
from pydantic import ValidationError

from agent_did_a2a.agent_card import (
    AGENT_CARD_WELL_KNOWN_PATH,
    A2AAgentCapabilities,
    A2AAgentExtension,
    A2ASkill,
    agent_card_to_json,
    build_agent_card,
)
from agent_did_a2a.config import AgentDidA2AConfig, AgentDidA2AOAuthClientCredentials
from agent_did_a2a.snapshot import build_agent_did_identity_snapshot

SKILL = A2ASkill(id="s1", name="Skill One", description="Does something", tags=["demo"])


async def _create(name: str) -> CreateAgentResult:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    return await identity.create(CreateAgentParams(name=name, core_model="gpt-4.1-mini", system_prompt="test"))


@pytest.mark.asyncio
async def test_agent_card_has_the_a2a_1_0_shape() -> None:
    result = await _create("CardAgent")
    card = build_agent_card(
        identity_snapshot=build_agent_did_identity_snapshot(result),
        agent_url="https://example.com/a2a",
        skills=[SKILL],
        key_ids=[result.document.assertion_method[0]] if result.document.assertion_method else None,
    )
    card_json = agent_card_to_json(card)

    assert card_json["name"] == "CardAgent"
    assert card_json["description"] == "CardAgent"  # no description: the name stands in (A2A requires one)
    assert card_json["supportedInterfaces"] == [
        {"url": "https://example.com/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
    ]
    assert card_json["defaultInputModes"] == ["text/plain"]
    assert card_json["defaultOutputModes"] == ["text/plain"]
    assert card_json["skills"] == [{"id": "s1", "name": "Skill One", "description": "Does something", "tags": ["demo"]}]
    assert "securitySchemes" not in card_json
    assert not {"did", "controller", "url", "authentication"} & set(card_json)
    [extension] = card_json["capabilities"]["extensions"]
    assert extension["uri"] == AGENT_DID_A2A_EXTENSION_URI
    assert extension["required"] is False
    assert extension["params"]["did"] == result.document.id
    assert extension["params"]["keyIds"] == result.document.assertion_method
    assert AGENT_CARD_WELL_KNOWN_PATH == "/.well-known/agent-card.json"
    assert AgentDidA2AConfig().agent_card_url == AGENT_CARD_WELL_KNOWN_PATH


@pytest.mark.asyncio
async def test_require_signed_requests_marks_the_extension_required() -> None:
    result = await _create("StrictAgent")
    card = build_agent_card(
        identity_snapshot=build_agent_did_identity_snapshot(result),
        agent_url="https://example.com/a2a",
        skills=[SKILL],
        config=AgentDidA2AConfig(require_signed_requests=True),
    )
    extension = card.agent_did_extension()
    assert extension is not None and extension.required is True


@pytest.mark.asyncio
async def test_oauth_client_credentials_and_additional_schemes() -> None:
    result = await _create("OAuthAgent")
    config = AgentDidA2AConfig(
        oauth_client_credentials=AgentDidA2AOAuthClientCredentials(
            token_url="https://as.example.com/token", scopes={"a2a": "Call the agent"}
        ),
        additional_security_schemes={"mtls": {"mtlsSecurityScheme": {}}},
    )
    card_json = agent_card_to_json(
        build_agent_card(
            identity_snapshot=build_agent_did_identity_snapshot(result),
            agent_url="https://example.com/a2a",
            skills=[SKILL],
            config=config,
        )
    )

    assert card_json["securitySchemes"]["mtls"] == {"mtlsSecurityScheme": {}}
    flows = card_json["securitySchemes"]["agentDidClientCredentials"]["oauth2SecurityScheme"]["flows"]
    assert flows == {
        "clientCredentials": {"tokenUrl": "https://as.example.com/token", "scopes": {"a2a": "Call the agent"}}
    }
    assert card_json["securityRequirements"] == [{"schemes": {"agentDidClientCredentials": {"list": ["a2a"]}}}]

    with pytest.raises(ValidationError):
        AgentDidA2AOAuthClientCredentials(token_url="https://as.example.com/token", scopes={})


@pytest.mark.asyncio
async def test_caller_extensions_are_kept_and_an_agent_did_one_is_replaced() -> None:
    result = await _create("ExtAgent")
    capabilities = A2AAgentCapabilities(
        streaming=True,
        extensions=[
            A2AAgentExtension(uri="https://example.com/ext/v1"),
            A2AAgentExtension(uri=AGENT_DID_A2A_EXTENSION_URI, params={"did": "did:webvh:Qm:other.example"}),
        ],
    )
    card = build_agent_card(
        identity_snapshot=build_agent_did_identity_snapshot(result),
        agent_url="https://example.com/a2a",
        skills=[SKILL],
        capabilities=capabilities,
    )
    uris = [extension.uri for extension in card.capabilities.extensions]
    assert uris == ["https://example.com/ext/v1", AGENT_DID_A2A_EXTENSION_URI]
    extension = card.agent_did_extension()
    assert extension is not None and extension.params == {"did": result.document.id}
    assert capabilities.extensions[1].params == {"did": "did:webvh:Qm:other.example"}  # the input is not changed
    assert agent_card_to_json(card)["capabilities"]["streaming"] is True


def test_a2a_1_0_required_members_are_enforced() -> None:
    with pytest.raises(ValidationError):
        A2ASkill(id="s", name="S", description="d", tags=[])
    with pytest.raises(ValidationError):
        A2ASkill(id="s", name="S", description="", tags=["t"])
    with pytest.raises(ValidationError):
        A2ASkill(id="s", name="S", description="d", tags=["t"], unknown="x")  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_a_card_needs_a_skill() -> None:
    result = await _create("NoSkills")
    with pytest.raises(ValidationError):
        build_agent_card(
            identity_snapshot=build_agent_did_identity_snapshot(result), agent_url="https://example.com/a2a", skills=[]
        )
