from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_crewai import create_agent_did_crewai_integration


@pytest.mark.asyncio
async def test_tools_expose_identity_resolution_and_signature_verification() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9393939393939393939393939393939393939393"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="CrewToolBot",
            description="Testing CrewAI tools",
            core_model="gpt-4.1-mini",
            system_prompt="Tool test",
            capabilities=["verify:signature"],
        )
    )

    integration = create_agent_did_crewai_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "rotate_keys": True},
    )
    tools_by_name = {tool.name: tool for tool in integration.tools}

    identity_result = await tools_by_name["agent_did_get_current_identity"].ainvoke({})
    assert identity_result["did"] == runtime_identity.document.id

    resolved = await tools_by_name["agent_did_resolve_did"].ainvoke({})
    assert resolved["id"] == runtime_identity.document.id

    payload = "approve:ticket:123"
    signed = await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": payload})
    verified = await tools_by_name["agent_did_verify_signature"].ainvoke(
        {"payload": payload, "signature": signed["signature"]}
    )
    initial_key_id = integration.get_current_identity()["authentication_key_id"]
    rotated = await tools_by_name["agent_did_rotate_key"].ainvoke({})

    assert signed["did"] == runtime_identity.document.id
    assert verified["did"] == runtime_identity.document.id
    assert verified["is_valid"] is True
    assert rotated["verification_method_id"] != initial_key_id
    assert integration.get_current_identity()["authentication_key_id"] == rotated["verification_method_id"]
