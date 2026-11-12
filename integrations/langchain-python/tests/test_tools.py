from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_langchain.integration import create_agent_did_langchain_integration


@pytest.mark.asyncio
async def test_tools_expose_identity_resolution_and_signature_verification() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="ToolBot",
            description="Testing LangChain tools",
            core_model="gpt-4.1-mini",
            system_prompt="Tool test",
            capabilities=["verify:signature"],
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"resolve_did": True, "verify_signatures": True, "sign_payload": True, "rotate_keys": True},
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


@pytest.mark.asyncio
async def test_tools_return_structured_errors_on_invalid_inputs() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="ErrorBot",
            core_model="gpt-4.1-mini",
            system_prompt="Tool test",
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={
            "resolve_did": True,
            "verify_signatures": True,
        }
    )
    tools_by_name = {tool.name: tool for tool in integration.tools}

    malformed = await tools_by_name["agent_did_verify_signature"].ainvoke(
        {"payload": "test", "signature": "not-a-valid-hex-signature"}
    )
    unresolved = await tools_by_name["agent_did_resolve_did"].ainvoke({"did": "did:agent:polygon:0xnonexistent"})

    assert malformed.get("error") or malformed["is_valid"] is False
    assert unresolved["error"]
