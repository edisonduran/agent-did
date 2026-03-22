from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_semantic_kernel import create_agent_did_semantic_kernel_integration


@pytest.mark.asyncio
async def test_secure_defaults_keep_sensitive_tools_disabled() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x6161616161616161616161616161616161616161"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="MicrosoftSecureDefaultsBot",
            core_model="gpt-4.1-mini",
            system_prompt="Security test",
        )
    )

    integration = create_agent_did_semantic_kernel_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
    )

    tool_names = {tool.name for tool in integration.tools}

    assert "agent_did_sign_http_request" not in tool_names
    assert "agent_did_sign_payload" not in tool_names
    assert "agent_did_rotate_key" not in tool_names
    assert "agent_did_get_document_history" not in tool_names


@pytest.mark.asyncio
async def test_http_signing_rejects_private_targets_by_default() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x6262626262626262626262626262626262626262"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="MicrosoftHttpPolicyBot",
            core_model="gpt-4.1-mini",
            system_prompt="HTTP policy test",
        )
    )

    integration = create_agent_did_semantic_kernel_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True},
    )
    sign_http_tool = next(tool for tool in integration.tools if tool.name == "agent_did_sign_http_request")

    result = await sign_http_tool.ainvoke(
        {
            "method": "GET",
            "url": "http://127.0.0.1/internal",
        }
    )

    assert result == {"error": "Private or loopback HTTP targets are not allowed by default"}
