from __future__ import annotations

import pytest
from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryAgentRegistry,
    LocalKeySigner,
    VerifyHttpRequestSignatureParams,
)

from agent_did_langchain.integration import create_agent_did_langchain_integration


@pytest.mark.asyncio
async def test_sensitive_tools_are_opt_in_and_http_signing_rejects_non_http_schemes() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="SecurityBot",
            core_model="gpt-4.1-mini",
            system_prompt="Security test",
        )
    )

    default_integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
    )
    default_tool_names = {tool.name for tool in default_integration.tools}

    assert "agent_did_sign_http_request" not in default_tool_names
    assert "agent_did_sign_payload" not in default_tool_names
    assert "agent_did_rotate_key" not in default_tool_names

    enabled_integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True},
    )
    tools_by_name = {tool.name: tool for tool in enabled_integration.tools}

    rejected = await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {"method": "GET", "url": "file:///etc/passwd"}
    )

    assert rejected["error"]
    assert "http" in rejected["error"].lower()

    rejected_private = await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {"method": "GET", "url": "http://127.0.0.1:8080/health"}
    )

    assert rejected_private["error"]
    assert "private" in rejected_private["error"].lower() or "loopback" in rejected_private["error"].lower()


@pytest.mark.asyncio
async def test_http_signing_is_secret_safe_and_verifiable() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="HttpBot",
            core_model="gpt-4.1-mini",
            system_prompt="HTTP signing test",
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True},
    )
    tool = {tool.name: tool for tool in integration.tools}["agent_did_sign_http_request"]

    result = await tool.ainvoke(
        {
            "method": "POST",
            "url": "https://api.example.com/tasks",
            "body": '{"taskId":7}',
        }
    )

    assert result["did"] == runtime_identity.document.id
    assert runtime_identity.agent_private_key not in str(result)

    is_valid = await AgentIdentity.verify_http_request_signature(
        VerifyHttpRequestSignatureParams(
            method="POST",
            url="https://api.example.com/tasks",
            body='{"taskId":7}',
            headers=result["headers"],
        )
    )

    assert is_valid is True


@pytest.mark.asyncio
async def test_private_network_targets_can_be_enabled_explicitly() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="PrivateHttpBot",
            core_model="gpt-4.1-mini",
            system_prompt="Private HTTP signing test",
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True},
        allow_private_network_targets=True,
    )
    tool = {tool.name: tool for tool in integration.tools}["agent_did_sign_http_request"]

    result = await tool.ainvoke({"method": "GET", "url": "http://127.0.0.1:8080/health"})

    assert result["headers"]["Signature-Agent"] == runtime_identity.document.id
