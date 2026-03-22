from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_crewai import create_agent_did_crewai_integration
from agent_did_crewai.callbacks import create_step_callback
from agent_did_crewai.guardrails import create_identity_output_guardrail


@pytest.mark.asyncio
async def test_sensitive_tools_are_opt_in_and_http_validation_is_enforced() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9494949494949494949494949494949494949494"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="CrewSecurityBot",
            core_model="gpt-4.1-mini",
            system_prompt="Security test",
        )
    )

    default_integration = create_agent_did_crewai_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
    )
    default_tool_names = {tool.name for tool in default_integration.tools}
    assert "agent_did_sign_http_request" not in default_tool_names
    assert "agent_did_sign_payload" not in default_tool_names
    assert "agent_did_rotate_key" not in default_tool_names

    enabled_integration = create_agent_did_crewai_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True},
    )
    tools_by_name = {tool.name: tool for tool in enabled_integration.tools}
    rejected = await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {"method": "GET", "url": "file:///etc/passwd"}
    )

    assert "error" in rejected
    assert "http" in rejected["error"].lower()


@pytest.mark.asyncio
async def test_callbacks_are_sanitized_and_guardrails_block_sensitive_outputs() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9696969696969696969696969696969696969696"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="CrewAuditBot",
            core_model="gpt-4.1-mini",
            system_prompt="Audit test",
        )
    )

    integration = create_agent_did_crewai_integration(agent_identity=identity, runtime_identity=runtime_identity)
    step_callback = create_step_callback(integration)
    guardrail = create_identity_output_guardrail(integration, required_fields=["result"])

    event = step_callback({"payload": "secret", "signature": "sig", "result": "ok"})
    allowed, allowed_message = guardrail({"did": runtime_identity.document.id, "result": "ok"})
    blocked, blocked_message = guardrail({"did": runtime_identity.document.id, "result": "ok", "payload": "secret"})

    assert event["step_output"]["payload"] == "[REDACTED]"
    assert event["step_output"]["signature"] == "[REDACTED]"
    assert allowed is True
    assert allowed_message is None
    assert blocked is False
    assert blocked_message is not None
    assert "payload" in blocked_message
