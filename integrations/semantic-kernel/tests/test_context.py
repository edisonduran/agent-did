from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_semantic_kernel import create_agent_did_semantic_kernel_integration


@pytest.mark.asyncio
async def test_session_context_and_middleware_inject_identity_without_secrets() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x5858585858585858585858585858585858585858"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="MicrosoftContextBot",
            core_model="gpt-4.1-mini",
            system_prompt="Context test",
        )
    )

    integration = create_agent_did_semantic_kernel_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
    )

    session_context = integration.create_session_context({"tenant": "demo"})
    middleware = integration.create_context_middleware(context_key="identity")
    middleware_context = middleware({"workflow": "intake"})

    assert session_context["tenant"] == "demo"
    assert session_context["agent_did"]["did"] == runtime_identity.document.id
    assert "agent_private_key" not in session_context["agent_did"]
    assert middleware_context["workflow"] == "intake"
    assert middleware_context["identity"]["did"] == runtime_identity.document.id
    assert "agent_private_key" not in middleware_context["identity"]
