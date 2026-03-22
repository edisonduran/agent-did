from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_semantic_kernel import create_agent_did_semantic_kernel_integration


@pytest.mark.asyncio
async def test_real_semantic_kernel_runtime_accepts_agent_did_plugin() -> None:
    pytest.importorskip("semantic_kernel")
    from semantic_kernel.agents.chat_completion.chat_completion_agent import ChatCompletionAgent
    from semantic_kernel.kernel import Kernel

    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x6767676767676767676767676767676767676767"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="SemanticKernelRuntimeBot",
            description="Real semantic-kernel runtime smoke test",
            core_model="gpt-4.1-mini",
            system_prompt=(
                "Validate Agent-DID wiring against a real semantic-kernel install "
                "without executing an LLM run."
            ),
            capabilities=["identity:resolve"],
        )
    )

    integration = create_agent_did_semantic_kernel_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True},
    )
    plugin = integration.create_semantic_kernel_plugin(plugin_name="agent_did_runtime")
    kernel = Kernel()
    kernel.add_plugin(plugin)
    agent = ChatCompletionAgent(
        name="Verifier",
        instructions=integration.compose_instructions("Use Agent-DID tools when evidence is required."),
        kernel=kernel,
        plugins=[plugin],
    )

    result = await kernel.invoke(
        function_name="agent_did_get_current_identity",
        plugin_name="agent_did_runtime",
    )
    signed_payload = await kernel.invoke(
        function_name="agent_did_sign_payload",
        plugin_name="agent_did_runtime",
        payload="runtime-smoke-payload",
    )

    assert type(agent).__name__ == "ChatCompletionAgent"
    assert "agent_did_runtime" in kernel.plugins
    assert sorted(plugin.functions.keys()) == sorted(tool.name for tool in integration.tools)
    assert result is not None
    assert result.value["did"] == runtime_identity.document.id
    assert signed_payload.value["did"] == runtime_identity.document.id
    assert signed_payload.value["signature"]

