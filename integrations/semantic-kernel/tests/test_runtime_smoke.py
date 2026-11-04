from __future__ import annotations

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_semantic_kernel import create_agent_did_semantic_kernel_integration


@pytest.mark.asyncio
async def test_real_semantic_kernel_runtime_accepts_agent_did_plugin() -> None:
    pytest.importorskip("semantic_kernel")
    from semantic_kernel.agents.chat_completion.chat_completion_agent import ChatCompletionAgent
    from semantic_kernel.kernel import Kernel

    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
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


@pytest.mark.asyncio
async def test_real_semantic_kernel_runtime_supports_multistep_identity_lifecycle() -> None:
    pytest.importorskip("semantic_kernel")
    from semantic_kernel.agents.chat_completion.chat_completion_agent import ChatCompletionAgent
    from semantic_kernel.kernel import Kernel

    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="SemanticKernelLifecycleBot",
            description="Advanced semantic-kernel runtime lifecycle validation",
            core_model="gpt-4.1-mini",
            system_prompt=(
                "Validate Agent-DID multistep runtime behavior against a real semantic-kernel host "
                "without executing an LLM run."
            ),
            capabilities=["identity:resolve", "signature:verify", "key:rotate"],
        )
    )

    integration = create_agent_did_semantic_kernel_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "document_history": True, "rotate_keys": True},
    )
    plugin = integration.create_semantic_kernel_plugin(plugin_name="agent_did_runtime")
    kernel = Kernel()
    kernel.add_plugin(plugin)
    agent = ChatCompletionAgent(
        name="LifecycleVerifier",
        instructions=integration.compose_instructions("Use Agent-DID tools when lifecycle evidence is required."),
        kernel=kernel,
        plugins=[plugin],
    )

    context_middleware = integration.create_context_middleware(context_key="runtime_agent_did")
    pre_rotation_context = context_middleware({"session_id": "runtime-smoke"})
    pre_rotation_key_id = pre_rotation_context["runtime_agent_did"]["authentication_key_id"]

    initial_identity = await kernel.invoke(
        function_name="agent_did_get_current_identity",
        plugin_name="agent_did_runtime",
    )
    first_signature = await kernel.invoke(
        function_name="agent_did_sign_payload",
        plugin_name="agent_did_runtime",
        payload="runtime-lifecycle-payload-before-rotation",
    )
    first_verification = await kernel.invoke(
        function_name="agent_did_verify_signature",
        plugin_name="agent_did_runtime",
        did=runtime_identity.document.id,
        key_id=first_signature.value["key_id"],
        payload=first_signature.value["payload"],
        signature=first_signature.value["signature"],
    )
    rotation = await kernel.invoke(
        function_name="agent_did_rotate_key",
        plugin_name="agent_did_runtime",
    )
    post_rotation_context = context_middleware({"session_id": "runtime-smoke", "step": "after_rotation"})
    post_rotation_key_id = post_rotation_context["runtime_agent_did"]["authentication_key_id"]
    second_signature = await kernel.invoke(
        function_name="agent_did_sign_payload",
        plugin_name="agent_did_runtime",
        payload="runtime-lifecycle-payload-after-rotation",
    )
    second_verification = await kernel.invoke(
        function_name="agent_did_verify_signature",
        plugin_name="agent_did_runtime",
        did=runtime_identity.document.id,
        key_id=second_signature.value["key_id"],
        payload=second_signature.value["payload"],
        signature=second_signature.value["signature"],
    )
    resolved_document = await kernel.invoke(
        function_name="agent_did_resolve_did",
        plugin_name="agent_did_runtime",
    )
    document_history = await kernel.invoke(
        function_name="agent_did_get_document_history",
        plugin_name="agent_did_runtime",
    )
    refreshed_agent_kwargs = integration.create_agent_kwargs("Use Agent-DID tools when lifecycle evidence is required.")

    assert type(agent).__name__ == "ChatCompletionAgent"
    assert initial_identity.value["authentication_key_id"] == pre_rotation_key_id
    assert first_verification.value["is_valid"] is True
    assert rotation.value["verification_method_id"] == post_rotation_key_id
    assert pre_rotation_key_id != post_rotation_key_id
    assert second_verification.value["is_valid"] is True
    assert resolved_document.value["id"] == runtime_identity.document.id
    assert len(document_history.value) >= 2
    assert second_signature.value["key_id"] == post_rotation_key_id
    assert refreshed_agent_kwargs["context"]["agent_did"]["authentication_key_id"] == post_rotation_key_id

