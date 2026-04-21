from __future__ import annotations

import asyncio

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry
from agent_framework import AgentExecutorResponse, BaseChatClient, ChatResponse, Message

from agent_did_microsoft_agent_framework import create_agent_did_microsoft_agent_framework_integration


def _extract_message_text(message: object) -> str:
    legacy_text = getattr(message, "text", None)
    if isinstance(legacy_text, str) and legacy_text:
        return legacy_text

    contents = getattr(message, "contents", None) or ()
    text_parts: list[str] = []
    for content in contents:
        if isinstance(content, str):
            text_parts.append(content)
            continue

        text_value = getattr(content, "text", None)
        if isinstance(text_value, str) and text_value:
            text_parts.append(text_value)

    return "".join(text_parts) or "none"


class DummyChatClient(BaseChatClient):
    def __init__(self, label: str = "agent"):
        super().__init__()
        self.label = label

    async def _inner_get_response(self, *, messages, stream, options, **kwargs):  # type: ignore[override]
        text = _extract_message_text(messages[-1]) if messages else "none"
        response_text = f"{self.label}:{text}"
        return ChatResponse(
            messages=Message("assistant", [response_text]),
            finish_reason="stop",
            value=response_text,
        )


def test_real_agent_framework_runtime_accepts_agent_did_bundle() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x6767676767676767676767676767676767676767"))
    runtime_identity = asyncio.run(
        identity.create(
            CreateAgentParams(
                name="AgentFrameworkRuntimeBot",
                description="Real Agent Framework runtime smoke test",
                core_model="gpt-4.1-mini",
                system_prompt=(
                    "Validate Agent-DID wiring against a real agent-framework install without external model calls."
                ),
                capabilities=["identity:resolve", "signature:verify"],
            )
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True},
    )

    agent = integration.create_agent(
        DummyChatClient(),
        name="Verifier",
        description="Smoke host for Agent-DID + Microsoft Agent Framework",
        base_instructions="Use Agent-DID tools when verifiable identity evidence is required.",
    )

    assert type(agent).__name__ == "Agent"
    assert agent.name == "Verifier"
    assert len(integration.tools) == 4
    assert [tool.name for tool in integration.tools] == [
        "agent_did_get_current_identity",
        "agent_did_resolve_did",
        "agent_did_verify_signature",
        "agent_did_sign_payload",
    ]


def test_real_agent_framework_runtime_supports_multistep_workflow_orchestration() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x6868686868686868686868686868686868686868"))
    runtime_identity = asyncio.run(
        identity.create(
            CreateAgentParams(
                name="AgentFrameworkWorkflowBot",
                description="Advanced Microsoft Agent Framework workflow validation",
                core_model="gpt-4.1-mini",
                system_prompt=(
                    "Validate Agent-DID workflow orchestration against a real agent-framework install "
                    "without external model calls."
                ),
                capabilities=["identity:resolve", "signature:verify", "key:rotate", "workflow:run"],
            )
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "rotate_keys": True, "document_history": True},
    )

    current_identity_tool = integration.get_tool("agent_did_get_current_identity")
    sign_payload_tool = integration.get_tool("agent_did_sign_payload")
    verify_signature_tool = integration.get_tool("agent_did_verify_signature")
    rotate_key_tool = integration.get_tool("agent_did_rotate_key")
    document_history_tool = integration.get_tool("agent_did_get_document_history")

    initial_identity = current_identity_tool.func()
    first_signature = asyncio.run(sign_payload_tool.func(payload="workflow-payload-before-rotation"))
    rotation = asyncio.run(rotate_key_tool.func())
    second_signature = asyncio.run(sign_payload_tool.func(payload="workflow-payload-after-rotation"))
    second_verification = asyncio.run(
        verify_signature_tool.func(
            payload=second_signature["payload"],
            signature=second_signature["signature"],
            did=runtime_identity.document.id,
            key_id=second_signature["key_id"],
        )
    )
    document_history = asyncio.run(document_history_tool.func())

    planner = integration.create_agent(
        DummyChatClient("planner"),
        name="Planner",
        description="Identity planner",
        base_instructions="Plan a verifiable identity response.",
    )
    reviewer = integration.create_agent(
        DummyChatClient("reviewer"),
        name="Reviewer",
        description="Identity reviewer",
        base_instructions="Review the planner response and emit a final answer.",
    )
    planner_executor = integration.create_agent_executor(planner, executor_id="planner_executor")
    reviewer_executor = integration.create_agent_executor(reviewer, executor_id="reviewer_executor")
    workflow = integration.build_workflow_chain(
        [planner_executor, reviewer_executor],
        name="identity_review_workflow",
        description="Planner to reviewer identity workflow",
    )
    workflow_result = asyncio.run(workflow.run("draft verifiable identity report"))
    outputs = workflow_result.get_outputs()

    assert initial_identity["authentication_key_id"] == first_signature["key_id"]
    assert rotation["verificationMethodId"] == integration.identity_snapshot.authentication_key_id
    assert second_signature["key_id"] == rotation["verificationMethodId"]
    assert second_verification["is_valid"] is True
    assert len(document_history) >= 2
    assert outputs[0].value == "reviewer:planner:draft verifiable identity report"
    assert len(workflow_result) > 0


def test_real_agent_framework_runtime_supports_advanced_workflow_patterns() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x6969696969696969696969696969696969696969"))
    runtime_identity = asyncio.run(
        identity.create(
            CreateAgentParams(
                name="AgentFrameworkAdvancedWorkflowBot",
                description="Advanced workflow pattern validation",
                core_model="gpt-4.1-mini",
                system_prompt="Validate advanced Microsoft Agent Framework workflow patterns.",
                capabilities=["identity:resolve", "workflow:run"],
            )
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
    )
    reducer_results: list[str] = []

    def reduce_branch_outputs(responses: list[AgentExecutorResponse]) -> str:
        reduced = "reducer:" + "|".join(sorted(response.agent_response.value for response in responses))
        reducer_results.append(reduced)
        return reduced

    def should_approve(data: object) -> bool:
        candidate = getattr(getattr(data, "agent_response", None), "value", data)
        return "approve" in str(candidate).lower()

    router = integration.create_agent(DummyChatClient("router"), name="Router")
    branch_a = integration.create_agent(DummyChatClient("branch_a"), name="BranchA")
    branch_b = integration.create_agent(DummyChatClient("branch_b"), name="BranchB")
    approve = integration.create_agent(DummyChatClient("approve"), name="Approve")
    fallback = integration.create_agent(DummyChatClient("fallback"), name="Fallback")

    router_executor = integration.create_agent_executor(router, executor_id="router_executor")
    branch_a_executor = integration.create_agent_executor(branch_a, executor_id="branch_a_executor")
    branch_b_executor = integration.create_agent_executor(branch_b, executor_id="branch_b_executor")
    reducer_executor = integration.create_function_executor(
        reduce_branch_outputs,
        executor_id="reducer_executor",
        input_type=list[AgentExecutorResponse],
        output_type=str,
        workflow_output_type=str,
    )
    approve_executor = integration.create_agent_executor(approve, executor_id="approve_executor")
    fallback_executor = integration.create_agent_executor(fallback, executor_id="fallback_executor")

    fan_workflow = integration.build_fan_out_fan_in_workflow(
        router_executor,
        [branch_a_executor, branch_b_executor],
        reducer_executor,
        name="identity_fan_workflow",
        description="Fan-out/fan-in identity workflow",
    )
    asyncio.run(fan_workflow.run("fan workflow request"))
    selection_workflow = integration.build_multi_selection_workflow(
        router_executor,
        [branch_a_executor, branch_b_executor],
        lambda data, targets: targets,
        name="identity_selection_workflow",
        description="Multi-selection identity workflow",
    )
    selection_result = asyncio.run(selection_workflow.run("selection workflow request"))
    selected_executor_ids = {
        event.executor_id
        for event in selection_result
        if getattr(event, "type", None) == "executor_completed"
        and getattr(event, "executor_id", None) in {"branch_a_executor", "branch_b_executor"}
    }

    switch_workflow = integration.build_switch_case_workflow(
        router_executor,
        cases=[(should_approve, approve_executor)],
        default_target=fallback_executor,
        name="identity_switch_workflow",
        description="Switch-case identity workflow",
        output_executors=[approve_executor, fallback_executor],
    )
    approve_result = asyncio.run(switch_workflow.run("please approve this response"))
    fallback_result = asyncio.run(switch_workflow.run("reject this response"))

    assert reducer_results[0] == (
        "reducer:branch_a:router:fan workflow request|branch_b:router:fan workflow request"
    )
    assert selected_executor_ids == {"branch_a_executor", "branch_b_executor"}
    assert approve_result.get_outputs()[0].value == "approve:router:please approve this response"
    assert fallback_result.get_outputs()[0].value == "fallback:router:reject this response"
