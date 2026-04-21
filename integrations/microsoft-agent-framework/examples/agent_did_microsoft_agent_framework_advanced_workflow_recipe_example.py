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
    def __init__(self, label: str):
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


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x5757575757575757575757575757575757575757"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="MicrosoftAgentFrameworkAdvancedWorkflowBot",
            description="Advanced workflow recipe for Agent-DID + Microsoft Agent Framework",
            core_model="gpt-4.1-mini",
            system_prompt="Coordinate advanced multi-agent identity workflows.",
            capabilities=["identity:resolve", "workflow:run"],
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

    router = integration.create_agent_executor(
        integration.create_agent(DummyChatClient("router"), name="Router"),
        executor_id="router_executor",
    )
    branch_a = integration.create_agent_executor(
        integration.create_agent(DummyChatClient("branch_a"), name="BranchA"),
        executor_id="branch_a_executor",
    )
    branch_b = integration.create_agent_executor(
        integration.create_agent(DummyChatClient("branch_b"), name="BranchB"),
        executor_id="branch_b_executor",
    )
    reducer = integration.create_function_executor(
        reduce_branch_outputs,
        executor_id="reducer_executor",
        input_type=list[AgentExecutorResponse],
        output_type=str,
        workflow_output_type=str,
    )
    approve = integration.create_agent_executor(
        integration.create_agent(DummyChatClient("approve"), name="Approve"),
        executor_id="approve_executor",
    )
    fallback = integration.create_agent_executor(
        integration.create_agent(DummyChatClient("fallback"), name="Fallback"),
        executor_id="fallback_executor",
    )

    fan_workflow = integration.build_fan_out_fan_in_workflow(
        router,
        [branch_a, branch_b],
        reducer,
        name="advanced_fan_workflow",
    )
    await fan_workflow.run("fan workflow request")

    selection_workflow = integration.build_multi_selection_workflow(
        router,
        [branch_a, branch_b],
        lambda data, targets: targets,
        name="advanced_selection_workflow",
    )
    selection_result = await selection_workflow.run("selection workflow request")
    selected_executor_ids = sorted(
        {
            event.executor_id
            for event in selection_result
            if getattr(event, "type", None) == "executor_completed"
            and getattr(event, "executor_id", None) in {"branch_a_executor", "branch_b_executor"}
        }
    )

    switch_workflow = integration.build_switch_case_workflow(
        router,
        cases=[(should_approve, approve)],
        default_target=fallback,
        name="advanced_switch_workflow",
        output_executors=[approve, fallback],
    )
    approve_result = await switch_workflow.run("please approve this response")
    fallback_result = await switch_workflow.run("reject this response")

    print("fan_output", reducer_results[0])
    print("selection_executors", selected_executor_ids)
    print("switch_approve_output", approve_result.get_outputs()[0].value)
    print("switch_fallback_output", fallback_result.get_outputs()[0].value)


if __name__ == "__main__":
    asyncio.run(main())
