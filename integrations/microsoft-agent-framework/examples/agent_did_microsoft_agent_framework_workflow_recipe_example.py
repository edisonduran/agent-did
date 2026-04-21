from __future__ import annotations

import asyncio

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry
from agent_framework import BaseChatClient, ChatResponse, Message

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
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x5858585858585858585858585858585858585858"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="MicrosoftAgentFrameworkWorkflowBot",
            description="Workflow recipe for Agent-DID + Microsoft Agent Framework",
            core_model="gpt-4.1-mini",
            system_prompt="Coordinate multi-step identity workflows.",
            capabilities=["identity:resolve", "signature:verify", "workflow:run", "key:rotate"],
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "rotate_keys": True, "document_history": True},
    )

    sign_payload_tool = integration.get_tool("agent_did_sign_payload")
    rotate_key_tool = integration.get_tool("agent_did_rotate_key")
    document_history_tool = integration.get_tool("agent_did_get_document_history")

    first_signature = await sign_payload_tool.func(payload="workflow-recipe-before-rotation")
    rotation = await rotate_key_tool.func()
    second_signature = await sign_payload_tool.func(payload="workflow-recipe-after-rotation")
    history = await document_history_tool.func()

    planner = integration.create_agent(
        DummyChatClient("planner"),
        name="Planner",
        description="Draft identity-aware output",
        base_instructions="Plan a verifiable response.",
    )
    reviewer = integration.create_agent(
        DummyChatClient("reviewer"),
        name="Reviewer",
        description="Review and finalize the response",
        base_instructions="Review the planner output and finalize the answer.",
    )

    workflow = integration.build_workflow_chain(
        [
            integration.create_agent_executor(planner, executor_id="planner_executor"),
            integration.create_agent_executor(reviewer, executor_id="reviewer_executor"),
        ],
        name="identity_workflow_recipe",
        description="Two-step identity workflow recipe",
    )
    workflow_result = await workflow.run("draft verifiable identity report")
    outputs = workflow_result.get_outputs()

    print("first_signature_key", first_signature["key_id"])
    print("rotated_key", rotation["verificationMethodId"])
    print("second_signature_key", second_signature["key_id"])
    print("document_history_entries", len(history))
    print("workflow_output", outputs[0].value)


if __name__ == "__main__":
    asyncio.run(main())
