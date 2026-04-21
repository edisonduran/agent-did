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


def test_create_agent_kwargs_exposes_native_tools_and_instructions() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9797979797979797979797979797979797979797"))
    runtime_identity = asyncio.run(
        identity.create(
            CreateAgentParams(
                name="MicrosoftAgentFrameworkBot",
                description="Agent Framework integration test",
                core_model="gpt-4.1-mini",
                system_prompt="Use tools when evidence is needed.",
                capabilities=["identity:resolve", "signature:verify"],
            )
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True},
    )

    agent_kwargs = integration.create_agent_kwargs("Use Agent-DID tools for verifiable identity tasks.")

    assert "Agent-DID identity context:" in agent_kwargs["instructions"]
    assert runtime_identity.document.id in agent_kwargs["instructions"]
    assert [tool.name for tool in integration.tools] == [tool.name for tool in agent_kwargs["tools"]]
    assert "agent_did_get_current_identity" in [tool.name for tool in integration.tools]
    assert "agent_did_sign_payload" in [tool.name for tool in integration.tools]


def test_rotate_key_tool_updates_runtime_identity_reference() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9898989898989898989898989898989898989898"))
    runtime_identity = asyncio.run(
        identity.create(
            CreateAgentParams(
                name="RotateKeyBot",
                description="Rotate key integration test",
                core_model="gpt-4.1-mini",
                system_prompt="Rotate keys only when explicitly asked.",
                capabilities=["key:rotate"],
            )
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"rotate_keys": True},
    )
    rotate_tool = next(tool for tool in integration.tools if tool.name == "agent_did_rotate_key")

    rotated = asyncio.run(rotate_tool.func())

    assert rotated["verificationMethodId"]
    assert integration.identity_snapshot.authentication_key_id == rotated["verificationMethodId"]


def test_workflow_helpers_emit_orchestration_events_and_build_chain() -> None:
    events = []

    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x8787878787878787878787878787878787878787"))
    runtime_identity = asyncio.run(
        identity.create(
            CreateAgentParams(
                name="WorkflowBot",
                description="Workflow integration test",
                core_model="gpt-4.1-mini",
                system_prompt="Coordinate verifiable identity tasks.",
                capabilities=["identity:resolve", "workflow:run"],
            )
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        observability_handler=events.append,
    )

    planner = integration.create_agent(DummyChatClient("planner"), name="Planner")
    reviewer = integration.create_agent(DummyChatClient("reviewer"), name="Reviewer")
    planner_executor = integration.create_agent_executor(planner, executor_id="planner_executor")
    reviewer_executor = integration.create_agent_executor(reviewer, executor_id="reviewer_executor")
    workflow = integration.build_workflow_chain(
        [planner_executor, reviewer_executor],
        name="identity_workflow",
        description="Identity workflow coverage",
    )

    result = asyncio.run(workflow.run("draft verifiable identity report"))
    outputs = result.get_outputs()

    assert outputs[0].value == "reviewer:planner:draft verifiable identity report"
    assert {event.event_type for event in events} >= {
        "agent_did.workflow.executor_created",
        "agent_did.workflow.builder_created",
        "agent_did.workflow.chain_built",
    }


def test_advanced_workflow_helpers_emit_specialized_events() -> None:
    events = []

    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x8686868686868686868686868686868686868686"))
    runtime_identity = asyncio.run(
        identity.create(
            CreateAgentParams(
                name="AdvancedWorkflowBot",
                description="Advanced workflow helper integration test",
                core_model="gpt-4.1-mini",
                system_prompt="Coordinate advanced identity workflows.",
                capabilities=["identity:resolve", "workflow:run"],
            )
        )
    )

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        observability_handler=events.append,
    )

    router = integration.create_agent_executor(integration.create_agent(DummyChatClient("router"), name="Router"))
    branch_a = integration.create_agent_executor(integration.create_agent(DummyChatClient("branch_a"), name="A"))
    branch_b = integration.create_agent_executor(integration.create_agent(DummyChatClient("branch_b"), name="B"))
    reducer = integration.create_function_executor(
        lambda responses: "reducer:" + "|".join(sorted(response.agent_response.value for response in responses)),
        executor_id="reducer_executor",
        input_type=list[AgentExecutorResponse],
        output_type=str,
        workflow_output_type=str,
    )
    approve = integration.create_agent_executor(integration.create_agent(DummyChatClient("approve"), name="Approve"))
    fallback = integration.create_agent_executor(integration.create_agent(DummyChatClient("fallback"), name="Fallback"))

    fan_workflow = integration.build_fan_out_fan_in_workflow(
        router,
        [branch_a, branch_b],
        reducer,
        name="fan_workflow",
    )
    selection_workflow = integration.build_multi_selection_workflow(
        router,
        [branch_a, branch_b],
        lambda data, targets: targets,
        name="selection_workflow",
    )
    switch_workflow = integration.build_switch_case_workflow(
        router,
        cases=[(lambda data: "approve" in str(data).lower(), approve)],
        default_target=fallback,
        name="switch_workflow",
        output_executors=[approve, fallback],
    )

    assert fan_workflow is not None
    assert selection_workflow is not None
    assert switch_workflow is not None
    assert {event.event_type for event in events} >= {
        "agent_did.workflow.function_executor_created",
        "agent_did.workflow.fan_out_fan_in_built",
        "agent_did.workflow.multi_selection_built",
        "agent_did.workflow.switch_case_built",
    }
