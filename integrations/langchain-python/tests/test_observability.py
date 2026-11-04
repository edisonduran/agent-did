from __future__ import annotations

import io
import json
import logging

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_langchain import create_agent_did_langchain_integration
from agent_did_langchain.observability import (
    AgentDidObservabilityEvent,
    compose_event_handlers,
    create_json_logger_event_handler,
    create_langsmith_event_handler,
    create_langsmith_run_tree,
)


@pytest.mark.asyncio
async def test_identity_snapshot_refresh_emits_observability_event() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="SnapshotObserverBot",
            core_model="gpt-4.1-mini",
            system_prompt="Observe identity snapshot refreshes.",
        )
    )

    captured_events: list[AgentDidObservabilityEvent] = []
    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        observability_handler=captured_events.append,
    )

    current_identity = integration.get_current_identity()
    integration.compose_system_prompt("Base prompt")

    snapshot_events = [
        event for event in captured_events if event.event_type == "agent_did.identity_snapshot.refreshed"
    ]

    assert current_identity["did"] == runtime_identity.document.id
    assert len(snapshot_events) >= 2
    assert snapshot_events[0].attributes["did"] == runtime_identity.document.id
    assert snapshot_events[0].attributes["reason"] == "get_current_identity"
    assert snapshot_events[1].attributes["reason"] == "compose_system_prompt"


@pytest.mark.asyncio
async def test_tool_events_redact_payloads_signatures_and_headers() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="ToolObserverBot",
            core_model="gpt-4.1-mini",
            system_prompt="Observe tool inputs safely.",
        )
    )

    captured_events: list[AgentDidObservabilityEvent] = []
    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "sign_http": True},
        observability_handler=captured_events.append,
    )
    tools_by_name = {tool.name: tool for tool in integration.tools}

    await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": "very-sensitive-payload"})
    await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {
            "method": "POST",
            "url": "https://api.example.com/tasks?token=secret",
            "body": '{"secret":"value"}',
        }
    )

    started_events = [event for event in captured_events if event.event_type == "agent_did.tool.started"]
    http_success = next(
        event
        for event in captured_events
        if event.event_type == "agent_did.tool.succeeded"
        and event.attributes["tool_name"] == "agent_did_sign_http_request"
    )

    assert any(
        event.attributes["tool_name"] == "agent_did_sign_payload"
        and event.attributes["inputs"]["payload"] == {"redacted": True, "length": 22}
        for event in started_events
    )
    assert any(
        event.attributes["tool_name"] == "agent_did_sign_http_request"
        and event.attributes["inputs"]["url"] == "https://api.example.com/tasks"
        and event.attributes["inputs"]["body"] == {"redacted": True, "length": 18}
        for event in started_events
    )
    assert http_success.attributes["outputs"]["header_names"]


@pytest.mark.asyncio
async def test_tool_failure_event_emits_sanitized_error_context() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="FailureObserverBot",
            core_model="gpt-4.1-mini",
            system_prompt="Observe failures safely.",
        )
    )

    captured_events: list[AgentDidObservabilityEvent] = []
    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True},
        observability_handler=captured_events.append,
    )
    tool = {tool.name: tool for tool in integration.tools}["agent_did_sign_http_request"]

    result = await tool.ainvoke({"method": "POST", "url": "file:///tmp/secret", "body": "payload-data"})

    failed_event = next(event for event in captured_events if event.event_type == "agent_did.tool.failed")

    assert result["error"]
    assert failed_event.level == "error"
    assert failed_event.attributes["inputs"]["body"] == {"redacted": True, "length": 12}
    assert failed_event.attributes["inputs"]["url"] == "file:///tmp/secret"
    assert "http" in failed_event.attributes["error"].lower()


def test_compose_event_handlers_fans_out_to_all_handlers() -> None:
    received_a: list[AgentDidObservabilityEvent] = []
    received_b: list[AgentDidObservabilityEvent] = []
    handler = compose_event_handlers(received_a.append, None, received_b.append)

    event = AgentDidObservabilityEvent(event_type="agent_did.tool.started", attributes={"payload": "secret"})
    handler(event)

    assert len(received_a) == 1
    assert len(received_b) == 1
    assert received_a[0].attributes["payload"] == "secret"


def test_json_logger_event_handler_emits_structured_sanitized_payload() -> None:
    stream = io.StringIO()
    logger = logging.getLogger("agent_did_langchain.tests.json")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(logging.StreamHandler(stream))

    handler = create_json_logger_event_handler(
        logger,
        include_timestamp=False,
        extra_fields={"component": "tests", "payload": "should-redact"},
    )
    handler(
        AgentDidObservabilityEvent(
            event_type="agent_did.tool.started",
            level="info",
            attributes={"payload": {"redacted": True, "length": 4}, "url": "https://api.example.com/path?q=1"},
        )
    )

    record = json.loads(stream.getvalue().strip())

    assert record["source"] == "agent_did_langchain"
    assert record["event_type"] == "agent_did.tool.started"
    assert record["attributes"]["payload"] == {"redacted": True, "length": 4}
    assert record["attributes"]["url"] == "https://api.example.com/path"
    assert record["component"] == "tests"
    assert record["payload"] == {"redacted": True, "length": 13}


def test_langsmith_event_handler_tracks_tool_run_lifecycle() -> None:
    root_run = create_langsmith_run_tree(
        name="agent_did_root",
        inputs={"url": "https://api.example.com/tasks?token=secret"},
        tags=["tests"],
    )
    handler = create_langsmith_event_handler(
        root_run,
        include_timestamp=False,
        extra_fields={"service": "tests", "payload": "should-redact"},
        tags=["langsmith"],
    )

    handler(
        AgentDidObservabilityEvent(
            event_type="agent_did.tool.started",
            attributes={
                "tool_name": "agent_did_sign_payload",
                "did": "did:agent:test:123",
                "inputs": {"payload": "very-secret-payload"},
            },
        )
    )
    handler(
        AgentDidObservabilityEvent(
            event_type="agent_did.tool.succeeded",
            attributes={
                "tool_name": "agent_did_sign_payload",
                "did": "did:agent:test:123",
                "outputs": {"signature_generated": True, "key_id": "key-1"},
            },
        )
    )

    assert root_run.inputs["url"] == "https://api.example.com/tasks"
    assert len(root_run.child_runs) == 1

    child_run = root_run.child_runs[0]
    assert child_run.name == "agent_did_sign_payload"
    assert child_run.run_type == "tool"
    assert child_run.inputs["inputs"]["payload"] == {"redacted": True, "length": 19}
    assert child_run.outputs["attributes"]["outputs"]["signature_generated"] is True
    assert child_run.extra["source"] == "agent_did_langchain"


def test_langsmith_event_handler_creates_chain_run_for_snapshot_event() -> None:
    root_run = create_langsmith_run_tree(name="agent_did_snapshot_root")
    handler = create_langsmith_event_handler(root_run, include_timestamp=False)

    handler(
        AgentDidObservabilityEvent(
            event_type="agent_did.identity_snapshot.refreshed",
            attributes={"did": "did:agent:test:321", "reason": "compose_system_prompt"},
        )
    )

    assert len(root_run.child_runs) == 1
    child_run = root_run.child_runs[0]
    assert child_run.name == "agent_did.identity_snapshot.refreshed"
    assert child_run.run_type == "chain"
    assert child_run.outputs["attributes"]["reason"] == "compose_system_prompt"


def test_compose_event_handlers_can_fan_out_to_json_logger_and_langsmith() -> None:
    stream = io.StringIO()
    logger = logging.getLogger("agent_did_langchain.tests.composed")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(logging.StreamHandler(stream))

    root_run = create_langsmith_run_tree(name="agent_did_composed_root")
    captured_events: list[AgentDidObservabilityEvent] = []
    handler = compose_event_handlers(
        captured_events.append,
        create_json_logger_event_handler(logger, include_timestamp=False, extra_fields={"sink": "json"}),
        create_langsmith_event_handler(root_run, include_timestamp=False, extra_fields={"sink": "langsmith"}),
    )

    handler(
        AgentDidObservabilityEvent(
            event_type="agent_did.tool.started",
            attributes={
                "tool_name": "agent_did_sign_http_request",
                "did": "did:agent:test:compose",
                "inputs": {"url": "https://api.example.com/compose?debug=true", "body": "secret-payload"},
            },
        )
    )
    handler(
        AgentDidObservabilityEvent(
            event_type="agent_did.tool.succeeded",
            attributes={
                "tool_name": "agent_did_sign_http_request",
                "did": "did:agent:test:compose",
                "outputs": {"header_names": ["Signature", "Signature-Input"]},
            },
        )
    )

    record = json.loads(stream.getvalue().splitlines()[0])

    assert len(captured_events) == 2
    assert record["sink"] == "json"
    assert record["attributes"]["inputs"]["url"] == "https://api.example.com/compose"
    assert record["attributes"]["inputs"]["body"] == {"redacted": True, "length": 14}
    assert len(root_run.child_runs) == 1
    assert root_run.child_runs[0].outputs["attributes"]["outputs"]["header_names"] == [
        "Signature",
        "Signature-Input",
    ]
