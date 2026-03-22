from __future__ import annotations

import io
import json
import logging

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_crewai import create_agent_did_crewai_integration
from agent_did_crewai.callbacks import create_step_callback
from agent_did_crewai.observability import (
    AgentDidCrewAIObservabilityEvent,
    compose_event_handlers,
    create_json_logger_event_handler,
)


@pytest.mark.asyncio
async def test_identity_snapshot_refresh_emits_observability_event() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x8181818181818181818181818181818181818181"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="CrewSnapshotObserverBot",
            core_model="gpt-4.1-mini",
            system_prompt="Observe identity snapshot refreshes.",
        )
    )

    captured_events: list[AgentDidCrewAIObservabilityEvent] = []
    integration = create_agent_did_crewai_integration(
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
async def test_tool_events_redact_payloads_bodies_and_urls() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x8282828282828282828282828282828282828282"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="CrewToolObserverBot",
            core_model="gpt-4.1-mini",
            system_prompt="Observe tool inputs safely.",
        )
    )

    captured_events: list[AgentDidCrewAIObservabilityEvent] = []
    integration = create_agent_did_crewai_integration(
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
async def test_step_callback_emits_structured_observability_event() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x8383838383838383838383838383838383838383"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="CrewCallbackObserverBot",
            core_model="gpt-4.1-mini",
            system_prompt="Observe callbacks safely.",
        )
    )

    captured_events: list[AgentDidCrewAIObservabilityEvent] = []
    integration = create_agent_did_crewai_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        observability_handler=captured_events.append,
    )
    callback = create_step_callback(integration)

    callback_result = callback({"payload": "secret", "signature": "sig", "result": "ok"})
    observed_event = next(event for event in captured_events if event.event_type == "agent_did.crewai.step")

    assert callback_result["step_output"]["payload"] == "[REDACTED]"
    assert observed_event.attributes["step_output"]["payload"] == {"redacted": True, "length": 6}
    assert observed_event.attributes["step_output"]["signature"] == {"redacted": True, "length": 3}


def test_compose_event_handlers_fans_out_to_all_handlers() -> None:
    received_a: list[AgentDidCrewAIObservabilityEvent] = []
    received_b: list[AgentDidCrewAIObservabilityEvent] = []
    handler = compose_event_handlers(received_a.append, None, received_b.append)

    event = AgentDidCrewAIObservabilityEvent(event_type="agent_did.tool.started", attributes={"payload": "secret"})
    handler(event)

    assert len(received_a) == 1
    assert len(received_b) == 1
    assert received_a[0].attributes["payload"] == "secret"


def test_json_logger_event_handler_emits_structured_sanitized_payload() -> None:
    stream = io.StringIO()
    logger = logging.getLogger("agent_did_crewai.tests.json")
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
        AgentDidCrewAIObservabilityEvent(
            event_type="agent_did.tool.started",
            level="info",
            attributes={"payload": {"redacted": True, "length": 4}, "url": "https://api.example.com/path?q=1"},
        )
    )

    record = json.loads(stream.getvalue().strip())

    assert record["source"] == "agent_did_crewai"
    assert record["event_type"] == "agent_did.tool.started"
    assert record["attributes"]["payload"] == {"redacted": True, "length": 4}
    assert record["attributes"]["url"] == "https://api.example.com/path"
    assert record["component"] == "tests"
    assert record["payload"] == {"redacted": True, "length": 13}
