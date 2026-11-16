"""Tests for A2A JSON-RPC message construction and signing."""

from __future__ import annotations

import json

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner
from pydantic import ValidationError

from agent_did_a2a.jsonrpc import (
    A2AMessage,
    A2APart,
    A2ATask,
    JsonRpcRequest,
    JsonRpcResponse,
    build_get_task_request,
    build_send_message_request,
    parse_jsonrpc_response,
    parse_send_message_result,
    sign_a2a_request,
    text_message,
)


def test_build_send_message_request() -> None:
    message = text_message("Hello", message_id="m-1", context_id="ctx-1")
    request = build_send_message_request(
        request_id=1, message=message, configuration={"historyLength": 2}, tenant="t1"
    )

    assert request.jsonrpc == "2.0"
    assert request.id == 1
    assert request.method == "SendMessage"
    assert request.params == {
        "message": {"messageId": "m-1", "contextId": "ctx-1", "role": "ROLE_USER", "parts": [{"text": "Hello"}]},
        "tenant": "t1",
        "configuration": {"historyLength": 2},
    }


def test_build_send_message_request_minimal() -> None:
    request = build_send_message_request(request_id="req-2", message=text_message("Hi"))

    assert set(request.params) == {"message"}
    assert request.params["message"]["messageId"]


def test_build_get_task_request() -> None:
    request = build_get_task_request(request_id=3, task_id="task-003", history_length=10)

    assert request.method == "GetTask"
    assert request.params == {"id": "task-003", "historyLength": 10}


def test_a_part_has_exactly_one_content() -> None:
    with pytest.raises(ValidationError):
        A2APart()
    with pytest.raises(ValidationError):
        A2APart(text="a", url="https://example.com/x")
    assert A2APart(data={"k": 1}, media_type="application/json").to_json() == {
        "data": {"k": 1},
        "mediaType": "application/json",
    }


def test_parse_send_message_result() -> None:
    task = parse_send_message_result(
        {"task": {"id": "t", "contextId": "c", "status": {"state": "TASK_STATE_COMPLETED"}, "newField": 1}}
    )
    assert isinstance(task, A2ATask)
    assert task.status.state == "TASK_STATE_COMPLETED"
    assert task.context_id == "c"
    message = parse_send_message_result(
        {"message": {"messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "done"}]}}
    )
    assert isinstance(message, A2AMessage)
    assert message.parts[0].text == "done"
    with pytest.raises(ValueError):
        parse_send_message_result({})


def test_parse_jsonrpc_response_from_dict() -> None:
    raw = {"jsonrpc": "2.0", "id": 1, "result": {"status": "completed"}}
    response = parse_jsonrpc_response(raw)

    assert isinstance(response, JsonRpcResponse)
    assert response.id == 1
    assert response.result is not None
    assert response.result["status"] == "completed"
    assert response.error is None


def test_parse_jsonrpc_response_from_string() -> None:
    raw = json.dumps({"jsonrpc": "2.0", "id": 2, "error": {"code": -32600, "message": "Invalid"}})
    response = parse_jsonrpc_response(raw)

    assert response.id == 2
    assert response.error is not None
    assert response.error["code"] == -32600
    assert response.result is None


def test_jsonrpc_request_serialization() -> None:
    request = JsonRpcRequest(id=42, method="SendMessage", params={"message": {}})
    data = json.loads(request.model_dump_json())

    assert data["jsonrpc"] == "2.0"
    assert data["id"] == 42
    assert data["method"] == "SendMessage"


@pytest.mark.asyncio
async def test_sign_a2a_request_produces_signed_headers() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(name="SignBot", core_model="gpt-4.1-mini", system_prompt="sign test")
    )

    request = build_send_message_request(request_id=1, message=text_message("Test"))

    signed = await sign_a2a_request(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        target_url="https://remote-agent.example.com/a2a",
        jsonrpc_request=request,
    )

    assert signed.method == "POST"
    assert signed.url == "https://remote-agent.example.com/a2a"
    assert signed.body
    assert "content-type" in {k.lower() for k in signed.headers}

    # The SDK adds Signature and Signature-Input headers
    header_keys_lower = {k.lower() for k in signed.headers}
    assert "signature" in header_keys_lower
    assert "signature-input" in header_keys_lower
    assert signed.headers["a2a-version"] == "1.0"
    assert signed.headers["a2a-extensions"] == "https://agent-did.org/a2a/identity/v1"

    # Body should be valid JSON-RPC
    body_data = json.loads(signed.body)
    assert body_data["method"] == "SendMessage"


@pytest.mark.asyncio
async def test_verify_a2a_request_uses_the_identity_client() -> None:
    """Verification goes through the identity's own client, not the process-wide default."""
    from unittest.mock import AsyncMock

    from agent_did_sdk import AgentDidClient
    from agent_did_sdk.core.types import VerifyHttpRequestSignatureResult

    from agent_did_a2a.jsonrpc import verify_a2a_request

    client = AgentDidClient()
    client.verify_http_request_signature_detailed = AsyncMock(  # type: ignore[method-assign]
        return_value=VerifyHttpRequestSignatureResult(ok=True, did="did:webvh:x", key_id="did:webvh:x#key-1")
    )
    identity = AgentIdentity(
        AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client)
    )

    assert await verify_a2a_request(
        agent_identity=identity, method="POST", url="https://example.com/a2a", headers={}, body="{}"
    )
    client.verify_http_request_signature_detailed.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_a2a_request_detailed_says_who_signed_and_applies_the_allow_lists() -> None:
    from agent_did_sdk import AgentDidClient

    from agent_did_a2a.jsonrpc import verify_a2a_request, verify_a2a_request_detailed

    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    runtime_identity = await identity.create(
        CreateAgentParams(name="A2ASender", core_model="gpt-4.1-mini", system_prompt="verify test")
    )
    request = build_send_message_request(request_id=1, message=text_message("Hi"))
    signed = await sign_a2a_request(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        target_url="https://remote-agent.example.com/a2a",
        jsonrpc_request=request,
    )
    did = runtime_identity.document.id

    def verify_args() -> dict[str, object]:
        return {
            "agent_identity": identity,
            "method": signed.method,
            "url": signed.url,
            "headers": dict(signed.headers),
            "body": signed.body,
        }

    result = await verify_a2a_request_detailed(**verify_args())  # type: ignore[arg-type]
    assert result.ok is True
    assert result.did == did
    assert result.controllers == [runtime_identity.document.controller]

    refused = await verify_a2a_request_detailed(
        **verify_args(), allowed_dids=["did:webvh:QmOther:example.com:agents:other"]  # type: ignore[arg-type]
    )
    assert refused.ok is False
    assert refused.reason == "did_not_allowed"
    assert not await verify_a2a_request(
        **verify_args(), allowed_controllers=["did:webvh:QmOther:example.com:organizations:o"]  # type: ignore[arg-type]
    )
