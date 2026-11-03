"""Tests for A2A JSON-RPC message construction and signing."""

from __future__ import annotations

import json

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_a2a.jsonrpc import (
    JsonRpcRequest,
    JsonRpcResponse,
    build_task_get_request,
    build_task_send_request,
    parse_jsonrpc_response,
    sign_a2a_request,
)


def test_build_task_send_request() -> None:
    request = build_task_send_request(
        request_id=1,
        task_id="task-001",
        message={"role": "user", "parts": [{"type": "text", "text": "Hello"}]},
        session_id="session-abc",
    )

    assert request.jsonrpc == "2.0"
    assert request.id == 1
    assert request.method == "tasks/send"
    assert request.params["id"] == "task-001"
    assert request.params["sessionId"] == "session-abc"
    assert request.params["message"]["role"] == "user"


def test_build_task_send_request_without_session() -> None:
    request = build_task_send_request(
        request_id="req-2",
        task_id="task-002",
        message={"role": "user", "parts": [{"type": "text", "text": "Hi"}]},
    )

    assert "sessionId" not in request.params


def test_build_task_get_request() -> None:
    request = build_task_get_request(request_id=3, task_id="task-003")

    assert request.method == "tasks/get"
    assert request.params["id"] == "task-003"


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
    request = JsonRpcRequest(id=42, method="tasks/send", params={"id": "t1"})
    data = json.loads(request.model_dump_json())

    assert data["jsonrpc"] == "2.0"
    assert data["id"] == 42
    assert data["method"] == "tasks/send"


@pytest.mark.asyncio
async def test_sign_a2a_request_produces_signed_headers() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
    runtime_identity = await identity.create(
        CreateAgentParams(name="SignBot", core_model="gpt-4.1-mini", system_prompt="sign test")
    )

    request = build_task_send_request(
        request_id=1,
        task_id="task-sign-001",
        message={"role": "user", "parts": [{"type": "text", "text": "Test"}]},
    )

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

    # Body should be valid JSON-RPC
    body_data = json.loads(signed.body)
    assert body_data["method"] == "tasks/send"


@pytest.mark.asyncio
async def test_verify_a2a_request_uses_the_identity_client() -> None:
    """Verification goes through the identity's own client, not the process-wide default."""
    from unittest.mock import AsyncMock

    from agent_did_sdk import AgentDidClient

    from agent_did_a2a.jsonrpc import verify_a2a_request

    client = AgentDidClient()
    client.verify_http_request_signature = AsyncMock(return_value=True)  # type: ignore[method-assign]
    identity = AgentIdentity(
        AgentIdentityConfig(signer_address="0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", client=client)
    )

    assert await verify_a2a_request(
        agent_identity=identity, method="POST", url="https://example.com/a2a", headers={}, body="{}"
    )
    client.verify_http_request_signature.assert_awaited_once()
