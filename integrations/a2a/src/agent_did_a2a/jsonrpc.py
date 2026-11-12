"""JSON-RPC 2.0 message types and DID-based signing for A2A protocol messages.

A2A uses JSON-RPC 2.0 over HTTPS for task-oriented communication.
This module provides:
  - Pydantic models for JSON-RPC requests and responses
  - Signing of outgoing requests using Agent-DID HTTP Signatures
  - Verification of incoming signed requests
"""

from __future__ import annotations

import json
from typing import Any

from agent_did_sdk import AgentIdentity, SignHttpRequestParams, VerifyHttpRequestSignatureParams
from pydantic import BaseModel, ConfigDict, Field

from .snapshot import RuntimeIdentity, get_active_authentication_key_id

# --- JSON-RPC 2.0 Models ---


class JsonRpcRequest(BaseModel):
    """A2A JSON-RPC 2.0 request."""

    model_config = ConfigDict(extra="forbid")

    jsonrpc: str = "2.0"
    id: str | int
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class JsonRpcResponse(BaseModel):
    """A2A JSON-RPC 2.0 response."""

    model_config = ConfigDict(extra="forbid")

    jsonrpc: str = "2.0"
    id: str | int
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class JsonRpcError(BaseModel):
    """JSON-RPC 2.0 error object."""

    model_config = ConfigDict(extra="forbid")

    code: int
    message: str
    data: Any | None = None


# --- A2A Task Models ---


class A2ATaskSendParams(BaseModel):
    """Parameters for tasks/send method."""

    model_config = ConfigDict(extra="allow")

    id: str
    message: dict[str, Any]
    session_id: str | None = None
    history_length: int | None = None


class A2ATaskStatus(BaseModel):
    """A2A task status returned by the remote agent."""

    model_config = ConfigDict(extra="allow")

    id: str
    status: str
    message: dict[str, Any] | None = None
    artifacts: list[dict[str, Any]] = Field(default_factory=list)


# --- Signing / Verification ---


class SignedA2ARequest(BaseModel):
    """A signed A2A request ready for transmission."""

    model_config = ConfigDict(extra="forbid")

    url: str
    method: str
    headers: dict[str, str]
    body: str


async def sign_a2a_request(
    *,
    agent_identity: AgentIdentity,
    runtime_identity: RuntimeIdentity,
    target_url: str,
    jsonrpc_request: JsonRpcRequest,
) -> SignedA2ARequest:
    """Sign an outgoing A2A JSON-RPC request using Agent-DID HTTP Signatures.

    Returns a ``SignedA2ARequest`` containing the target URL, HTTP method,
    signed headers (including ``Signature`` and ``Signature-Input``), and
    the serialized JSON body.
    """

    body = jsonrpc_request.model_dump_json()
    agent_did = runtime_identity.document.id
    key_id = get_active_authentication_key_id(runtime_identity)
    if key_id is None:
        raise ValueError("The runtime identity has no active authentication key to sign with")

    signed_headers = await agent_identity.sign_http_request(
        SignHttpRequestParams(
            method="POST",
            url=target_url,
            body=body,
            agent_did=agent_did,
            agent_private_key=runtime_identity.agent_private_key,
            verification_method_id=key_id,
        )
    )

    # Merge the base content-type header with the signature headers
    merged_headers = {"content-type": "application/json", **signed_headers}

    return SignedA2ARequest(
        url=target_url,
        method="POST",
        headers=merged_headers,
        body=body,
    )


async def verify_a2a_request(
    *,
    agent_identity: AgentIdentity,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None = None,
) -> bool:
    """Verify an incoming A2A request's HTTP Signature using Agent-DID.

    Returns ``True`` if the signature is valid, ``False`` otherwise.
    """

    try:
        return await agent_identity.client.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method=method,
                url=url,
                headers=headers,
                body=body,
            )
        )
    except Exception:
        return False


def build_task_send_request(
    *,
    request_id: str | int,
    task_id: str,
    message: dict[str, Any],
    session_id: str | None = None,
) -> JsonRpcRequest:
    """Build a ``tasks/send`` JSON-RPC request."""

    params: dict[str, Any] = {
        "id": task_id,
        "message": message,
    }
    if session_id is not None:
        params["sessionId"] = session_id

    return JsonRpcRequest(
        id=request_id,
        method="tasks/send",
        params=params,
    )


def build_task_get_request(*, request_id: str | int, task_id: str) -> JsonRpcRequest:
    """Build a ``tasks/get`` JSON-RPC request."""

    return JsonRpcRequest(
        id=request_id,
        method="tasks/get",
        params={"id": task_id},
    )


def parse_jsonrpc_response(raw: str | bytes | dict[str, Any]) -> JsonRpcResponse:
    """Parse a JSON-RPC response from raw input."""

    if isinstance(raw, (str, bytes)):
        data: dict[str, Any] = json.loads(raw)
    else:
        data = raw

    return JsonRpcResponse(**data)
