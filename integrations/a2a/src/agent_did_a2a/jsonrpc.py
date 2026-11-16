"""A2A 1.0 JSON-RPC binding (§9) and DID-based signing of A2A requests.

This module provides:
  - Pydantic models for JSON-RPC 2.0 envelopes and the A2A 1.0 objects a client sends and reads (``Message``,
    ``Part``, ``Task``), with the A2A JSON names (lowerCamelCase, ``ROLE_USER``, ``TASK_STATE_COMPLETED``)
  - Builders for ``SendMessage`` and ``GetTask``
  - Signing of outgoing requests with Agent-DID HTTP Message Signatures, with the ``A2A-Version`` and
    ``A2A-Extensions`` service parameters (§9.2)
  - Verification of incoming signed requests
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal

from agent_did_sdk import (
    AGENT_DID_A2A_EXTENSION_URI,
    AgentIdentity,
    HttpTargetValidationOptions,
    SignHttpRequestParams,
    VerifyHttpRequestSignatureParams,
    validate_http_target,
)
from agent_did_sdk.core.types import (
    VerifyHttpRequestSignatureResult,
    VerifyIdentityCompositionParams,
    VerifyIdentityCompositionResult,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.alias_generators import to_camel

from .agent_card import A2A_PROTOCOL_VERSION
from .snapshot import RuntimeIdentity, get_active_signing_key_id, runtime_signing_params

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
    id: str | int | None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class JsonRpcError(BaseModel):
    """JSON-RPC 2.0 error object."""

    model_config = ConfigDict(extra="forbid")

    code: int
    message: str
    data: Any | None = None


# --- A2A 1.0 objects ---


class _A2AObject(BaseModel):
    """A2A 1.0 JSON: lowerCamelCase names; members a newer A2A version adds are kept (§5.7: ignore unrecognized)."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="allow")

    def to_json(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, exclude_none=True)


class A2APart(_A2AObject):
    """A ``Part``: exactly one of ``text``, ``raw`` (base64), ``url`` or ``data``."""

    text: str | None = None
    raw: str | None = None
    url: str | None = None
    data: Any | None = None
    metadata: dict[str, Any] | None = None
    filename: str | None = None
    media_type: str | None = None

    @model_validator(mode="after")
    def _one_content(self) -> A2APart:
        if sum(value is not None for value in (self.text, self.raw, self.url, self.data)) != 1:
            raise ValueError("A Part has exactly one of text, raw, url or data")
        return self


class A2AMessage(_A2AObject):
    """A ``Message``."""

    message_id: str
    context_id: str | None = None
    task_id: str | None = None
    role: Literal["ROLE_USER", "ROLE_AGENT"]
    parts: list[A2APart] = Field(min_length=1)
    metadata: dict[str, Any] | None = None
    extensions: list[str] | None = None
    reference_task_ids: list[str] | None = None


class A2ATaskStatus(_A2AObject):
    """A ``TaskStatus``: ``state`` is a ``TaskState`` name such as ``TASK_STATE_COMPLETED``."""

    state: str
    message: A2AMessage | None = None
    timestamp: str | None = None


class A2ATask(_A2AObject):
    """A ``Task``."""

    id: str
    context_id: str | None = None
    status: A2ATaskStatus
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    history: list[A2AMessage] = Field(default_factory=list)
    metadata: dict[str, Any] | None = None


def text_message(
    text: str,
    *,
    role: Literal["ROLE_USER", "ROLE_AGENT"] = "ROLE_USER",
    message_id: str | None = None,
    context_id: str | None = None,
    task_id: str | None = None,
) -> A2AMessage:
    """A one-part text ``Message`` (a random ``messageId`` unless given)."""
    return A2AMessage(
        message_id=message_id or str(uuid.uuid4()),
        role=role,
        parts=[A2APart(text=text)],
        context_id=context_id,
        task_id=task_id,
    )


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
    http_security: HttpTargetValidationOptions | None = None,
    extensions: list[str] | None = None,
) -> SignedA2ARequest:
    """Sign an outgoing A2A JSON-RPC request using Agent-DID HTTP Signatures.

    Returns a ``SignedA2ARequest`` containing the target URL, HTTP method,
    signed headers (including ``Signature``, ``Signature-Input`` and ``Agent-DID``), the A2A service parameters
    ``A2A-Version: 1.0`` and ``A2A-Extensions`` (the Agent-DID extension, then *extensions*), and
    the serialized JSON body. The target must pass the SDK's HTTP target policy;
    ``http_security=HttpTargetValidationOptions(allow_private_targets=True)`` allows
    non-global targets (development only).
    """

    validate_http_target(target_url, http_security)

    body = jsonrpc_request.model_dump_json()
    agent_did = runtime_identity.document.id
    key_id = get_active_signing_key_id(runtime_identity)
    if key_id is None:
        raise ValueError("The runtime identity has no active assertionMethod key to sign with")

    signed_headers = await agent_identity.sign_http_request(
        SignHttpRequestParams(
            method="POST",
            url=target_url,
            body=body,
            agent_did=agent_did,
            **runtime_signing_params(runtime_identity),
            verification_method_id=key_id,
            http_security=http_security,
        )
    )

    activated = list(dict.fromkeys([AGENT_DID_A2A_EXTENSION_URI, *(extensions or [])]))
    merged_headers = {
        "content-type": "application/json",
        "a2a-version": A2A_PROTOCOL_VERSION,
        "a2a-extensions": ",".join(activated),
        **signed_headers,
    }

    return SignedA2ARequest(
        url=target_url,
        method="POST",
        headers=merged_headers,
        body=body,
    )


async def verify_a2a_request_detailed(
    *,
    agent_identity: AgentIdentity,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None = None,
    allowed_dids: list[str] | None = None,
    allowed_controllers: list[str] | None = None,
) -> VerifyHttpRequestSignatureResult:
    """Verify an incoming A2A request's HTTP Signature using Agent-DID and say who signed it.

    An accepted result carries ``did`` (the sender), ``key_id`` and ``controllers`` (its controller chain). A valid
    signature only proves which DID signed: pass ``allowed_dids`` and/or ``allowed_controllers`` to accept only the
    senders you trust, or check ``result.did`` yourself. A rejection carries ``reason``.
    """

    try:
        return await agent_identity.client.verify_http_request_signature_detailed(
            VerifyHttpRequestSignatureParams(
                method=method,
                url=url,
                headers=headers,
                body=body,
                allowed_dids=allowed_dids,
                allowed_controllers=allowed_controllers,
            )
        )
    except Exception:
        return VerifyHttpRequestSignatureResult(ok=False, reason="malformed_headers")


async def verify_a2a_request_composition(
    *,
    agent_identity: AgentIdentity,
    method: str,
    url: str,
    headers: dict[str, str],
    agent_card: object,
    body: str | None = None,
    allowed_dids: list[str] | None = None,
    allowed_controllers: list[str] | None = None,
) -> VerifyIdentityCompositionResult:
    """Verify an incoming A2A request against the sender's signed Agent Card (composition contract §2): the card's
    signatures, the request's HTTP Signature, and that the request's ``keyid`` is a key the card publishes. A rejection
    carries the contract ``reason`` (``rotation_window_closed``, ``emergency_revoked``, ``key_purpose_violation``,
    ``tampered``, ``card_keyid_mismatch``, ``format_drift``...) and ``stage``."""

    try:
        return await agent_identity.client.verify_identity_composition(
            VerifyIdentityCompositionParams(
                method=method,
                url=url,
                headers=headers,
                body=body,
                allowed_dids=allowed_dids,
                allowed_controllers=allowed_controllers,
                agent_card=agent_card,
            )
        )
    except Exception:
        return VerifyIdentityCompositionResult(ok=False, stage="request", reason="request_rejected")


async def verify_a2a_request(
    *,
    agent_identity: AgentIdentity,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None = None,
    allowed_dids: list[str] | None = None,
    allowed_controllers: list[str] | None = None,
) -> bool:
    """Verify an incoming A2A request's HTTP Signature using Agent-DID.

    Returns ``True`` if the signature is valid (and the sender passes ``allowed_dids`` / ``allowed_controllers``
    when given), ``False`` otherwise. Without those lists any DID with a valid key passes: use
    :func:`verify_a2a_request_detailed` to learn who signed.
    """

    result = await verify_a2a_request_detailed(
        agent_identity=agent_identity,
        method=method,
        url=url,
        headers=headers,
        body=body,
        allowed_dids=allowed_dids,
        allowed_controllers=allowed_controllers,
    )
    return result.ok


def build_send_message_request(
    *,
    request_id: str | int,
    message: A2AMessage,
    configuration: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    tenant: str | None = None,
) -> JsonRpcRequest:
    """Build a ``SendMessage`` request (A2A 1.0 §9.4.1); *configuration* is a ``SendMessageConfiguration`` as JSON."""

    params: dict[str, Any] = {"message": message.to_json()}
    if tenant:
        params["tenant"] = tenant
    if configuration is not None:
        params["configuration"] = configuration
    if metadata is not None:
        params["metadata"] = metadata
    return JsonRpcRequest(id=request_id, method="SendMessage", params=params)


def build_get_task_request(
    *,
    request_id: str | int,
    task_id: str,
    history_length: int | None = None,
    tenant: str | None = None,
) -> JsonRpcRequest:
    """Build a ``GetTask`` request (A2A 1.0 §9.4.3)."""

    params: dict[str, Any] = {"id": task_id}
    if tenant:
        params["tenant"] = tenant
    if history_length is not None:
        params["historyLength"] = history_length
    return JsonRpcRequest(id=request_id, method="GetTask", params=params)


def parse_jsonrpc_response(raw: str | bytes | dict[str, Any]) -> JsonRpcResponse:
    """Parse a JSON-RPC response from raw input."""

    if isinstance(raw, (str, bytes)):
        data: dict[str, Any] = json.loads(raw)
    else:
        data = raw

    return JsonRpcResponse(**data)


def parse_send_message_result(result: dict[str, Any]) -> A2ATask | A2AMessage:
    """The ``SendMessageResponse`` of a ``SendMessage`` result: a ``Task`` or a ``Message``."""

    if "task" in result and "message" not in result:
        return A2ATask.model_validate(result["task"])
    if "message" in result and "task" not in result:
        return A2AMessage.model_validate(result["message"])
    raise ValueError("A SendMessage result has exactly one of task or message")
