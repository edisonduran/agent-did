"""LangChain tool construction for Agent-DID operations."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any, Protocol
from urllib.parse import urlparse

from agent_did_sdk import AgentIdentity, SignHttpRequestParams
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from .config import AgentDidExposureConfig
from .observability import AgentDidObserver
from .snapshot import RuntimeIdentity, build_agent_did_identity_snapshot, get_active_authentication_key_id

MAX_PAYLOAD_BYTES = 1_048_576


class EmptyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResolveDidArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    did: str | None = None


class VerifySignatureArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    did: str | None = None
    payload: str = Field(max_length=MAX_PAYLOAD_BYTES)
    signature: str = Field(max_length=256)
    key_id: str | None = Field(default=None, max_length=512)


class SignPayloadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: str = Field(max_length=MAX_PAYLOAD_BYTES)


class SignHttpRequestArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: str = Field(max_length=16)
    url: str = Field(max_length=2048)
    body: str | None = Field(default=None, max_length=MAX_PAYLOAD_BYTES)


class DocumentHistoryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    did: str | None = None


class RotateKeysArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SupportsModelDump(Protocol):
    def model_dump(self, *, by_alias: bool = False, exclude_none: bool = False) -> dict[str, Any]: ...


def _with_prefix(prefix: str, name: str) -> str:
    return f"{prefix}_{name}"


def _serialize_document(document: SupportsModelDump) -> dict[str, Any]:
    return document.model_dump(by_alias=True, exclude_none=True)


def _serialize_snapshot(runtime_identity: RuntimeIdentity) -> dict[str, Any]:
    return build_agent_did_identity_snapshot(runtime_identity).model_dump(exclude_none=True)


def _structured_error(error: Exception) -> dict[str, str]:
    return {"error": str(error)}


def _emit_tool_started(
    observer: AgentDidObserver,
    *,
    tool_name: str,
    did: str,
    inputs: dict[str, Any] | None = None,
) -> None:
    observer.emit(
        "agent_did.tool.started",
        attributes={
            "tool_name": tool_name,
            "did": did,
            "inputs": inputs or {},
        },
    )


def _emit_tool_succeeded(
    observer: AgentDidObserver,
    *,
    tool_name: str,
    did: str,
    outputs: dict[str, Any] | None = None,
) -> None:
    observer.emit(
        "agent_did.tool.succeeded",
        attributes={
            "tool_name": tool_name,
            "did": did,
            "outputs": outputs or {},
        },
    )


def _emit_tool_failed(
    observer: AgentDidObserver,
    *,
    tool_name: str,
    did: str,
    error: Exception,
    inputs: dict[str, Any] | None = None,
) -> None:
    observer.emit(
        "agent_did.tool.failed",
        attributes={
            "tool_name": tool_name,
            "did": did,
            "inputs": inputs or {},
            "error": str(error),
        },
        level="error",
    )


def _validate_http_target(url: str, allow_private_network_targets: bool) -> None:
    parsed_url = urlparse(url)
    if parsed_url.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are allowed")
    if parsed_url.username or parsed_url.password:
        raise ValueError("URLs with embedded credentials are not allowed")

    hostname = parsed_url.hostname
    if not hostname:
        raise ValueError("An absolute URL with hostname is required")

    normalized_hostname = hostname.lower()
    if not allow_private_network_targets:
        if normalized_hostname == "localhost" or normalized_hostname.endswith(".localhost"):
            raise ValueError("Private or loopback HTTP targets are not allowed by default")

        try:
            parsed_ip = ip_address(normalized_hostname)
        except ValueError:
            return

        if (
            parsed_ip.is_private
            or parsed_ip.is_loopback
            or parsed_ip.is_link_local
            or parsed_ip.is_multicast
            or parsed_ip.is_reserved
            or parsed_ip.is_unspecified
        ):
            raise ValueError("Private or loopback HTTP targets are not allowed by default")


def _build_get_current_identity_tool(
    runtime_identity: RuntimeIdentity,
    tool_prefix: str,
    observer: AgentDidObserver,
) -> StructuredTool:
    tool_name = _with_prefix(tool_prefix, "get_current_identity")

    def get_current_identity() -> dict[str, Any]:
        current_did = runtime_identity.document.id
        _emit_tool_started(observer, tool_name=tool_name, did=current_did)
        try:
            snapshot = _serialize_snapshot(runtime_identity)
            _emit_tool_succeeded(
                observer,
                tool_name=tool_name,
                did=current_did,
                outputs={
                    "authentication_key_id": snapshot.get("authentication_key_id"),
                },
            )
            return snapshot
        except Exception as error:  # pragma: no cover - defensive boundary
            _emit_tool_failed(observer, tool_name=tool_name, did=current_did, error=error)
            return _structured_error(error)

    return StructuredTool.from_function(
        func=get_current_identity,
        name=tool_name,
        description="Return the current Agent-DID identity attached to this LangChain agent.",
        args_schema=EmptyArgs,
    )


def _build_resolve_did_tool(
    runtime_identity: RuntimeIdentity,
    tool_prefix: str,
    observer: AgentDidObserver,
) -> StructuredTool:
    tool_name = _with_prefix(tool_prefix, "resolve_did")

    async def resolve_did(did: str | None = None) -> dict[str, Any]:
        current_did = runtime_identity.document.id
        _emit_tool_started(observer, tool_name=tool_name, did=current_did, inputs={"did": did})
        try:
            target_did = did.strip() if did and did.strip() else runtime_identity.document.id
            document = await AgentIdentity.resolve(target_did)
            result = _serialize_document(document)
            _emit_tool_succeeded(
                observer,
                tool_name=tool_name,
                did=current_did,
                outputs={"resolved_did": result.get("id")},
            )
            return result
        except Exception as error:
            _emit_tool_failed(observer, tool_name=tool_name, did=current_did, error=error, inputs={"did": did})
            return _structured_error(error)

    return StructuredTool.from_function(
        coroutine=resolve_did,
        name=tool_name,
        description="Resolve an Agent-DID document. If no DID is provided, resolves the current agent DID.",
        args_schema=ResolveDidArgs,
    )


def _build_verify_signature_tool(
    runtime_identity: RuntimeIdentity,
    tool_prefix: str,
    observer: AgentDidObserver,
) -> StructuredTool:
    tool_name = _with_prefix(tool_prefix, "verify_signature")

    async def verify_signature(
        payload: str,
        signature: str,
        did: str | None = None,
        key_id: str | None = None,
    ) -> dict[str, Any]:
        current_did = runtime_identity.document.id
        _emit_tool_started(
            observer,
            tool_name=tool_name,
            did=current_did,
            inputs={
                "did": did,
                "key_id": key_id,
                "payload": payload,
                "signature": signature,
            },
        )
        try:
            target_did = did.strip() if did and did.strip() else runtime_identity.document.id
            is_valid = await AgentIdentity.verify_signature(target_did, payload, signature, key_id)
            result: dict[str, Any] = {"did": target_did, "is_valid": is_valid}
            if key_id:
                result["key_id"] = key_id
            _emit_tool_succeeded(
                observer,
                tool_name=tool_name,
                did=current_did,
                outputs={
                    "target_did": target_did,
                    "is_valid": is_valid,
                    "key_id": key_id,
                },
            )
            return result
        except Exception as error:
            _emit_tool_failed(
                observer,
                tool_name=tool_name,
                did=current_did,
                error=error,
                inputs={"did": did, "key_id": key_id, "payload": payload, "signature": signature},
            )
            return _structured_error(error)

    return StructuredTool.from_function(
        coroutine=verify_signature,
        name=tool_name,
        description="Verify an Agent-DID signature against a DID document and active verification methods.",
        args_schema=VerifySignatureArgs,
    )


def _build_sign_payload_tool(
    agent_identity: AgentIdentity,
    runtime_identity: RuntimeIdentity,
    tool_prefix: str,
    observer: AgentDidObserver,
) -> StructuredTool:
    tool_name = _with_prefix(tool_prefix, "sign_payload")

    async def sign_payload(payload: str) -> dict[str, Any]:
        current_did = runtime_identity.document.id
        _emit_tool_started(observer, tool_name=tool_name, did=current_did, inputs={"payload": payload})
        try:
            signature = await agent_identity.sign_message(payload, runtime_identity.agent_private_key)
            result = {
                "did": runtime_identity.document.id,
                "key_id": get_active_authentication_key_id(runtime_identity),
                "payload": payload,
                "signature": signature,
            }
            _emit_tool_succeeded(
                observer,
                tool_name=tool_name,
                did=current_did,
                outputs={
                    "key_id": result["key_id"],
                    "signature_generated": True,
                },
            )
            return result
        except Exception as error:
            _emit_tool_failed(
                observer,
                tool_name=tool_name,
                did=current_did,
                error=error,
                inputs={"payload": payload},
            )
            return _structured_error(error)

    return StructuredTool.from_function(
        coroutine=sign_payload,
        name=tool_name,
        description="Sign a payload with the current agent verification key without exposing the private key.",
        args_schema=SignPayloadArgs,
    )


def _build_sign_http_request_tool(
    agent_identity: AgentIdentity,
    runtime_identity: RuntimeIdentity,
    tool_prefix: str,
    allow_private_network_targets: bool,
    observer: AgentDidObserver,
) -> StructuredTool:
    tool_name = _with_prefix(tool_prefix, "sign_http_request")

    async def sign_http_request(method: str, url: str, body: str | None = None) -> dict[str, Any]:
        current_did = runtime_identity.document.id
        _emit_tool_started(
            observer,
            tool_name=tool_name,
            did=current_did,
            inputs={"method": method, "url": url, "body": body},
        )
        try:
            _validate_http_target(url, allow_private_network_targets)

            key_id = get_active_authentication_key_id(runtime_identity)
            http_sec = None
            if allow_private_network_targets:
                from agent_did_sdk.core.http_security import HttpTargetValidationOptions
                http_sec = HttpTargetValidationOptions(allow_private_targets=True)
            headers = await agent_identity.sign_http_request(
                SignHttpRequestParams(
                    method=method,
                    url=url,
                    body=body,
                    agent_private_key=runtime_identity.agent_private_key,
                    agent_did=runtime_identity.document.id,
                    verification_method_id=key_id,
                    http_security=http_sec,
                )
            )
            result = {
                "did": runtime_identity.document.id,
                "key_id": key_id,
                "method": method,
                "url": url,
                "headers": headers,
            }
            _emit_tool_succeeded(
                observer,
                tool_name=tool_name,
                did=current_did,
                outputs={
                    "key_id": key_id,
                    "method": method,
                    "url": url,
                    "header_names": sorted(headers.keys()),
                },
            )
            return result
        except Exception as error:
            _emit_tool_failed(
                observer,
                tool_name=tool_name,
                did=current_did,
                error=error,
                inputs={"method": method, "url": url, "body": body},
            )
            return _structured_error(error)

    return StructuredTool.from_function(
        coroutine=sign_http_request,
        name=tool_name,
        description="Create Agent-DID HTTP signature headers for an outbound request.",
        args_schema=SignHttpRequestArgs,
    )


def _build_rotate_keys_tool(
    runtime_identity: RuntimeIdentity,
    tool_prefix: str,
    observer: AgentDidObserver,
) -> StructuredTool:
    tool_name = _with_prefix(tool_prefix, "rotate_key")

    async def rotate_key() -> dict[str, Any]:
        current_did = runtime_identity.document.id
        _emit_tool_started(observer, tool_name=tool_name, did=current_did)
        try:
            rotated = await AgentIdentity.rotate_verification_method(runtime_identity.document.id)
            runtime_identity.document = rotated.document
            runtime_identity.agent_private_key = rotated.agent_private_key

            result = {
                "did": rotated.document.id,
                "verification_method_id": rotated.verification_method_id,
                "snapshot": _serialize_snapshot(runtime_identity),
            }
            _emit_tool_succeeded(
                observer,
                tool_name=tool_name,
                did=rotated.document.id,
                outputs={"verification_method_id": rotated.verification_method_id},
            )
            return result
        except Exception as error:
            _emit_tool_failed(observer, tool_name=tool_name, did=current_did, error=error)
            return _structured_error(error)

    return StructuredTool.from_function(
        coroutine=rotate_key,
        name=tool_name,
        description="Rotate the active Agent-DID verification method and update the attached runtime identity.",
        args_schema=RotateKeysArgs,
    )


def _build_document_history_tool(
    runtime_identity: RuntimeIdentity,
    tool_prefix: str,
    observer: AgentDidObserver,
) -> StructuredTool:
    tool_name = _with_prefix(tool_prefix, "get_document_history")

    def get_document_history(did: str | None = None) -> list[dict[str, Any]] | dict[str, str]:
        current_did = runtime_identity.document.id
        _emit_tool_started(observer, tool_name=tool_name, did=current_did, inputs={"did": did})
        try:
            target_did = did.strip() if did and did.strip() else runtime_identity.document.id
            history = AgentIdentity.get_document_history(target_did)
            result = [entry.model_dump(by_alias=True, exclude_none=True) for entry in history]
            _emit_tool_succeeded(
                observer,
                tool_name=tool_name,
                did=current_did,
                outputs={"target_did": target_did, "entry_count": len(result)},
            )
            return result
        except Exception as error:
            _emit_tool_failed(observer, tool_name=tool_name, did=current_did, error=error, inputs={"did": did})
            return _structured_error(error)

    return StructuredTool.from_function(
        func=get_document_history,
        name=tool_name,
        description="Return the revision history registered for an Agent-DID document.",
        args_schema=DocumentHistoryArgs,
    )


def create_agent_did_tools(
    *,
    agent_identity: AgentIdentity,
    runtime_identity: RuntimeIdentity,
    expose: AgentDidExposureConfig,
    tool_prefix: str = "agent_did",
    allow_private_network_targets: bool = False,
    observer: AgentDidObserver | None = None,
) -> list[StructuredTool]:
    active_observer = observer or AgentDidObserver()
    tool_builders: list[StructuredTool] = []

    if expose.current_identity:
        tool_builders.append(_build_get_current_identity_tool(runtime_identity, tool_prefix, active_observer))
    if expose.resolve_did:
        tool_builders.append(_build_resolve_did_tool(runtime_identity, tool_prefix, active_observer))
    if expose.verify_signatures:
        tool_builders.append(_build_verify_signature_tool(runtime_identity, tool_prefix, active_observer))
    if expose.sign_payload:
        tool_builders.append(_build_sign_payload_tool(agent_identity, runtime_identity, tool_prefix, active_observer))
    if expose.sign_http:
        tool_builders.append(
            _build_sign_http_request_tool(
                agent_identity,
                runtime_identity,
                tool_prefix,
                allow_private_network_targets,
                active_observer,
            )
        )
    if expose.document_history:
        tool_builders.append(_build_document_history_tool(runtime_identity, tool_prefix, active_observer))
    if expose.rotate_keys:
        tool_builders.append(_build_rotate_keys_tool(runtime_identity, tool_prefix, active_observer))

    return tool_builders
