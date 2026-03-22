"""CrewAI-compatible Agent-DID tool construction."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse

from agent_did_sdk import AgentIdentity, SignHttpRequestParams
from pydantic import BaseModel, ConfigDict, Field

from .config import AgentDidExposureConfig
from .observability import AgentDidObserver
from .snapshot import (
    RuntimeIdentity,
    RuntimeIdentityHandle,
    build_agent_did_identity_snapshot,
    get_active_authentication_key_id,
)

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


RunnerResult = dict[str, Any] | Awaitable[dict[str, Any]]
Runner = Callable[..., RunnerResult]


async def _await_runner_result(result: Awaitable[dict[str, Any]]) -> dict[str, Any]:
    return await result


@dataclass(slots=True)
class _ToolRuntimeContext:
    agent_identity: AgentIdentity
    runtime_identity_handle: RuntimeIdentityHandle
    allow_private_network_targets: bool
    observer: AgentDidObserver

    @property
    def runtime_identity(self) -> RuntimeIdentity:
        return self.runtime_identity_handle.value

    @runtime_identity.setter
    def runtime_identity(self, value: RuntimeIdentity) -> None:
        self.runtime_identity_handle.value = value

    @property
    def current_did(self) -> str:
        return self.runtime_identity_handle.value.document.id


@dataclass(slots=True)
class CrewAITool:
    """Minimal dependency-free tool wrapper with a CrewAI-friendly shape."""

    name: str
    description: str
    args_schema: type[BaseModel]
    runner: Runner

    def invoke(self, inputs: dict[str, Any] | None = None) -> dict[str, Any]:
        validated = self.args_schema.model_validate(inputs or {})
        result = self.runner(**validated.model_dump(exclude_none=True))
        if inspect.isawaitable(result):
            return _run_awaitable(result)
        return result

    async def ainvoke(self, inputs: dict[str, Any] | None = None) -> dict[str, Any]:
        validated = self.args_schema.model_validate(inputs or {})
        result = self.runner(**validated.model_dump(exclude_none=True))
        if inspect.isawaitable(result):
            return await result
        return result

    def run(self, **kwargs: Any) -> dict[str, Any]:
        return self.invoke(kwargs)

    async def arun(self, **kwargs: Any) -> dict[str, Any]:
        return await self.ainvoke(kwargs)


def _run_awaitable(result: Awaitable[dict[str, Any]]) -> dict[str, Any]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_await_runner_result(result))
    raise RuntimeError("Use 'ainvoke' or 'arun' when calling CrewAI tools from an active event loop")


def _with_prefix(prefix: str, name: str) -> str:
    return f"{prefix}_{name}"


def _build_tool(
    *,
    enabled: bool,
    tool_prefix: str,
    name: str,
    description: str,
    args_schema: type[BaseModel],
    runner: Runner,
) -> CrewAITool | None:
    if not enabled:
        return None

    return CrewAITool(
        name=_with_prefix(tool_prefix, name),
        description=description,
        args_schema=args_schema,
        runner=runner,
    )


def _structured_error(error: Exception) -> dict[str, str]:
    return {"error": str(error)}


def _emit_tool_started(context: _ToolRuntimeContext, *, tool_name: str, inputs: dict[str, Any] | None = None) -> None:
    context.observer.emit(
        "agent_did.tool.started",
        attributes={
            "tool_name": tool_name,
            "did": context.current_did,
            "inputs": inputs or {},
        },
    )


def _emit_tool_succeeded(
    context: _ToolRuntimeContext,
    *,
    tool_name: str,
    outputs: dict[str, Any] | None = None,
) -> None:
    context.observer.emit(
        "agent_did.tool.succeeded",
        attributes={
            "tool_name": tool_name,
            "did": context.current_did,
            "outputs": outputs or {},
        },
    )


def _emit_tool_failed(
    context: _ToolRuntimeContext,
    *,
    tool_name: str,
    error: Exception,
    inputs: dict[str, Any] | None = None,
) -> None:
    context.observer.emit(
        "agent_did.tool.failed",
        level="error",
        attributes={
            "tool_name": tool_name,
            "did": context.current_did,
            "inputs": inputs or {},
            "error": str(error),
        },
    )


def _emit_identity_snapshot_refreshed(context: _ToolRuntimeContext, *, reason: str) -> None:
    snapshot = build_agent_did_identity_snapshot(context.runtime_identity)
    context.observer.emit(
        "agent_did.identity_snapshot.refreshed",
        attributes={
            "did": snapshot.did,
            "authentication_key_id": snapshot.authentication_key_id,
            "reason": reason,
        },
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


def _create_current_identity_runner(context: _ToolRuntimeContext, tool_name: str) -> Runner:
    def get_current_identity() -> dict[str, Any]:
        _emit_tool_started(context, tool_name=tool_name)
        try:
            snapshot = build_agent_did_identity_snapshot(context.runtime_identity)
            _emit_identity_snapshot_refreshed(context, reason="tool:get_current_identity")
            _emit_tool_succeeded(
                context,
                tool_name=tool_name,
                outputs={"authentication_key_id": snapshot.authentication_key_id},
            )
            return snapshot.model_dump(exclude_none=True)
        except Exception as error:
            _emit_tool_failed(context, tool_name=tool_name, error=error)
            return _structured_error(error)

    return get_current_identity


def _create_resolve_did_runner(context: _ToolRuntimeContext, tool_name: str) -> Runner:
    async def resolve_did(did: str | None = None) -> dict[str, Any]:
        _emit_tool_started(context, tool_name=tool_name, inputs={"did": did})
        try:
            target_did = did.strip() if did and did.strip() else context.current_did
            document = await AgentIdentity.resolve(target_did)
            _emit_tool_succeeded(context, tool_name=tool_name, outputs={"resolved_did": document.id})
            return document.model_dump(by_alias=True, exclude_none=True)
        except Exception as error:
            _emit_tool_failed(context, tool_name=tool_name, error=error, inputs={"did": did})
            return _structured_error(error)

    return resolve_did


def _create_verify_signature_runner(context: _ToolRuntimeContext, tool_name: str) -> Runner:
    async def verify_signature(
        payload: str,
        signature: str,
        did: str | None = None,
        key_id: str | None = None,
    ) -> dict[str, Any]:
        inputs = {"did": did, "key_id": key_id, "payload": payload, "signature": signature}
        _emit_tool_started(context, tool_name=tool_name, inputs=inputs)
        try:
            target_did = did.strip() if did and did.strip() else context.current_did
            is_valid = await AgentIdentity.verify_signature(target_did, payload, signature, key_id)
            result: dict[str, Any] = {"did": target_did, "is_valid": is_valid}
            if key_id:
                result["key_id"] = key_id
            _emit_tool_succeeded(
                context,
                tool_name=tool_name,
                outputs={"target_did": target_did, "is_valid": is_valid, "key_id": key_id},
            )
            return result
        except Exception as error:
            _emit_tool_failed(context, tool_name=tool_name, error=error, inputs=inputs)
            return _structured_error(error)

    return verify_signature


def _create_sign_payload_runner(context: _ToolRuntimeContext, tool_name: str) -> Runner:
    async def sign_payload(payload: str) -> dict[str, Any]:
        _emit_tool_started(context, tool_name=tool_name, inputs={"payload": payload})
        try:
            signature = await context.agent_identity.sign_message(payload, context.runtime_identity.agent_private_key)
            key_id = get_active_authentication_key_id(context.runtime_identity)
            _emit_tool_succeeded(
                context,
                tool_name=tool_name,
                outputs={"key_id": key_id, "signature_generated": True},
            )
            return {
                "did": context.current_did,
                "key_id": key_id,
                "payload": payload,
                "signature": signature,
            }
        except Exception as error:
            _emit_tool_failed(context, tool_name=tool_name, error=error, inputs={"payload": payload})
            return _structured_error(error)

    return sign_payload


def _create_sign_http_request_runner(context: _ToolRuntimeContext, tool_name: str) -> Runner:
    async def sign_http_request(method: str, url: str, body: str | None = None) -> dict[str, Any]:
        inputs = {"method": method, "url": url, "body": body}
        _emit_tool_started(context, tool_name=tool_name, inputs=inputs)
        try:
            _validate_http_target(url, context.allow_private_network_targets)
            headers = await context.agent_identity.sign_http_request(
                SignHttpRequestParams(
                    method=method,
                    url=url,
                    body=body,
                    agent_did=context.current_did,
                    agent_private_key=context.runtime_identity.agent_private_key,
                    verification_method_id=get_active_authentication_key_id(context.runtime_identity),
                )
            )
            _emit_tool_succeeded(
                context,
                tool_name=tool_name,
                outputs={
                    "key_id": get_active_authentication_key_id(context.runtime_identity),
                    "method": method,
                    "url": url,
                    "header_names": sorted(headers.keys()),
                },
            )
            return {"did": context.current_did, "headers": headers}
        except Exception as error:
            _emit_tool_failed(context, tool_name=tool_name, error=error, inputs=inputs)
            return _structured_error(error)

    return sign_http_request


def _create_document_history_runner(context: _ToolRuntimeContext, tool_name: str) -> Runner:
    def get_document_history(did: str | None = None) -> dict[str, Any]:
        _emit_tool_started(context, tool_name=tool_name, inputs={"did": did})
        try:
            target_did = did.strip() if did and did.strip() else context.current_did
            entries = AgentIdentity.get_document_history(target_did)
            _emit_tool_succeeded(
                context,
                tool_name=tool_name,
                outputs={"target_did": target_did, "entry_count": len(entries)},
            )
            return {
                "did": target_did,
                "entries": [entry.model_dump(by_alias=True, exclude_none=True) for entry in entries],
            }
        except Exception as error:
            _emit_tool_failed(context, tool_name=tool_name, error=error, inputs={"did": did})
            return _structured_error(error)

    return get_document_history


def _create_rotate_key_runner(context: _ToolRuntimeContext, tool_name: str) -> Runner:
    async def rotate_key() -> dict[str, Any]:
        _emit_tool_started(context, tool_name=tool_name)
        try:
            context.runtime_identity = await AgentIdentity.rotate_verification_method(context.current_did)
            _emit_identity_snapshot_refreshed(context, reason="tool:rotate_key")
            _emit_tool_succeeded(
                context,
                tool_name=tool_name,
                outputs={"verification_method_id": context.runtime_identity.verification_method_id},
            )
            return {
                "did": context.runtime_identity.document.id,
                "verification_method_id": context.runtime_identity.verification_method_id,
            }
        except Exception as error:
            _emit_tool_failed(context, tool_name=tool_name, error=error)
            return _structured_error(error)

    return rotate_key


def create_agent_did_tools(
    *,
    agent_identity: AgentIdentity,
    runtime_identity_handle: RuntimeIdentityHandle,
    expose: AgentDidExposureConfig,
    tool_prefix: str,
    allow_private_network_targets: bool,
    observer: AgentDidObserver,
) -> list[CrewAITool]:
    context = _ToolRuntimeContext(
        agent_identity=agent_identity,
        runtime_identity_handle=runtime_identity_handle,
        allow_private_network_targets=allow_private_network_targets,
        observer=observer,
    )

    tool_specs = [
        _build_tool(
            enabled=expose.current_identity,
            tool_prefix=tool_prefix,
            name="get_current_identity",
            description="Return the current Agent-DID identity attached to this CrewAI runtime.",
            args_schema=EmptyArgs,
            runner=_create_current_identity_runner(context, _with_prefix(tool_prefix, "get_current_identity")),
        ),
        _build_tool(
            enabled=expose.resolve_did,
            tool_prefix=tool_prefix,
            name="resolve_did",
            description="Resolve an Agent-DID document. If no DID is provided, resolves the current agent DID.",
            args_schema=ResolveDidArgs,
            runner=_create_resolve_did_runner(context, _with_prefix(tool_prefix, "resolve_did")),
        ),
        _build_tool(
            enabled=expose.verify_signatures,
            tool_prefix=tool_prefix,
            name="verify_signature",
            description="Verify an Agent-DID signature against the active authentication key set.",
            args_schema=VerifySignatureArgs,
            runner=_create_verify_signature_runner(context, _with_prefix(tool_prefix, "verify_signature")),
        ),
        _build_tool(
            enabled=expose.sign_payload,
            tool_prefix=tool_prefix,
            name="sign_payload",
            description="Sign a payload with the current agent verification key without exposing the private key.",
            args_schema=SignPayloadArgs,
            runner=_create_sign_payload_runner(context, _with_prefix(tool_prefix, "sign_payload")),
        ),
        _build_tool(
            enabled=expose.sign_http,
            tool_prefix=tool_prefix,
            name="sign_http_request",
            description="Sign an outbound HTTP request with Agent-DID headers when the host explicitly enables it.",
            args_schema=SignHttpRequestArgs,
            runner=_create_sign_http_request_runner(context, _with_prefix(tool_prefix, "sign_http_request")),
        ),
        _build_tool(
            enabled=expose.document_history,
            tool_prefix=tool_prefix,
            name="get_document_history",
            description="Return Agent-DID document history entries for the current DID or a target DID.",
            args_schema=DocumentHistoryArgs,
            runner=_create_document_history_runner(context, _with_prefix(tool_prefix, "get_document_history")),
        ),
        _build_tool(
            enabled=expose.rotate_keys,
            tool_prefix=tool_prefix,
            name="rotate_key",
            description=(
                "Rotate the active verification method. Disabled by default "
                "and intended for administrative flows."
            ),
            args_schema=RotateKeysArgs,
            runner=_create_rotate_key_runner(context, _with_prefix(tool_prefix, "rotate_key")),
        ),
    ]

    return [tool for tool in tool_specs if tool is not None]
