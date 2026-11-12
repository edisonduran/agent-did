"""Public integration assembly for Agent-DID and Google A2A protocol."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agent_did_sdk import AgentIdentity

from .agent_card import A2AAgentCard, A2ASkill, agent_card_to_json, build_agent_card
from .config import AgentDidA2AConfig, AgentDidA2AExposureConfig
from .context import build_agent_did_a2a_context
from .jsonrpc import (
    JsonRpcRequest,
    SignedA2ARequest,
    build_task_get_request,
    build_task_send_request,
    sign_a2a_request,
    verify_a2a_request,
)
from .observability import AgentDidA2AEventHandler, AgentDidObserver, create_json_logger_event_handler
from .snapshot import (
    AgentDidIdentitySnapshot,
    RuntimeIdentity,
    RuntimeIdentityHandle,
    build_agent_did_identity_snapshot,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AgentDidA2AIntegration:
    """Ready-to-use integration bundle for A2A agent-to-agent communication."""

    agent_identity: AgentIdentity
    runtime_identity_handle: RuntimeIdentityHandle
    config: AgentDidA2AConfig
    observer: AgentDidObserver

    @property
    def runtime_identity(self) -> RuntimeIdentity:
        return self.runtime_identity_handle.value

    @property
    def identity_snapshot(self) -> AgentDidIdentitySnapshot:
        return build_agent_did_identity_snapshot(self.runtime_identity)

    def _capture_identity_snapshot(self, reason: str) -> AgentDidIdentitySnapshot:
        snapshot = self.identity_snapshot
        self.observer.emit(
            "agent_did.a2a.identity_snapshot.refreshed",
            attributes={
                "did": snapshot.did,
                "authentication_key_id": snapshot.authentication_key_id,
                "reason": reason,
            },
        )
        return snapshot

    def get_current_identity(self) -> dict[str, Any]:
        """Return the current identity as a serializable dict."""
        return self._capture_identity_snapshot("get_current_identity").model_dump(exclude_none=True)

    def build_agent_card(
        self,
        *,
        agent_url: str,
        skills: list[A2ASkill] | None = None,
        capabilities: dict[str, bool] | None = None,
        verification_endpoint: str | None = None,
    ) -> A2AAgentCard:
        """Build an A2A AgentCard enriched with this agent's DID identity."""

        snapshot = self._capture_identity_snapshot("build_agent_card")
        self.observer.emit(
            "agent_did.a2a.agent_card.built",
            attributes={"did": snapshot.did, "url": agent_url},
        )
        return build_agent_card(
            identity_snapshot=snapshot,
            agent_url=agent_url,
            skills=skills,
            capabilities=capabilities,
            config=self.config,
            verification_endpoint=verification_endpoint,
        )

    def agent_card_json(
        self,
        *,
        agent_url: str,
        skills: list[A2ASkill] | None = None,
        capabilities: dict[str, bool] | None = None,
        verification_endpoint: str | None = None,
    ) -> dict[str, Any]:
        """Build and serialize an AgentCard to JSON-compatible dict."""
        card = self.build_agent_card(
            agent_url=agent_url,
            skills=skills,
            capabilities=capabilities,
            verification_endpoint=verification_endpoint,
        )
        return agent_card_to_json(card)

    async def sign_request(
        self,
        *,
        target_url: str,
        jsonrpc_request: JsonRpcRequest,
    ) -> SignedA2ARequest:
        """Sign an outgoing A2A JSON-RPC request with HTTP Signatures."""

        self.observer.emit(
            "agent_did.a2a.request.signing",
            attributes={
                "method": jsonrpc_request.method,
                "url": target_url,
                "request_id": str(jsonrpc_request.id),
            },
        )

        signed = await sign_a2a_request(
            agent_identity=self.agent_identity,
            runtime_identity=self.runtime_identity,
            target_url=target_url,
            jsonrpc_request=jsonrpc_request,
        )

        self.observer.emit(
            "agent_did.a2a.request.signed",
            attributes={
                "method": jsonrpc_request.method,
                "url": target_url,
                "request_id": str(jsonrpc_request.id),
            },
        )

        return signed

    async def verify_request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str | None = None,
        allowed_dids: list[str] | None = None,
        allowed_controllers: list[str] | None = None,
    ) -> bool:
        """Verify an incoming A2A request's HTTP Signature.

        Without ``allowed_dids`` / ``allowed_controllers`` any sender with a valid key passes; see
        :func:`verify_a2a_request_detailed` to learn who signed."""

        self.observer.emit(
            "agent_did.a2a.request.verifying",
            attributes={"url": url, "http_method": method},
        )

        is_valid = await verify_a2a_request(
            agent_identity=self.agent_identity,
            method=method,
            url=url,
            headers=headers,
            body=body,
            allowed_dids=allowed_dids,
            allowed_controllers=allowed_controllers,
        )

        self.observer.emit(
            "agent_did.a2a.request.verified",
            attributes={"url": url, "is_valid": is_valid},
        )

        return is_valid

    async def send_task(
        self,
        *,
        target_url: str,
        request_id: str | int,
        task_id: str,
        message: dict[str, Any],
        session_id: str | None = None,
    ) -> SignedA2ARequest:
        """Build and sign a ``tasks/send`` request."""

        request = build_task_send_request(
            request_id=request_id,
            task_id=task_id,
            message=message,
            session_id=session_id,
        )
        return await self.sign_request(target_url=target_url, jsonrpc_request=request)

    async def get_task(
        self,
        *,
        target_url: str,
        request_id: str | int,
        task_id: str,
    ) -> SignedA2ARequest:
        """Build and sign a ``tasks/get`` request."""

        request = build_task_get_request(request_id=request_id, task_id=task_id)
        return await self.sign_request(target_url=target_url, jsonrpc_request=request)

    def get_a2a_context(self) -> str:
        """Return a human-readable identity context block for A2A sessions."""
        snapshot = self._capture_identity_snapshot("get_a2a_context")
        return build_agent_did_a2a_context(snapshot)


def create_agent_did_a2a_integration(
    *,
    agent_identity: AgentIdentity,
    runtime_identity: RuntimeIdentity,
    config: AgentDidA2AConfig | None = None,
    expose: dict[str, bool] | None = None,
    event_handler: AgentDidA2AEventHandler | None = None,
) -> AgentDidA2AIntegration:
    """Public factory for the Agent-DID A2A integration.

    Parameters
    ----------
    agent_identity:
        An ``AgentIdentity`` instance with a configured registry and signer.
    runtime_identity:
        The result of ``agent_identity.create()`` or ``agent_identity.rotate_verification_method()``.
    config:
        Optional top-level configuration.  Overrides are merged from *expose*.
    expose:
        Convenience dict that overrides individual ``AgentDidA2AExposureConfig`` fields.
    event_handler:
        Optional observability event handler.  Defaults to a JSON logger.
    """

    effective_config = config or AgentDidA2AConfig()
    if expose:
        effective_config.expose = AgentDidA2AExposureConfig(**{
            **effective_config.expose.model_dump(),
            **expose,
        })

    handler = event_handler or create_json_logger_event_handler()
    observer = AgentDidObserver(handler=handler)

    observer.emit(
        "agent_did.a2a.integration.created",
        attributes={
            "did": runtime_identity.document.id,
            "expose": effective_config.expose.model_dump(),
        },
    )

    return AgentDidA2AIntegration(
        agent_identity=agent_identity,
        runtime_identity_handle=RuntimeIdentityHandle(value=runtime_identity),
        config=effective_config,
        observer=observer,
    )
