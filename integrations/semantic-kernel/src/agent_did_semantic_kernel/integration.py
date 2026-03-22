"""Public integration assembly for Agent-DID and Semantic Kernel."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agent_did_sdk import AgentDIDDocument, AgentIdentity

from .config import AgentDidExposureConfig, AgentDidSemanticKernelConfig
from .context import compose_instructions
from .observability import AgentDidEventHandler, AgentDidObserver
from .snapshot import AgentDidIdentitySnapshot, RuntimeIdentity, build_agent_did_identity_snapshot
from .tools import SemanticKernelTool, create_agent_did_tools, create_host_tool_specs


@dataclass(slots=True)
class AgentDidSemanticKernelIntegration:
    """Ready-to-use integration bundle for Semantic Kernel hosts."""

    agent_identity: AgentIdentity
    runtime_identity: RuntimeIdentity
    config: AgentDidSemanticKernelConfig
    observer: AgentDidObserver
    tools: list[SemanticKernelTool]

    def _capture_identity_snapshot(self, reason: str) -> AgentDidIdentitySnapshot:
        snapshot = build_agent_did_identity_snapshot(self.runtime_identity)
        self.observer.emit(
            "agent_did.identity_snapshot.refreshed",
            attributes={
                "did": snapshot.did,
                "authentication_key_id": snapshot.authentication_key_id,
                "reason": reason,
            },
        )
        return snapshot

    @property
    def identity_snapshot(self) -> AgentDidIdentitySnapshot:
        return self._capture_identity_snapshot("property_access")

    def get_current_identity(self) -> dict[str, Any]:
        return self._capture_identity_snapshot("get_current_identity").model_dump(exclude_none=True)

    def get_current_document(self) -> AgentDIDDocument:
        return self.runtime_identity.document

    def compose_instructions(
        self,
        base_instructions: str | None = None,
        additional_instructions: str | None = None,
    ) -> str:
        effective_additional_instructions = additional_instructions or self.config.additional_instructions
        return compose_instructions(
            base_instructions,
            self._capture_identity_snapshot("compose_instructions"),
            effective_additional_instructions,
        )

    def create_session_context(self, base_context: Mapping[str, Any] | None = None) -> dict[str, Any]:
        merged_context = dict(base_context or {})
        merged_context["agent_did"] = self._capture_identity_snapshot("create_session_context").model_dump(
            exclude_none=True
        )
        self.observer.emit(
            "agent_did.context.created",
            attributes={"keys": sorted(merged_context.keys()), "did": self.runtime_identity.document.id},
        )
        return merged_context

    def create_context_middleware(self, *, context_key: str = "agent_did") -> Any:
        def middleware(base_context: Mapping[str, Any] | None = None) -> dict[str, Any]:
            merged_context = dict(base_context or {})
            merged_context[context_key] = self._capture_identity_snapshot("middleware_context_injection").model_dump(
                exclude_none=True
            )
            self.observer.emit(
                "agent_did.middleware.context_injected",
                attributes={"context_key": context_key, "did": self.runtime_identity.document.id},
            )
            return merged_context

        return middleware

    def create_agent_kwargs(self, base_instructions: str | None = None) -> dict[str, Any]:
        return {
            "tools": create_host_tool_specs(self.tools),
            "instructions": self.compose_instructions(base_instructions),
            "context": self.create_session_context(),
        }

    def create_semantic_kernel_plugin(
        self,
        *,
        plugin_name: str = "agent_did",
        description: str | None = None,
    ) -> Any:
        from .runtime import create_semantic_kernel_plugin

        return create_semantic_kernel_plugin(
            self.tools,
            plugin_name=plugin_name,
            description=description,
        )


def create_agent_did_semantic_kernel_integration(
    *,
    agent_identity: AgentIdentity,
    runtime_identity: RuntimeIdentity,
    expose: AgentDidExposureConfig | dict[str, Any] | None = None,
    tool_prefix: str = "agent_did",
    additional_instructions: str | None = None,
    allow_private_network_targets: bool = False,
    observability_handler: AgentDidEventHandler | None = None,
    logger: logging.Logger | None = None,
) -> AgentDidSemanticKernelIntegration:
    exposure = (
        expose
        if isinstance(expose, AgentDidExposureConfig)
        else AgentDidExposureConfig.model_validate(expose or {})
    )
    config = AgentDidSemanticKernelConfig(
        expose=exposure,
        tool_prefix=tool_prefix,
        additional_instructions=additional_instructions,
        allow_private_network_targets=allow_private_network_targets,
    )
    observer = AgentDidObserver(event_handler=observability_handler, logger=logger)
    tools = create_agent_did_tools(
        agent_identity=agent_identity,
        runtime_identity=runtime_identity,
        expose=config.expose,
        tool_prefix=config.tool_prefix,
        allow_private_network_targets=config.allow_private_network_targets,
        observer=observer,
    )

    return AgentDidSemanticKernelIntegration(
        agent_identity=agent_identity,
        runtime_identity=runtime_identity,
        config=config,
        observer=observer,
        tools=tools,
    )
