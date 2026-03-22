"""Public integration assembly for Agent-DID and CrewAI."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agent_did_sdk import AgentDIDDocument, AgentIdentity
from pydantic import BaseModel

from .config import AgentDidCrewAIConfig, AgentDidExposureConfig
from .context import compose_system_prompt
from .observability import AgentDidCrewAIEventHandler, AgentDidObserver
from .snapshot import (
    AgentDidIdentitySnapshot,
    RuntimeIdentity,
    RuntimeIdentityHandle,
    build_agent_did_identity_snapshot,
)
from .tools import CrewAITool, create_agent_did_tools


@dataclass(slots=True)
class AgentDidCrewAIIntegration:
    """Ready-to-use integration bundle for CrewAI agents and crews."""

    agent_identity: AgentIdentity
    runtime_identity_handle: RuntimeIdentityHandle
    config: AgentDidCrewAIConfig
    observer: AgentDidObserver
    tools: list[CrewAITool]

    @property
    def runtime_identity(self) -> RuntimeIdentity:
        return self.runtime_identity_handle.value

    @property
    def identity_snapshot(self) -> AgentDidIdentitySnapshot:
        return build_agent_did_identity_snapshot(self.runtime_identity)

    def _capture_identity_snapshot(self, reason: str) -> AgentDidIdentitySnapshot:
        snapshot = self.identity_snapshot
        self.observer.emit(
            "agent_did.identity_snapshot.refreshed",
            attributes={
                "did": snapshot.did,
                "authentication_key_id": snapshot.authentication_key_id,
                "reason": reason,
            },
        )
        return snapshot

    def get_current_identity(self) -> dict[str, Any]:
        return self._capture_identity_snapshot("get_current_identity").model_dump(exclude_none=True)

    def get_current_document(self) -> AgentDIDDocument:
        return self.runtime_identity.document

    def compose_system_prompt(self, base_prompt: str | None = None, additional_context: str | None = None) -> str:
        effective_additional_context = additional_context or self.config.additional_system_context
        snapshot = self._capture_identity_snapshot("compose_system_prompt")
        return compose_system_prompt(base_prompt, snapshot, effective_additional_context)

    def create_agent_kwargs(self, base_prompt: str | None = None) -> dict[str, Any]:
        return {
            "tools": self.tools,
            "backstory": self.compose_system_prompt(base_prompt),
        }

    def create_output_model(
        self,
        *,
        required_fields: list[str] | None = None,
        model_name: str = "AgentDidCrewOutput",
    ) -> type[BaseModel]:
        from .structured_outputs import create_identity_output_model

        return create_identity_output_model(model_name=model_name, required_fields=required_fields)

    def create_task_kwargs(
        self,
        *,
        required_output_fields: list[str] | None = None,
        include_tools: bool = True,
    ) -> dict[str, Any]:
        from .callbacks import create_task_callback
        from .guardrails import create_identity_output_guardrail

        output_model = self.create_output_model(required_fields=required_output_fields)
        task_kwargs: dict[str, Any] = {
            "callback": create_task_callback(self),
            "guardrail": create_identity_output_guardrail(self, required_fields=required_output_fields),
            "output_pydantic": output_model,
        }
        if include_tools:
            task_kwargs["tools"] = self.tools
        return task_kwargs

    def create_crew_kwargs(self) -> dict[str, Any]:
        from .callbacks import create_step_callback, create_task_callback

        return {
            "step_callback": create_step_callback(self),
            "task_callback": create_task_callback(self),
        }


def create_agent_did_crewai_integration(
    *,
    agent_identity: AgentIdentity,
    runtime_identity: RuntimeIdentity,
    expose: AgentDidExposureConfig | dict[str, Any] | None = None,
    tool_prefix: str = "agent_did",
    additional_system_context: str | None = None,
    allow_private_network_targets: bool = False,
    observability_handler: AgentDidCrewAIEventHandler | None = None,
    logger: logging.Logger | None = None,
) -> AgentDidCrewAIIntegration:
    exposure = (
        expose if isinstance(expose, AgentDidExposureConfig) else AgentDidExposureConfig.model_validate(expose or {})
    )
    runtime_identity_handle = RuntimeIdentityHandle(runtime_identity)
    config = AgentDidCrewAIConfig(
        expose=exposure,
        tool_prefix=tool_prefix,
        additional_system_context=additional_system_context,
        allow_private_network_targets=allow_private_network_targets,
    )
    observer = AgentDidObserver(event_handler=observability_handler, logger=logger)
    tools = create_agent_did_tools(
        agent_identity=agent_identity,
        runtime_identity_handle=runtime_identity_handle,
        expose=config.expose,
        tool_prefix=config.tool_prefix,
        allow_private_network_targets=config.allow_private_network_targets,
        observer=observer,
    )

    return AgentDidCrewAIIntegration(
        agent_identity=agent_identity,
        runtime_identity_handle=runtime_identity_handle,
        config=config,
        observer=observer,
        tools=tools,
    )
