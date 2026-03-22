"""CrewAI callback helpers for Agent-DID traceability."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .integration import AgentDidCrewAIIntegration
from .sanitization import sanitize_output

CallbackSink = Callable[[dict[str, Any]], None]


def create_step_callback(
    integration: AgentDidCrewAIIntegration, sink: CallbackSink | None = None
) -> Callable[[Any], dict[str, Any]]:
    def callback(step_output: Any) -> dict[str, Any]:
        identity = integration.identity_snapshot.model_dump(exclude_none=True)
        sanitized_step_output = sanitize_output(step_output)
        payload = {
            "event": "agent_did.crewai.step",
            "identity": identity,
            "step_output": sanitized_step_output,
        }
        integration.observer.emit(
            "agent_did.crewai.step",
            attributes={
                "did": identity["did"],
                "authentication_key_id": identity.get("authentication_key_id"),
                "step_output": step_output,
            },
        )
        if sink:
            sink(payload)
        return payload

    return callback


def create_task_callback(
    integration: AgentDidCrewAIIntegration, sink: CallbackSink | None = None
) -> Callable[[Any], dict[str, Any]]:
    def callback(task_output: Any) -> dict[str, Any]:
        identity = integration.identity_snapshot.model_dump(exclude_none=True)
        sanitized_task_output = sanitize_output(task_output)
        payload = {
            "event": "agent_did.crewai.task",
            "identity": identity,
            "task_output": sanitized_task_output,
        }
        integration.observer.emit(
            "agent_did.crewai.task",
            attributes={
                "did": identity["did"],
                "authentication_key_id": identity.get("authentication_key_id"),
                "task_output": task_output,
            },
        )
        if sink:
            sink(payload)
        return payload

    return callback
