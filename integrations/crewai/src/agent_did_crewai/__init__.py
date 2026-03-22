"""Public package surface for the Agent-DID CrewAI integration."""

from .callbacks import create_step_callback, create_task_callback
from .config import AgentDidCrewAIConfig, AgentDidExposureConfig
from .context import build_agent_did_system_prompt, compose_system_prompt
from .guardrails import create_identity_output_guardrail
from .integration import AgentDidCrewAIIntegration, create_agent_did_crewai_integration
from .observability import (
    AgentDidCrewAIObservabilityEvent,
    compose_event_handlers,
    create_json_logger_event_handler,
    serialize_observability_event,
)
from .snapshot import AgentDidIdentitySnapshot, build_agent_did_identity_snapshot
from .structured_outputs import AgentDidStructuredOutput, create_identity_output_model
from .tools import CrewAITool, create_agent_did_tools

PACKAGE_STATUS = "functional"

__all__ = [
    "PACKAGE_STATUS",
    "AgentDidCrewAIConfig",
    "AgentDidExposureConfig",
    "AgentDidIdentitySnapshot",
    "AgentDidCrewAIObservabilityEvent",
    "AgentDidCrewAIIntegration",
    "AgentDidStructuredOutput",
    "CrewAITool",
    "build_agent_did_identity_snapshot",
    "build_agent_did_system_prompt",
    "compose_event_handlers",
    "compose_system_prompt",
    "create_identity_output_model",
    "create_agent_did_crewai_integration",
    "create_agent_did_tools",
    "create_identity_output_guardrail",
    "create_json_logger_event_handler",
    "create_step_callback",
    "create_task_callback",
    "serialize_observability_event",
]
