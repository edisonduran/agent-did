"""Public package surface for the Agent-DID Semantic Kernel integration."""

from .config import AgentDidExposureConfig, AgentDidSemanticKernelConfig
from .context import build_agent_did_instructions, compose_instructions
from .integration import (
    AgentDidSemanticKernelIntegration,
    create_agent_did_semantic_kernel_integration,
)
from .observability import (
    AgentDidEventHandler,
    AgentDidSemanticKernelObservabilityEvent,
    compose_event_handlers,
    create_json_logger_event_handler,
    sanitize_observability_attributes,
    serialize_observability_event,
)
from .runtime import create_semantic_kernel_plugin
from .snapshot import AgentDidIdentitySnapshot, build_agent_did_identity_snapshot
from .tools import SemanticKernelTool, create_agent_did_tools, create_host_tool_specs

PACKAGE_STATUS = "functional"
createAgentDidSemanticKernelIntegration = create_agent_did_semantic_kernel_integration

__all__ = [
    "PACKAGE_STATUS",
    "AgentDidEventHandler",
    "AgentDidExposureConfig",
    "AgentDidIdentitySnapshot",
    "AgentDidSemanticKernelConfig",
    "AgentDidSemanticKernelIntegration",
    "AgentDidSemanticKernelObservabilityEvent",
    "SemanticKernelTool",
    "build_agent_did_identity_snapshot",
    "build_agent_did_instructions",
    "compose_event_handlers",
    "compose_instructions",
    "createAgentDidSemanticKernelIntegration",
    "create_agent_did_semantic_kernel_integration",
    "create_agent_did_tools",
    "create_host_tool_specs",
    "create_json_logger_event_handler",
    "create_semantic_kernel_plugin",
    "sanitize_observability_attributes",
    "serialize_observability_event",
]
