"""Public package surface for the Agent-DID Microsoft Agent Framework integration."""

from .config import AgentDidExposureConfig, AgentDidMicrosoftAgentFrameworkConfig
from .context import build_agent_did_instructions, compose_instructions
from .integration import (
    AgentDidMicrosoftAgentFrameworkIntegration,
    create_agent_did_microsoft_agent_framework_integration,
)
from .observability import (
    AgentDidEventHandler,
    AgentDidMicrosoftAgentFrameworkObservabilityEvent,
    compose_event_handlers,
    create_json_logger_event_handler,
    sanitize_observability_attributes,
    serialize_observability_event,
)
from .snapshot import AgentDidIdentitySnapshot, build_agent_did_identity_snapshot
from .tools import MicrosoftAgentFrameworkTool, create_agent_did_tools, create_host_tool_specs

PACKAGE_STATUS = "functional"
createAgentDidMicrosoftAgentFrameworkIntegration = create_agent_did_microsoft_agent_framework_integration

__all__ = [
    "PACKAGE_STATUS",
    "AgentDidEventHandler",
    "AgentDidExposureConfig",
    "AgentDidIdentitySnapshot",
    "AgentDidMicrosoftAgentFrameworkConfig",
    "AgentDidMicrosoftAgentFrameworkIntegration",
    "AgentDidMicrosoftAgentFrameworkObservabilityEvent",
    "MicrosoftAgentFrameworkTool",
    "build_agent_did_identity_snapshot",
    "build_agent_did_instructions",
    "compose_event_handlers",
    "compose_instructions",
    "createAgentDidMicrosoftAgentFrameworkIntegration",
    "create_agent_did_microsoft_agent_framework_integration",
    "create_agent_did_tools",
    "create_host_tool_specs",
    "create_json_logger_event_handler",
    "sanitize_observability_attributes",
    "serialize_observability_event",
]
