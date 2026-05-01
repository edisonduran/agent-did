"""Public package surface for the Agent-DID Microsoft Agent Framework integration."""

from .config import AgentDidExposureConfig, AgentDidMicrosoftAgentFrameworkConfig
from .context import build_agent_did_instructions, compose_instructions
from .handoff import (
    HANDOFF_TTL_DEFAULTS,
    ActionClass,
    SignedHandoffMessage,
    VerificationBlockedCallback,
    VerificationBlockedError,
    build_handoff_verifier_executor,
    build_handoff_verifier_function,
)
from .integration import (
    AgentDidMicrosoftAgentFrameworkIntegration,
    AgentDidWorkflowBuilder,
    create_agent_did_microsoft_agent_framework_integration,
)
from .observability import (
    AgentDidEventHandler,
    AgentDidMicrosoftAgentFrameworkObservabilityEvent,
    compose_event_handlers,
    create_json_logger_event_handler,
    create_opentelemetry_event_handler,
    create_opentelemetry_tracer,
    serialize_observability_event,
)
from .sanitization import sanitize_observability_attributes
from .snapshot import AgentDidIdentitySnapshot, build_agent_did_identity_snapshot
from .tools import create_agent_framework_tools

PACKAGE_STATUS = "functional"
createAgentDidMicrosoftAgentFrameworkIntegration = create_agent_did_microsoft_agent_framework_integration

__all__ = [
    "PACKAGE_STATUS",
    "ActionClass",
    "AgentDidEventHandler",
    "AgentDidExposureConfig",
    "AgentDidIdentitySnapshot",
    "AgentDidMicrosoftAgentFrameworkConfig",
    "AgentDidMicrosoftAgentFrameworkIntegration",
    "AgentDidMicrosoftAgentFrameworkObservabilityEvent",
    "AgentDidWorkflowBuilder",
    "HANDOFF_TTL_DEFAULTS",
    "SignedHandoffMessage",
    "VerificationBlockedCallback",
    "VerificationBlockedError",
    "build_agent_did_identity_snapshot",
    "build_agent_did_instructions",
    "build_handoff_verifier_executor",
    "build_handoff_verifier_function",
    "compose_event_handlers",
    "compose_instructions",
    "createAgentDidMicrosoftAgentFrameworkIntegration",
    "create_agent_did_microsoft_agent_framework_integration",
    "create_agent_framework_tools",
    "create_json_logger_event_handler",
    "create_opentelemetry_event_handler",
    "create_opentelemetry_tracer",
    "sanitize_observability_attributes",
    "serialize_observability_event",
]
