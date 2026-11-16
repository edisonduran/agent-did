"""Public package surface for the Agent-DID A2A integration."""

from .agent_card import (
    A2A_PROTOCOL_VERSION,
    AGENT_CARD_WELL_KNOWN_PATH,
    A2AAgentCapabilities,
    A2AAgentCard,
    A2AAgentExtension,
    A2AAgentInterface,
    A2AAgentProvider,
    A2ASkill,
    agent_card_to_json,
    build_agent_card,
)
from .config import AgentDidA2AConfig, AgentDidA2AExposureConfig, AgentDidA2AOAuthClientCredentials
from .context import build_agent_did_a2a_context
from .integration import AgentDidA2AIntegration, create_agent_did_a2a_integration
from .jsonrpc import (
    A2AMessage,
    A2APart,
    A2ATask,
    A2ATaskStatus,
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    SignedA2ARequest,
    build_get_task_request,
    build_send_message_request,
    parse_jsonrpc_response,
    parse_send_message_result,
    sign_a2a_request,
    text_message,
    verify_a2a_request,
    verify_a2a_request_detailed,
)
from .observability import (
    AgentDidA2AObservabilityEvent,
    compose_event_handlers,
    create_json_logger_event_handler,
    serialize_observability_event,
)
from .snapshot import AgentDidIdentitySnapshot, build_agent_did_identity_snapshot

PACKAGE_STATUS = "functional"

__all__ = [
    "PACKAGE_STATUS",
    # Agent Card
    "A2A_PROTOCOL_VERSION",
    "AGENT_CARD_WELL_KNOWN_PATH",
    "A2AAgentCapabilities",
    "A2AAgentCard",
    "A2AAgentExtension",
    "A2AAgentInterface",
    "A2AAgentProvider",
    "A2ASkill",
    "build_agent_card",
    "agent_card_to_json",
    # Config
    "AgentDidA2AConfig",
    "AgentDidA2AExposureConfig",
    "AgentDidA2AOAuthClientCredentials",
    # Context
    "build_agent_did_a2a_context",
    # Integration
    "AgentDidA2AIntegration",
    "create_agent_did_a2a_integration",
    # JSON-RPC and A2A 1.0 objects
    "A2AMessage",
    "A2APart",
    "A2ATask",
    "A2ATaskStatus",
    "JsonRpcError",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "SignedA2ARequest",
    "build_get_task_request",
    "build_send_message_request",
    "parse_jsonrpc_response",
    "parse_send_message_result",
    "text_message",
    "sign_a2a_request",
    "verify_a2a_request",
    "verify_a2a_request_detailed",
    # Observability
    "AgentDidA2AObservabilityEvent",
    "compose_event_handlers",
    "create_json_logger_event_handler",
    "serialize_observability_event",
    # Snapshot
    "AgentDidIdentitySnapshot",
    "build_agent_did_identity_snapshot",
]
