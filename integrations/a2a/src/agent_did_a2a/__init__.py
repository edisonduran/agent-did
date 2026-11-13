"""Public package surface for the Agent-DID A2A integration."""

from .agent_card import A2AAgentCard, A2AAuthenticationInfo, A2ASkill, agent_card_to_json, build_agent_card
from .config import AgentDidA2AConfig, AgentDidA2AExposureConfig
from .context import build_agent_did_a2a_context
from .integration import AgentDidA2AIntegration, create_agent_did_a2a_integration
from .jsonrpc import (
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    SignedA2ARequest,
    build_task_get_request,
    build_task_send_request,
    parse_jsonrpc_response,
    sign_a2a_request,
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
    "A2AAgentCard",
    "A2AAuthenticationInfo",
    "A2ASkill",
    "build_agent_card",
    "agent_card_to_json",
    # Config
    "AgentDidA2AConfig",
    "AgentDidA2AExposureConfig",
    # Context
    "build_agent_did_a2a_context",
    # Integration
    "AgentDidA2AIntegration",
    "create_agent_did_a2a_integration",
    # JSON-RPC
    "JsonRpcError",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "SignedA2ARequest",
    "build_task_get_request",
    "build_task_send_request",
    "parse_jsonrpc_response",
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
