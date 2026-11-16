"""Public package surface for the Agent-DID MCP integration (ADR-008 D-12d)."""

from .client import (
    AgentDidMcpAuth,
    agent_did_assertion_provider,
    create_agent_did_oauth_provider,
)
from .metadata import client_metadata_routes
from .server import (
    DEFAULT_MAX_BODY_BYTES,
    AgentDidPrincipal,
    AgentDidSignatureMiddleware,
    get_agent_did_principal,
)

PACKAGE_STATUS = "functional"

__all__ = [
    "PACKAGE_STATUS",
    # Client
    "AgentDidMcpAuth",
    "agent_did_assertion_provider",
    "create_agent_did_oauth_provider",
    # Server
    "DEFAULT_MAX_BODY_BYTES",
    "AgentDidPrincipal",
    "AgentDidSignatureMiddleware",
    "get_agent_did_principal",
    # Metadata
    "client_metadata_routes",
]
