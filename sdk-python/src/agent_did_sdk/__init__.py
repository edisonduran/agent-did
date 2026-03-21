"""agent-did-sdk — Python SDK for the Agent-DID Specification (RFC-001)."""

from __future__ import annotations

# Core identity
from .core.identity import (
    AgentIdentity,
    AgentIdentityConfig,
    ProductionHttpResolverProfileConfig,
    ProductionJsonRpcResolverProfileConfig,
    ProductionResolverProfileConfig,
)

# Core time utilities
from .core.time_utils import (
    is_unix_timestamp_string,
    iso_to_unix_string,
    normalize_timestamp_to_iso,
    unix_string_to_iso,
)

# Core types
from .core.types import (
    AgentDIDDocument,
    AgentDocumentHistoryAction,
    AgentDocumentHistoryEntry,
    AgentMetadata,
    CreateAgentParams,
    CreateAgentResult,
    RotateVerificationMethodResult,
    SignHttpRequestParams,
    UpdateAgentDocumentParams,
    VerifiableCredentialLink,
    VerificationMethod,
    VerifyHttpRequestSignatureParams,
)

# Crypto
from .crypto.hash import format_hash_uri, generate_agent_metadata_hash, hash_payload
from .registry.evm_registry import EvmAgentRegistry
from .registry.evm_types import EvmAgentRegistryAdapterConfig, EvmAgentRegistryContract, EvmTxResponse
from .registry.in_memory import InMemoryAgentRegistry

# Registry
from .registry.types import AgentRegistry, AgentRegistryRecord
from .registry.web3_client import Web3AgentRegistryContractClient
from .resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from .resolver.in_memory import InMemoryDIDResolver
from .resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig

# Resolver
from .resolver.types import (
    DIDDocumentSource,
    DIDResolver,
    ResolverCacheStats,
    ResolverResolutionEvent,
    ResolverResolutionStage,
    UniversalResolverConfig,
)
from .resolver.universal import UniversalResolverClient

__all__ = [
    # Core types
    "AgentMetadata",
    "VerifiableCredentialLink",
    "VerificationMethod",
    "AgentDIDDocument",
    "CreateAgentParams",
    "CreateAgentResult",
    "UpdateAgentDocumentParams",
    "RotateVerificationMethodResult",
    "SignHttpRequestParams",
    "VerifyHttpRequestSignatureParams",
    "AgentDocumentHistoryAction",
    "AgentDocumentHistoryEntry",
    # Core identity
    "AgentIdentity",
    "AgentIdentityConfig",
    "ProductionResolverProfileConfig",
    "ProductionHttpResolverProfileConfig",
    "ProductionJsonRpcResolverProfileConfig",
    # Core time
    "is_unix_timestamp_string",
    "unix_string_to_iso",
    "iso_to_unix_string",
    "normalize_timestamp_to_iso",
    # Crypto
    "hash_payload",
    "format_hash_uri",
    "generate_agent_metadata_hash",
    # Registry
    "AgentRegistry",
    "AgentRegistryRecord",
    "EvmTxResponse",
    "EvmAgentRegistryContract",
    "EvmAgentRegistryAdapterConfig",
    "InMemoryAgentRegistry",
    "EvmAgentRegistry",
    "Web3AgentRegistryContractClient",
    # Resolver
    "DIDResolver",
    "DIDDocumentSource",
    "UniversalResolverConfig",
    "ResolverCacheStats",
    "ResolverResolutionEvent",
    "ResolverResolutionStage",
    "InMemoryDIDResolver",
    "UniversalResolverClient",
    "HttpDIDDocumentSource",
    "HttpDIDDocumentSourceConfig",
    "JsonRpcDIDDocumentSource",
    "JsonRpcDIDDocumentSourceConfig",
]
