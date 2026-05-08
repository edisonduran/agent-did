"""agent-did-sdk — Python SDK for the Agent-DID Specification (RFC-001)."""

from __future__ import annotations

from .core.http_security import HttpTargetValidationOptions, validate_http_target
from .core.identity import (
    AgentIdentity,
    AgentIdentityConfig,
    ProductionHttpResolverProfileConfig,
    ProductionJsonRpcResolverProfileConfig,
    ProductionResolverProfileConfig,
)
from .core.identity_composition import (
    DID_VERIFICATION_RELATIONSHIPS,
    SIGNING_VERIFICATION_PURPOSES,
    IdentityCompositionError,
    assert_key_purpose,
    assert_signing_purpose,
    get_key_relationships,
    get_relationship_key_ids,
)
from .core.signer import AgentSigner, LocalKeySigner
from .core.time_utils import (
    is_unix_timestamp_string,
    iso_to_unix_string,
    normalize_timestamp_to_iso,
    unix_string_to_iso,
)
from .core.types import (
    AgentDIDDocument,
    AgentDocumentHistoryAction,
    AgentDocumentHistoryEntry,
    AgentMetadata,
    CreateAgentParams,
    CreateAgentResult,
    CreateDidWebvhOptions,
    IdentityCompositionErrorReason,
    RotateVerificationMethodResult,
    SignHttpRequestParams,
    SigningVerificationPurpose,
    UpdateAgentDocumentParams,
    VerifiableCredentialLink,
    VerificationMethod,
    VerificationRelationship,
    VerifyHttpRequestSignatureParams,
)
from .crypto.hash import format_hash_uri, generate_agent_metadata_hash, hash_payload
from .crypto.multibase import decode_public_key_multibase, encode_public_key_multibase
from .registry.evm_registry import EvmAgentRegistry
from .registry.evm_types import EvmAgentRegistryAdapterConfig, EvmAgentRegistryContract, EvmTxResponse
from .registry.in_memory import InMemoryAgentRegistry
from .registry.types import AgentRegistry, AgentRegistryRecord
from .registry.web3_client import Web3AgentRegistryContractClient
from .resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from .resolver.bearer_http_source import BearerTokenHttpDIDDocumentSource, BearerTokenHttpDIDDocumentSourceConfig
from .resolver.file_source import FilesystemDIDDocumentSource, FilesystemDIDDocumentSourceConfig
from .resolver.in_memory import InMemoryDIDResolver
from .resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig
from .resolver.aws_sigv4_s3_source import AwsSigV4S3DIDDocumentSource, AwsSigV4S3DIDDocumentSourceConfig
from .resolver.presigned_http_source import PresignedHttpDIDDocumentSource, PresignedHttpDIDDocumentSourceConfig
from .resolver.s3_compatible_source import S3CompatibleDIDDocumentSource, S3CompatibleDIDDocumentSourceConfig
from .resolver.webvh_source import WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig
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
    "CreateDidWebvhOptions",
    "VerificationRelationship",
    "SigningVerificationPurpose",
    "IdentityCompositionErrorReason",
    "CreateAgentParams",
    "CreateAgentResult",
    "UpdateAgentDocumentParams",
    "RotateVerificationMethodResult",
    "SignHttpRequestParams",
    "VerifyHttpRequestSignatureParams",
    "AgentDocumentHistoryAction",
    "AgentDocumentHistoryEntry",
    # Identity composition
    "IdentityCompositionError",
    "DID_VERIFICATION_RELATIONSHIPS",
    "SIGNING_VERIFICATION_PURPOSES",
    "assert_key_purpose",
    "assert_signing_purpose",
    "get_key_relationships",
    "get_relationship_key_ids",
    # Core signer
    "AgentSigner",
    "LocalKeySigner",
    # Core HTTP security
    "HttpTargetValidationOptions",
    "validate_http_target",
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
    "encode_public_key_multibase",
    "decode_public_key_multibase",
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
    "BearerTokenHttpDIDDocumentSource",
    "BearerTokenHttpDIDDocumentSourceConfig",
    "FilesystemDIDDocumentSource",
    "FilesystemDIDDocumentSourceConfig",
    "AwsSigV4S3DIDDocumentSource",
    "AwsSigV4S3DIDDocumentSourceConfig",
    "PresignedHttpDIDDocumentSource",
    "PresignedHttpDIDDocumentSourceConfig",
    "S3CompatibleDIDDocumentSource",
    "S3CompatibleDIDDocumentSourceConfig",
    "JsonRpcDIDDocumentSource",
    "JsonRpcDIDDocumentSourceConfig",
    "WebvhDIDDocumentSource",
    "WebvhDIDDocumentSourceConfig",
]
