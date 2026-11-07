"""agent-did-sdk — Python SDK for the Agent-DID Specification (RFC-001)."""

from __future__ import annotations

from .core.client import AgentDidClient, AgentDidClientOptions
from .core.http_security import HttpTargetValidationOptions, validate_http_target
from .core.http_signatures import (
    HttpRequestLike,
    HttpSignatureError,
    SignatureInput,
    Token,
    build_signature_base,
    parse_signature_header,
    parse_signature_input_header,
    serialize_signature_input,
)
from .core.identity import (
    AGENT_DID_HTTP_SIGNATURE_COMPONENTS,
    AGENT_DID_HTTP_SIGNATURE_TAG,
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
from .core.nonce_store import InMemoryNonceStore, NonceStore
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
    HttpSignatureRejection,
    IdentityCompositionErrorReason,
    MetadataCommitmentSalts,
    RotateVerificationMethodResult,
    SignHttpRequestParams,
    SigningVerificationPurpose,
    UpdateAgentDocumentParams,
    VerifiableCredentialLink,
    VerificationMethod,
    VerificationRelationship,
    VerifyHttpRequestSignatureParams,
    VerifyHttpRequestSignatureResult,
)
from .crypto.hash import (
    canonicalize_json,
    create_metadata_commitment,
    format_hash_uri,
    generate_agent_metadata_hash,
    generate_canonical_document_hash,
    generate_commitment_salt,
    hash_payload,
    verify_metadata_commitment,
)
from .crypto.multibase import decode_public_key_multibase, did_key_from_public_key, encode_public_key_multibase
from .registry.in_memory import InMemoryAgentRegistry
from .registry.types import AgentRegistry, AgentRegistryRecord
from .resolver.aws_sigv4_s3_source import AwsSigV4S3DIDDocumentSource, AwsSigV4S3DIDDocumentSourceConfig
from .resolver.bearer_http_source import BearerTokenHttpDIDDocumentSource, BearerTokenHttpDIDDocumentSourceConfig
from .resolver.file_source import FilesystemDIDDocumentSource, FilesystemDIDDocumentSourceConfig
from .resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from .resolver.in_memory import InMemoryDIDResolver
from .resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig
from .resolver.presigned_http_source import PresignedHttpDIDDocumentSource, PresignedHttpDIDDocumentSourceConfig
from .resolver.s3_compatible_source import S3CompatibleDIDDocumentSource, S3CompatibleDIDDocumentSourceConfig
from .resolver.types import (
    DIDDocumentSource,
    DIDResolver,
    DocumentIntegrityError,
    ResolverCacheStats,
    ResolverResolutionEvent,
    ResolverResolutionStage,
    UniversalResolverConfig,
)
from .resolver.universal import UniversalResolverClient
from .resolver.webvh_source import WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig
from .webvh.adapter import DidWebvhError, DidWebvhErrorCode

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
    "MetadataCommitmentSalts",
    "UpdateAgentDocumentParams",
    "RotateVerificationMethodResult",
    "SignHttpRequestParams",
    "VerifyHttpRequestSignatureParams",
    "VerifyHttpRequestSignatureResult",
    "HttpSignatureRejection",
    "AgentDocumentHistoryAction",
    "AgentDocumentHistoryEntry",
    # did:webvh v1.0 errors (log verification, unauthorized controller signer)
    "DidWebvhError",
    "DidWebvhErrorCode",
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
    # HTTP Message Signatures (RFC 9421) and replay protection
    "AGENT_DID_HTTP_SIGNATURE_COMPONENTS",
    "AGENT_DID_HTTP_SIGNATURE_TAG",
    "NonceStore",
    "InMemoryNonceStore",
    "HttpSignatureError",
    "HttpRequestLike",
    "SignatureInput",
    "Token",
    "build_signature_base",
    "parse_signature_header",
    "parse_signature_input_header",
    "serialize_signature_input",
    "LocalKeySigner",
    # Core HTTP security
    "HttpTargetValidationOptions",
    "validate_http_target",
    # Core identity
    "AgentDidClient",
    "AgentDidClientOptions",
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
    "canonicalize_json",
    "generate_canonical_document_hash",
    "generate_commitment_salt",
    "create_metadata_commitment",
    "verify_metadata_commitment",
    "encode_public_key_multibase",
    "decode_public_key_multibase",
    "did_key_from_public_key",
    "did_key_from_public_key",
    # Registry
    "AgentRegistry",
    "AgentRegistryRecord",
    "InMemoryAgentRegistry",
    # Resolver
    "DIDResolver",
    "DIDDocumentSource",
    "UniversalResolverConfig",
    "ResolverCacheStats",
    "ResolverResolutionEvent",
    "ResolverResolutionStage",
    "DocumentIntegrityError",
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
