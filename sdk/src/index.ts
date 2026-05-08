/**
 * @agentdid/sdk
 * The official TypeScript SDK for the Agent-DID Specification (RFC-001)
 * 
 * This SDK provides the core tools to create, sign, and verify Decentralized Identifiers
 * for autonomous AI agents, ensuring provenance, compliance, and secure delegation.
 */

// Export Core Types (RFC-001 Schema)
export {
  AgentMetadata,
  AgentDocumentHistoryAction,
  AgentDocumentHistoryEntry,
  VerifiableCredentialLink,
  VerificationMethod,
  AgentDIDDocument,
  VerificationRelationship,
  SigningVerificationPurpose,
  IdentityCompositionErrorReason,
  CreateAgentParams,
  CreateAgentResult,
  SignHttpRequestParams,
  UpdateAgentDocumentParams,
  RotateVerificationMethodResult,
  VerifyHttpRequestSignatureParams
} from './core/types';

export {
  IdentityCompositionError,
  IdentityCompositionErrorDetails,
  DID_VERIFICATION_RELATIONSHIPS,
  SIGNING_VERIFICATION_PURPOSES,
  assertKeyPurpose,
  assertSigningPurpose,
  getKeyRelationships,
  getRelationshipKeyIds
} from './core/identity-composition';

// Export Core Identity Class
export {
  AgentIdentity,
  AgentIdentityConfig,
  ProductionResolverProfileConfig,
  ProductionHttpResolverProfileConfig,
  ProductionJsonRpcResolverProfileConfig
} from './core/AgentIdentity';

// Export Cryptographic Utilities
export {
  hashPayload,
  formatHashUri,
  generateAgentMetadataHash
} from './crypto/hash';

export {
  encodePublicKeyMultibase,
  decodePublicKeyMultibase
} from './crypto/multibase';

export {
  AgentSigner,
  LocalKeySigner
} from './core/signer';

export {
  validateHttpTarget,
  HttpTargetValidationOptions
} from './core/http-security';

export {
  isUnixTimestampString,
  unixStringToIso,
  isoToUnixString,
  normalizeTimestampToIso
} from './core/time';

// Export Resolver APIs
export {
  DIDResolver,
  DIDDocumentSource,
  UniversalResolverConfig,
  ResolverCacheStats,
  ResolverResolutionEvent,
  ResolverResolutionStage
} from './resolver/types';

export {
  InMemoryDIDResolver
} from './resolver/InMemoryDIDResolver';

export {
  UniversalResolverClient
} from './resolver/UniversalResolverClient';

export {
  HttpDIDDocumentSource,
  HttpDIDDocumentSourceConfig
} from './resolver/HttpDIDDocumentSource';

export {
  BearerTokenHttpDIDDocumentSource,
  BearerTokenHttpDIDDocumentSourceConfig
} from './resolver/BearerTokenHttpDIDDocumentSource';

export {
  FilesystemDIDDocumentSource,
  FilesystemDIDDocumentSourceConfig
} from './resolver/FilesystemDIDDocumentSource';

export {
  PresignedHttpDIDDocumentSource,
  PresignedHttpDIDDocumentSourceConfig
} from './resolver/PresignedHttpDIDDocumentSource';

export {
  S3CompatibleDIDDocumentSource,
  S3CompatibleDIDDocumentSourceConfig
} from './resolver/S3CompatibleDIDDocumentSource';

export {
  AwsSigV4S3DIDDocumentSource,
  AwsSigV4S3DIDDocumentSourceConfig
} from './resolver/AwsSigV4S3DIDDocumentSource';

export {
  JsonRpcDIDDocumentSource,
  JsonRpcDIDDocumentSourceConfig
} from './resolver/JsonRpcDIDDocumentSource';

// Export Registry APIs
export {
  AgentRegistry,
  AgentRegistryRecord
} from './registry/types';

export {
  InMemoryAgentRegistry
} from './registry/InMemoryAgentRegistry';

export {
  EvmAgentRegistry
} from './registry/EvmAgentRegistry';

export {
  EthersAgentRegistryContractClient
} from './registry/EthersAgentRegistryContractClient';

export {
  EvmTxResponse,
  EvmAgentRegistryContract,
  EvmAgentRegistryAdapterConfig
} from './registry/evm-types';
