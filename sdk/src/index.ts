/**
 * @agent-did/sdk
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
  CreateAgentParams,
  CreateAgentResult,
  SignHttpRequestParams,
  UpdateAgentDocumentParams,
  RotateVerificationMethodResult,
  VerifyHttpRequestSignatureParams
} from './core/types';

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
