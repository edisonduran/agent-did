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
  SignedArtifactKind,
  AdditionalVerificationRelationship,
  IdentityCompositionErrorReason,
  CreateAgentParams,
  CreateAgentResult,
  CreateDidWebvhOptions,
  DidWebvhLifecycleOptions,
  RotateVerificationMethodOptions,
  AddVerificationMethodOptions,
  AddVerificationMethodResult,
  AddedKeyRelationship,
  DidWebvhControllerKeys,
  RotateControllerKeyOptions,
  MetadataCommitmentSalts,
  SignHttpRequestParams,
  UpdateAgentDocumentParams,
  RotateVerificationMethodResult,
  VerifyHttpRequestSignatureParams,
  VerifyHttpRequestSignatureResult,
  HttpSignatureRejection,
  CheckKeyAtTimeOptions,
  KeyAtTimeRejection,
  KeyAtTimeResult,
  KeyAtTimeUncertainty,
  VerifySignatureAtTimeOptions,
  VerifySignatureAtTimeResult
} from './core/types';

export { checkDidWebvhKeyAtTime } from './verification/key-at-time';

export {
  IdentityCompositionError,
  IdentityCompositionErrorDetails,
  DID_VERIFICATION_RELATIONSHIPS,
  SIGNING_VERIFICATION_PURPOSES,
  SIGNED_ARTIFACT_KINDS,
  ADDITIONAL_VERIFICATION_RELATIONSHIPS,
  REQUIRED_RELATIONSHIP_BY_ARTIFACT,
  requiredRelationshipFor,
  assertKeyPurpose,
  assertSigningPurpose,
  getKeyRelationships,
  getRelationshipKeyIds
} from './core/identity-composition';
export { AGENT_DID_MESSAGE_SIGNING_PREFIX, messageSigningInput } from './core/message-signing';
export { ControllerBindingError } from './core/controller-binding';
export type { DidWebvhResolution, DidWebvhState } from './resolver/types';

// Export Core Identity Class
export {
  AgentIdentity,
  AgentIdentityConfig,
  ProductionResolverProfileConfig,
  ProductionHttpResolverProfileConfig,
  ProductionJsonRpcResolverProfileConfig
} from './core/AgentIdentity';
export { AgentDidClient, AgentDidClientOptions } from './core/AgentDidClient';

// Export Cryptographic Utilities
export {
  hashPayload,
  formatHashUri,
  generateAgentMetadataHash,
  canonicalizeJson,
  generateCanonicalDocumentHash,
  generateCommitmentSalt,
  createMetadataCommitment,
  verifyMetadataCommitment
} from './crypto/hash';

export {
  encodePublicKeyMultibase,
  didKeyFromPublicKey,
  decodePublicKeyMultibase
} from './crypto/multibase';

export {
  AgentSigner,
  LocalKeySigner
} from './core/signer';

export {
  validateHttpTarget,
  HttpTargetValidationOptions,
  HttpSecurityOptions,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_MAX_RESPONSE_BYTES
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
  DEFAULT_RESOLVER_MAX_CACHE_ENTRIES,
  ResolverCacheStats,
  ResolverResolutionEvent,
  ResolverResolutionStage,
  DocumentIntegrityError
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

export { WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig } from './resolver/WebvhDIDDocumentSource';
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

// did:webvh v1.0 errors (log verification, unauthorized controller signer)
export { DidWebvhError, DidWebvhErrorCode } from './webvh/adapter';

// HTTP Message Signatures (RFC 9421) and replay protection
export {
  AGENT_DID_HTTP_SIGNATURE_COMPONENTS,
  AGENT_DID_HTTP_SIGNATURE_TAG
} from './core/AgentIdentity';
export { NonceStore, InMemoryNonceStore, InMemoryNonceStoreOptions } from './core/nonce-store';
export {
  HttpSignatureError,
  HttpRequestLike,
  SignatureInput,
  SignatureParamValue,
  buildSignatureBase,
  parseSignatureHeader,
  parseSignatureInputHeader,
  serializeSignatureInput
} from './core/http-signatures';
