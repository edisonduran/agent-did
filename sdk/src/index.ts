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
  DidDocument,
  VerificationRelationshipEntry,
  VerificationRelationship,
  SigningVerificationPurpose,
  SignedArtifactKind,
  AdditionalVerificationRelationship,
  IdentityCompositionErrorReason,
  IdentityCompositionRejection,
  VerifyAgentCardResult,
  VerifyIdentityCompositionParams,
  VerifyIdentityCompositionResult,
  RetireVerificationMethodOptions,
  AgentDidContextEntry,
  RevokedContextTerm,
  CreateAgentParams,
  CreateAgentResult,
  CreateDidWebvhOptions,
  DidWebvhEntryOptions,
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
  CheckDidWebvhKeyAtTimeOptions,
  KeyAtTimeRejection,
  KeyAtTimeResult,
  KeyAtTimeUncertainty,
  VerifySignatureAtTimeOptions,
  VerifySignatureAtTimeResult,
  AgentMetadataCredential,
  AgentMetadataCredentialRejection,
  IssueAgentMetadataCredentialParams,
  VerifyAgentMetadataCredentialOptions,
  VerifyAgentMetadataCredentialResult
} from './core/types';

export type { DataIntegrityProof } from './crypto/data-integrity';
export {
  AGENT_DID_A2A_EXTENSION_URI,
  AGENT_CARD_SIGNATURE_ALG,
  MAX_AGENT_CARD_SIGNATURES,
  signAgentCard,
  parseSignedAgentCard
} from './core/agent-card';
export type { AgentCard, AgentCardSignature, ParsedAgentCard } from './core/agent-card';
export { REVOKED_CONTEXT_TERM } from './core/verification-method';
export { AGENT_METADATA_CREDENTIAL_CONTEXT, AGENT_METADATA_CREDENTIAL_TYPE } from './core/agent-metadata-credential';
export type {
  AgentCapability,
  CapabilityDelegationProof,
  CapabilityInvocationRejection,
  CapabilityRejection,
  ClientAssertionRejection,
  CreateCapabilityParams,
  JwsEd25519Alg,
  VerifyCapabilityChainOptions,
  VerifyCapabilityChainResult,
  VerifyClientAssertionParams,
  VerifyClientAssertionResult,
  VerifyHttpCapabilityInvocationParams,
  VerifyHttpCapabilityInvocationResult
} from './core/types';
export {
  AGENT_DID_CAPABILITY_HTTP_HEADER,
  DEFAULT_MAX_CAPABILITY_CHAIN_LENGTH,
  MAX_CAPABILITY_CHAIN_LENGTH,
  MAX_CAPABILITY_HEADER_BYTES,
  rootCapabilityId,
  ZCAP_CONTEXT,
  ZCAP_ROOT_PREFIX
} from './core/capability';
export {
  buildClientJwks,
  buildClientMetadataDocument,
  CLIENT_ASSERTION_TYPE,
  CLIENT_ASSERTION_TYPE_JWT_BEARER,
  createClientAssertion,
  DEFAULT_CLIENT_ASSERTION_LIFETIME_SECONDS,
  MAX_CLIENT_ASSERTION_LIFETIME_SECONDS
} from './core/oauth-client';
export type { ClientMetadataDocumentParams, CreateClientAssertionParams, Ed25519Jwk } from './core/oauth-client';

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
  DEFAULT_NEGATIVE_CACHE_TTL_MS,
  DEFAULT_MAX_CONCURRENT_FETCHES,
  DEFAULT_MAX_CONCURRENT_FETCHES_PER_HOST,
  DEFAULT_MAX_QUEUED_FETCHES,
  DEFAULT_FETCH_DEADLINE_MS,
  ResolutionLimits,
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
export { DidWebvhError, DidWebvhErrorCode, createDidWebvhWitnessProof } from './webvh/adapter';
export { createTimestampRequest, verifyTimestampToken } from './crypto/timestamp';
export type { TimestampRejection, VerifyTimestampTokenOptions, VerifyTimestampTokenResult } from './crypto/timestamp';
export type {
  CreateDidWebvhWitnessProofParams,
  DidWebvhWitnessCollector,
  DidWebvhWitnessConfig,
  DidWebvhWitnessProofEntry,
  DidWebvhWitnessRequest
} from './webvh/adapter';

// HTTP Message Signatures (RFC 9421) and replay protection
export {
  AGENT_DID_HTTP_HEADER,
  AGENT_DID_HTTP_SIGNATURE_TAG,
  agentDidHttpSignatureComponents
} from './core/AgentIdentity';
export { NonceStore, InMemoryNonceStore, InMemoryNonceStoreOptions } from './core/nonce-store';
export {
  ComponentIdentifier,
  HttpSignatureError,
  HttpRequestLike,
  KeyedComponent,
  SignatureInput,
  SignatureParamValue,
  buildSignatureBase,
  parseSignatureHeader,
  parseSignatureInputHeader,
  requestUrlFormProblem,
  serializeSignatureInput
} from './core/http-signatures';

export {
  SENSITIVE_FIELD_NAMES,
  SENSITIVE_HEADER_NAMES,
  RedactedValue,
  isRedactedMarker,
  isSensitiveFieldName,
  redactValue,
  sanitizeHeaders,
  sanitizeObservabilityAttributes,
  sanitizeUrl
} from './core/observability';
