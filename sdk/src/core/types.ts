/**
 * Core types for the Agent-DID Specification (RFC-001)
 */

export interface AgentMetadata {
  name: string;
  description?: string;
  version: string;
  coreModelHash: string; // URI pointing to the base LLM hash (e.g., ipfs://...)
  systemPromptHash: string; // URI pointing to the system prompt hash
  capabilities?: string[]; // Array of authorized skills/permissions
  memberOf?: string; // DID of the Fleet/Class this agent belongs to
}

export interface VerifiableCredentialLink {
  type: string; // e.g., "VerifiableCredential"
  issuer: string; // DID of the auditor/issuer
  credentialSubject: string; // e.g., "SOC2-AI-Compliance"
  proofHash: string; // URI pointing to the actual VC proof
}

export interface VerificationMethod {
  id: string; // e.g., "did:agent:0x...#key-1"
  type: string; // e.g., "Ed25519VerificationKey2020" or "EcdsaSecp256k1RecoveryMethod2020"
  controller: string; // DID of the creator/owner
  publicKeyMultibase?: string;
  blockchainAccountId?: string; // For EVM/Smart Account compatibility (ERC-4337)
  deactivated?: string; // ISO 8601 timestamp when the key was rotated out
}

export interface AgentDIDDocument {
  "@context": string[];
  id: string; // The Agent's unique DID
  controller: string; // The Creator's DID or Wallet Address
  created: string; // ISO 8601 timestamp
  updated: string; // ISO 8601 timestamp
  agentMetadata: AgentMetadata;
  complianceCertifications?: VerifiableCredentialLink[];
  verificationMethod: VerificationMethod[];
  authentication: string[]; // Array of verificationMethod IDs
}

/**
 * Input parameters required to create a new Agent-DID
 */
export interface CreateAgentParams {
  name: string;
  description?: string;
  version?: string; // Defaults to "1.0.0"
  coreModel: string; // The raw model name/string (will be hashed by SDK)
  systemPrompt: string; // The raw prompt string (will be hashed by SDK)
  capabilities?: string[];
  memberOf?: string;
  /** Optional external signer. When omitted, a local Ed25519 key is generated (demo mode). */
  signer?: import('./signer').AgentSigner;
}

/**
 * The result of creating a new Agent-DID
 */
export interface CreateAgentResult {
  document: AgentDIDDocument;
  /** The Ed25519 private key (hex) — present only in demo mode (no external signer). */
  agentPrivateKey: string;
}

/**
 * Parameters to evolve an existing Agent-DID document while preserving DID.
 */
export interface UpdateAgentDocumentParams {
  description?: string;
  version?: string;
  coreModel?: string;
  systemPrompt?: string;
  capabilities?: string[];
  memberOf?: string;
  complianceCertifications?: VerifiableCredentialLink[];
}

export interface RotateVerificationMethodResult {
  document: AgentDIDDocument;
  verificationMethodId: string;
  agentPrivateKey: string;
}

export type AgentDocumentHistoryAction = 'created' | 'updated' | 'rotated-key' | 'revoked';

export interface AgentDocumentHistoryEntry {
  did: string;
  revision: number;
  action: AgentDocumentHistoryAction;
  timestamp: string;
  version?: string;
  documentRef?: string;
}

/**
 * Parameters for signing an HTTP request (Web Bot Auth)
 */
export interface SignHttpRequestParams {
  method: string;
  url: string;
  body?: string;
  /** Ed25519 private key hex. Either this or `signer` must be provided. */
  agentPrivateKey?: string;
  /** External signer. Preferred over agentPrivateKey when both are present. */
  signer?: import('./signer').AgentSigner;
  agentDid: string;
  verificationMethodId?: string;
  /** Signature expiration window in seconds (default: 30). */
  expiresInSeconds?: number;
  /** SSRF protection options. */
  httpSecurity?: import('./http-security').HttpTargetValidationOptions;
}

export interface VerifyHttpRequestSignatureParams {
  method: string;
  url: string;
  body?: string;
  headers: Record<string, string>;
  maxCreatedSkewSeconds?: number;
}
