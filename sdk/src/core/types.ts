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
  id: string; // e.g., "did:agent:0x...#key-1" or "did:webvh:...#key-1"
  type: string; // e.g., "Ed25519VerificationKey2020" or "EcdsaSecp256k1RecoveryMethod2020"
  controller: string; // DID of the creator/owner
  publicKeyMultibase?: string;
  blockchainAccountId?: string; // For EVM/Smart Account compatibility (ERC-4337)
  deactivated?: string; // ISO 8601 timestamp when the key was rotated out
}

export interface CreateDidWebvhOptions {
  /** Lowercase ASCII fully qualified host name, optionally with `:port`. */
  domain: string;
  /** The controller's DID, published by its owner. `'{DID}'` makes the new DID self-controlled. */
  controllerDid: string;
  /**
   * The controller's key. It is the did:webvh log's only `updateKeys` entry and signs every
   * log entry (create, update, rotate, revoke). Use a KMS/HSM-backed `AgentSigner` in production.
   */
  controllerSigner: import('./signer').AgentSigner;
  pathSegments?: string[];
  /**
   * Pre-rotation: public keys (Ed25519 multikeys) that will sign the DID's NEXT log entry. Only their
   * hashes go into the log (`nextKeyHashes`). From then on the key in `controllerSigner` can no longer sign
   * log entries: a compromised controller key cannot rotate or deactivate the DID, and the holder of one of
   * these keys can. Keep their private keys offline. Rotate with `rotateControllerKey`.
   */
  nextUpdateKeys?: string[];
}

/** Options of `AgentDidClient.rotateControllerKey`. */
export interface RotateControllerKeyOptions {
  /** The key that becomes the DID's active `updateKeys` entry. With pre-rotation active it must be a committed key and it signs the entry. */
  newControllerSigner: import('./signer').AgentSigner;
  /**
   * Public keys (Ed25519 multikeys) for the pre-rotation commitment of the NEXT entry. Omitted: the
   * commitments in force stay as they are, so the key you just rotated to stays the only valid next key.
   * An empty array ends pre-rotation. Must not include `newControllerSigner`'s key.
   */
  nextUpdateKeys?: string[];
  /** Signer of the current `updateKeys`, when pre-rotation is NOT active (otherwise `newControllerSigner` signs). Defaults to the signer retained in this process. */
  controllerSigner?: import('./signer').AgentSigner;
}

/** The controller keys of a did:webvh DID, from its verified log. */
export interface DidWebvhControllerKeys {
  /** Keys that may sign the next entry (when `nextKeyHashes` is empty) or that signed the last one. */
  updateKeys: string[];
  /** Pre-rotation commitments in force. While non-empty, only a key with one of these hashes can sign the next entry. */
  nextKeyHashes: string[];
}

/** Options for lifecycle operations that append to a did:webvh log. */
export interface DidWebvhLifecycleOptions {
  /**
   * The controller signer for the DID's `updateKeys`. Required for DIDs imported into this
   * process; defaults to the signer retained when the DID was created in this process.
   */
  controllerSigner?: import('./signer').AgentSigner;
}

export type VerificationRelationship =
  | 'authentication'
  | 'assertionMethod'
  | 'capabilityDelegation'
  | 'capabilityInvocation'
  | 'keyAgreement';

export type SigningVerificationPurpose = Exclude<VerificationRelationship, 'keyAgreement'>;

export type IdentityCompositionErrorReason =
  | 'key_purpose_violation'
  | 'rotation_window_closed'
  | 'emergency_revoked'
  | 'tampered';

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
  assertionMethod?: string[]; // Keys allowed to sign assertions/messages
  capabilityDelegation?: string[]; // Keys allowed to issue delegations
  capabilityInvocation?: string[]; // Keys allowed to invoke delegated capabilities
  keyAgreement?: string[]; // Keys allowed only for agreement/encryption, not signing
}

/**
 * Input parameters required to create a new Agent-DID
 */
export interface CreateAgentParams {
  name: string;
  description?: string;
  version?: string; // Defaults to "1.0.0"
  coreModel: string; // The raw model name/string (committed to with a salted HMAC by the SDK)
  systemPrompt: string; // The raw prompt string (committed to with a salted HMAC by the SDK)
  /** 32-byte hex salt for the `coreModelHash` commitment. Generated randomly when omitted. */
  coreModelSalt?: string;
  /** 32-byte hex salt for the `systemPromptHash` commitment. Generated randomly when omitted. */
  systemPromptSalt?: string;
  capabilities?: string[];
  memberOf?: string;
  /** Optional external signer. When omitted, a local Ed25519 key is generated (demo mode). */
  signer?: import('./signer').AgentSigner;
  /** DID emission profile. Defaults to the canonical `did:webvh` profile. */
  didMethod?: 'agent' | 'webvh';
  /**
   * Optional when `didMethod` is `webvh`. When omitted, the local `agents.local` profile is used and a
   * bootstrap controller with a random key is registered (see `CreateAgentResult.controllerPrivateKey`).
   * When provided, `controllerDid` must be published by its owner; the SDK does not fabricate it.
   */
  webvh?: CreateDidWebvhOptions;
}

/**
 * The result of creating a new Agent-DID
 */
export interface CreateAgentResult {
  document: AgentDIDDocument;
  /** The Ed25519 private key (hex) — present only in demo mode (no external signer). */
  agentPrivateKey: string;
  /**
   * Ed25519 private key (hex) of the local bootstrap controller. Present only when this call
   * created the bootstrap controller document (implicit `did:webvh` profile, controller not yet
   * registered). It is randomly generated and returned only once; store it securely or discard it.
   */
  controllerPrivateKey?: string;
  /**
   * Salts of the `coreModelHash` and `systemPromptHash` commitments (`hash://hmac-sha256/`).
   * Keep them private; reveal a salt together with its value only to a party that should be
   * able to verify it (see `verifyMetadataCommitment`). They are not stored anywhere else.
   * Always set by `AgentIdentity.create()`; absent only when a result is built by hand.
   */
  metadataCommitmentSalts?: MetadataCommitmentSalts;
}

/** Salts (32-byte hex) of an agent's metadata commitments. */
export interface MetadataCommitmentSalts {
  coreModel: string;
  systemPrompt: string;
}

/**
 * Parameters to evolve an existing Agent-DID document while preserving DID.
 */
export interface UpdateAgentDocumentParams {
  description?: string;
  version?: string;
  coreModel?: string;
  /** Required when `coreModel` is set: 32-byte hex salt for the new commitment (see `generateCommitmentSalt`). */
  coreModelSalt?: string;
  systemPrompt?: string;
  /** Required when `systemPrompt` is set: 32-byte hex salt for the new commitment (see `generateCommitmentSalt`). */
  systemPromptSalt?: string;
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
  /** Maximum distance between `created` and now, in seconds (default: 300). */
  maxCreatedSkewSeconds?: number;
  /** Maximum lifetime of a signature (`expires - created`), in seconds (default: 300). */
  maxSignatureLifetimeSeconds?: number;
  /**
   * Replay store for the signature's `nonce`. Defaults to a process-wide `InMemoryNonceStore`;
   * use a shared store when several verifier instances serve the same agents.
   */
  nonceStore?: import('./nonce-store').NonceStore;
}

/**
 * Why `verifyHttpRequestSignatureDetailed` rejected a request. When the request carries several
 * signatures, the reason is the one of the first signature that has `tag="agent-did"` (else the
 * first signature).
 *
 * - `missing_headers`: `Signature`, `Signature-Input` or `Signature-Agent` is absent.
 * - `malformed_headers`: `Signature` / `Signature-Input` do not parse, or no signature has a matching label.
 * - `digest_mismatch`: `Content-Digest` is absent or is not exactly the SHA-256 of the body.
 * - `tag_mismatch`: the `tag` parameter is not `agent-did` (for example another profile's signature).
 * - `alg_unsupported`: the `alg` parameter is not `ed25519`.
 * - `params_missing`: `created`, `expires`, `nonce` or `keyid` is absent or has the wrong type.
 * - `keyid_not_bound`: `keyid` is not a key of the `Signature-Agent` DID.
 * - `components_missing`: a required covered component is absent.
 * - `components_order`: the required components are all covered but not first and in order.
 * - `created_skew`: `created` is further from now than `maxCreatedSkewSeconds`.
 * - `expires_before_created`: `expires` is earlier than `created`.
 * - `lifetime_exceeded`: `expires - created` is greater than `maxSignatureLifetimeSeconds`.
 * - `expired`: now is after `expires`.
 * - `signed_component_missing`: a covered component has no value in the request (for example no `Date`).
 * - `did_resolution_failed`: the `Signature-Agent` DID has no active verification chain: unknown,
 *   revoked, deactivated, inactive controller, or the resolver failed. The SDK does not tell a
 *   resolver outage from a revocation; treat this reason as "could not establish the key".
 * - `keyid_not_authorized`: `keyid` is not an `assertionMethod` key of the DID document (a fragment
 *   the document does not have, or a key listed only under another relationship).
 * - `signature_invalid`: the signature does not verify, or the key is no longer active.
 * - `nonce_replayed`: the `(keyid, nonce)` pair was already seen.
 */
export type HttpSignatureRejection =
  | 'missing_headers'
  | 'malformed_headers'
  | 'digest_mismatch'
  | 'tag_mismatch'
  | 'alg_unsupported'
  | 'params_missing'
  | 'keyid_not_bound'
  | 'components_missing'
  | 'components_order'
  | 'created_skew'
  | 'expires_before_created'
  | 'lifetime_exceeded'
  | 'expired'
  | 'signed_component_missing'
  | 'did_resolution_failed'
  | 'keyid_not_authorized'
  | 'signature_invalid'
  | 'nonce_replayed';

/**
 * Result of `verifyHttpRequestSignatureDetailed`. Always test `result.ok`: the object itself is
 * truthy for a rejection too, which is why `verifyHttpRequestSignature` keeps returning a boolean.
 */
export type VerifyHttpRequestSignatureResult =
  | { ok: true }
  | { ok: false; reason: HttpSignatureRejection };
