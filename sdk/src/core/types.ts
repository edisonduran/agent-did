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
  id: string; // e.g., "did:webvh:...#key-1"
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

/**
 * Relationships a document created by the SDK can list the agent key under, besides `authentication` and
 * `assertionMethod` (see `CreateAgentParams.additionalVerificationRelationships`, RFC-001 §6.2.1.3).
 */
export type AdditionalVerificationRelationship = 'capabilityDelegation' | 'capabilityInvocation';

/**
 * Kinds of signed artifact whose required verification relationship RFC-001 §6.2.1.3 fixes:
 * `assertion` (signed payloads, receipts, attestations and other claims), `http_request` (HTTP message
 * signatures), `delegation` (issuing a delegation of authority), `invocation` (exercising a delegated
 * capability) and `authentication` (proving control of the DID, e.g. in a challenge).
 */
export type SignedArtifactKind = 'assertion' | 'http_request' | 'delegation' | 'invocation' | 'authentication';

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
  /**
   * Optional. When omitted, the local `agents.local` profile is used and a
   * bootstrap controller with a random key is registered (see `CreateAgentResult.controllerPrivateKey`).
   * When provided, `controllerDid` must be published by its owner; the SDK does not fabricate it.
   */
  webvh?: CreateDidWebvhOptions;
  /**
   * Relationships to list the agent key under besides `authentication` and `assertionMethod`
   * (RFC-001 §6.2.1.3): `capabilityDelegation` for an agent that issues delegations of authority,
   * `capabilityInvocation` for one that exercises capabilities delegated to it. Duplicates are ignored and
   * any other value throws `TypeError`. Omitted or empty, the document is the same as in earlier releases.
   * Key rotation carries these relationships over to the new key.
   */
  additionalVerificationRelationships?: AdditionalVerificationRelationship[];
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
  /** Request body; bytes are hashed as they are, a string as UTF-8. */
  body?: string | Uint8Array;
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
  /** Request body; bytes are hashed as they are, a string as UTF-8. */
  body?: string | Uint8Array;
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

/**
 * Why a key was not authorized at the stated time (RFC-001 §6.2.2):
 * - `invalid_stated_time`: the stated time is not an RFC 3339 date-time.
 * - `did_not_yet_created`: the stated time is before the first entry of the DID log.
 * - `did_deactivated`: the DID was already deactivated at the stated time.
 * - `key_not_found`: the DID document at the stated time has no such key (or it has no public key).
 * - `key_deactivated`: the key was already deactivated at the stated time.
 * - `key_purpose_violation`: the key was not listed under the required relationship at the stated time.
 */
export type KeyAtTimeRejection =
  | 'invalid_stated_time'
  | 'did_not_yet_created'
  | 'did_deactivated'
  | 'key_not_found'
  | 'key_deactivated'
  | 'key_purpose_violation';

/**
 * Why a key check at a stated time could not be decided (RFC-001 §6.2.2). The stated time is asserted by the
 * signer, so it cannot place a signature on either side of a later change:
 * - `key_retired_after_stated_time`: the key was authorized at the stated time, but a later log entry retires
 *   it (removed, deactivated or moved out of the required relationship) and no trusted time evidence places
 *   the signature before that entry.
 * - `did_deactivated_after_stated_time`: same, for a later deactivation of the DID.
 * - `history_unavailable`: no verified did:webvh log is available for the DID, so its state at the stated
 *   time cannot be established.
 */
export type KeyAtTimeUncertainty =
  | 'key_retired_after_stated_time'
  | 'did_deactivated_after_stated_time'
  | 'history_unavailable';

/**
 * Result of a key check at a stated time. `authorized` means the key was authorized at the stated time and,
 * either nothing later retires it (`basis: 'no_later_change'`), or trusted time evidence places the signature
 * before the first entry that does (`basis: 'time_evidence'`). Treat `indeterminate` as not accepted.
 */
export type KeyAtTimeResult =
  | {
      status: 'authorized';
      keyId: string;
      publicKeyMultibase: string;
      /** The log version in effect at the stated time. */
      versionId: string;
      basis: 'no_later_change' | 'time_evidence';
    }
  | {
      status: 'not_authorized';
      keyId: string;
      reason: KeyAtTimeRejection;
      /** Relationships listing the key at the stated time (empty when it was not there). */
      foundIn: VerificationRelationship[];
    }
  | {
      status: 'indeterminate';
      keyId: string;
      reason: KeyAtTimeUncertainty;
      /** The key at the stated time, when it was authorized then. */
      publicKeyMultibase?: string;
      /** The first log entry that retires the key or deactivates the DID, when there is one. */
      boundaryVersionId?: string;
      /** When the key stopped being authorized (log `versionTime` or the key's `deactivated`). */
      boundaryTime?: string;
    };

export interface CheckKeyAtTimeOptions {
  /** Verification method id, e.g. `did:webvh:...#key-1`. */
  keyId: string;
  /** The signing time the artifact states (RFC 3339). It is asserted by the signer, not trusted. */
  statedTime: string;
  /** Defaults to `REQUIRED_RELATIONSHIP_BY_ARTIFACT.assertion` (`assertionMethod`). */
  requiredPurpose?: VerificationRelationship;
  /** When set, the log must belong to this DID. */
  did?: string;
  /**
   * Trusted evidence (for example a verified RFC 3161 timestamp) that the signature existed no later than this
   * time (RFC 3339). Only the caller can vouch for it; the SDK does not verify timestamp tokens. Without it, a
   * key retired after the stated time is never `authorized`.
   */
  trustedTimeNotAfter?: string;
}

export type VerifySignatureAtTimeOptions = Omit<CheckKeyAtTimeOptions, 'keyId' | 'did'>;

/**
 * Result of `verifySignatureAtTime`. `valid` only when the signature verifies and the key was authorized at
 * the stated time. Treat `indeterminate` as not accepted.
 * - `did_resolution_failed`: the stored did:webvh log failed verification.
 * - `key_not_authorized`: the key was not authorized at the stated time (see `key.reason`).
 * - `signature_invalid`: the signature does not verify with the key.
 */
export type VerifySignatureAtTimeResult =
  | { status: 'valid'; key: Extract<KeyAtTimeResult, { status: 'authorized' }> }
  | {
      status: 'invalid';
      reason: 'did_resolution_failed' | 'key_not_authorized' | 'signature_invalid';
      key?: KeyAtTimeResult;
    }
  | { status: 'indeterminate'; key: Extract<KeyAtTimeResult, { status: 'indeterminate' }> };
