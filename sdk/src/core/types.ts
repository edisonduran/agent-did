/**
 * Core types for the Agent-DID Specification (RFC-001)
 */

export interface AgentMetadata {
  name: string;
  description?: string;
  version: string;
  /**
   * Optional commitment to the base model (RFC-001 §4.3): an assertion by the controller, not evidence of
   * what the agent runs.
   */
  coreModelHash?: string;
  /** Optional commitment to the system prompt (RFC-001 §4.3): an assertion by the controller. */
  systemPromptHash?: string;
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
  type: string; // "Multikey" (emitted) or "Ed25519VerificationKey2020" (accepted on read) for Ed25519 keys
  controller: string; // DID of the creator/owner
  publicKeyMultibase?: string;
  blockchainAccountId?: string; // For EVM/Smart Account compatibility (ERC-4337)
  deactivated?: string; // ISO 8601 timestamp when the key was rotated out
  /**
   * ISO 8601 timestamp of an emergency revocation (`https://w3id.org/security#revoked`). A revoked key also has
   * `deactivated` and is never authorized, whatever time a signature states (composition contract scenario 3d).
   */
  revoked?: string;
}

/**
 * Inline JSON-LD context term a document adds after its context URLs when one of its keys carries `revoked`:
 * the published `https://agent-did.org/v1` context is immutable and does not define it.
 */
export interface RevokedContextTerm {
  revoked: { '@id': 'https://w3id.org/security#revoked'; '@type': 'http://www.w3.org/2001/XMLSchema#dateTime' };
}

/** An entry of a document's `@context`: a context URL, or the inline `revoked` term. */
export type AgentDidContextEntry = string | RevokedContextTerm;

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
  /**
   * Witnesses (ADR-007): `threshold` of these `did:key` DIDs must approve the genesis entry and every later entry
   * before it is published. The client obtains the approvals with `AgentDidClientOptions.collectWitnessProofs`.
   */
  witness?: import('../webvh/adapter').DidWebvhWitnessConfig;
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

/** A relationship a key added with `addVerificationMethod` can be listed under (never `keyAgreement`). */
export type AddedKeyRelationship = SigningVerificationPurpose;

export interface AddVerificationMethodOptions extends DidWebvhLifecycleOptions {
  /**
   * Signer that holds the new key (for example a KMS or HSM key). Its public key becomes the new verification
   * method and no private key reaches the SDK: `agentPrivateKey` in the result is an empty string. Without it the
   * SDK generates a local key and returns it.
   */
  signer?: import('./signer').AgentSigner;
  /**
   * Relationships to list the new key under. Defaults to `['capabilityInvocation']`: a key that can endorse the
   * agents it controls (RFC-001 §6.6 item 7) without signing in any other role.
   */
  relationships?: AddedKeyRelationship[];
}

export interface AddVerificationMethodResult {
  document: AgentDIDDocument;
  verificationMethodId: string;
  /** Empty when `signer` was given. */
  agentPrivateKey: string;
  /**
   * The external signer given for the agent key (`signer`), when one was: the private key never left it and
   * `agentPrivateKey` is empty. Integrations sign with it. It lives only in this process and is not serialized.
   */
  signer?: import('./signer').AgentSigner;
}

export interface RotateVerificationMethodOptions extends DidWebvhLifecycleOptions {
  /**
   * Signer that holds the new agent key (for example a KMS or HSM key). Its public key becomes the new
   * verification method and the private key never reaches the SDK: `agentPrivateKey` in the result is an
   * empty string. Without it the SDK generates a local key and returns it.
   */
  signer?: import('./signer').AgentSigner;
  /**
   * Emergency rotation (the old keys may be compromised): every retired key also gets `revoked`, so no signature
   * under it is accepted again, whatever time it states. Default `false`: a planned rotation.
   */
  emergency?: boolean;
}

export interface RetireVerificationMethodOptions extends DidWebvhLifecycleOptions {
  /**
   * Emergency revocation (the key may be compromised): the key also gets `revoked` and no signature under it is
   * accepted again, whatever time it states. An already retired key can still be revoked this way. Default
   * `false`: a planned retirement.
   */
  emergency?: boolean;
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

/**
 * Why a signed Agent Card or a request checked against one was rejected (composition contract §5). The first four
 * are the cross-stack floor (§5.1); the others are verifier-side reasons (§5.2) plus `request_rejected`:
 * - `rotation_window_closed`: the key was retired by its controller (planned retirement); the overlap is over.
 * - `emergency_revoked`: the key carries `revoked`.
 * - `key_purpose_violation`: the key is a key of the DID, active, but not an `assertionMethod` key.
 * - `tampered`: the signature does not verify under the key, or the key is not a key of the DID.
 * - `card_keyid_mismatch`: the request was signed by a DID or key the card does not publish.
 * - `format_drift`: the card is not a JSON object with Agent-DID JWS signatures (see `parseSignedAgentCard`).
 * - `did_document_unresolvable`: the agent DID has no active verification chain (unknown, deactivated, unbound
 *   controller or the resolver failed).
 * - `request_rejected`: the HTTP signature failed a check the contract does not name; `httpReason` says which.
 */
export type IdentityCompositionRejection =
  | IdentityCompositionErrorReason
  | 'card_keyid_mismatch'
  | 'format_drift'
  | 'did_document_unresolvable'
  | 'request_rejected';

/** Result of `verifyAgentCard`. Test `result.ok`. */
export type VerifyAgentCardResult =
  | {
      ok: true;
      /** The agent DID of the card. */
      did: string;
      /** Keys the card publishes: signature `kid`s, then the Agent-DID extension `keyIds`. */
      publishedKeyIds: string[];
    }
  | {
      ok: false;
      reason: IdentityCompositionRejection;
      /** The signature `kid` that failed, when one did. */
      keyId?: string;
    };

export interface VerifyIdentityCompositionParams extends VerifyHttpRequestSignatureParams {
  /** The Agent Card of the agent that signed the request, as fetched (a parsed JSON value). */
  agentCard: unknown;
}

/** Result of `verifyIdentityComposition`. Test `result.ok`. */
export type VerifyIdentityCompositionResult =
  | {
      ok: true;
      did: string;
      keyId: string;
      controllers: string[];
      publishedKeyIds: string[];
    }
  | {
      ok: false;
      reason: IdentityCompositionRejection;
      /** Which check failed: the card's own signatures, or the request against the card. */
      stage: 'agent_card' | 'request';
      /** The HTTP verifier's reason, when the request failed there. */
      httpReason?: HttpSignatureRejection;
      keyId?: string;
    };

/**
 * An entry of a verification relationship in a DID Core document: a reference to a `verificationMethod` (absolute
 * DID URL, or relative such as `#key-1`, read against the document `id`) or a method embedded in the relationship.
 */
export type VerificationRelationshipEntry = string | VerificationMethod;

/**
 * A DID Core document as this SDK reads a controller (RFC-001 §4.2.1): a did:webvh controller does not need the
 * Agent-DID members (`agentMetadata`, `created`, `updated`). Only the members the SDK uses are typed; a document may
 * carry others. `AgentDIDDocument` is the agent profile of it.
 */
export interface DidDocument {
  "@context"?: unknown;
  id: string;
  controller?: string | string[];
  verificationMethod?: VerificationMethod[];
  authentication?: VerificationRelationshipEntry[];
  assertionMethod?: VerificationRelationshipEntry[];
  capabilityDelegation?: VerificationRelationshipEntry[];
  capabilityInvocation?: VerificationRelationshipEntry[];
  keyAgreement?: VerificationRelationshipEntry[];
}

export interface AgentDIDDocument extends DidDocument {
  "@context": AgentDidContextEntry[];
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
  /**
   * The raw model name, committed to with a salted HMAC as `coreModelHash`. Optional: when omitted the
   * document carries no `coreModelHash` (RFC-001 §4.3).
   */
  coreModel?: string;
  /** The raw system prompt, committed to as `systemPromptHash`. Optional, like `coreModel`. */
  systemPrompt?: string;
  /**
   * 32-byte hex salt for the `coreModelHash` commitment. Generated randomly when omitted. Only valid
   * together with `coreModel`.
   */
  coreModelSalt?: string;
  /** 32-byte hex salt for the `systemPromptHash` commitment. Only valid together with `systemPrompt`. */
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
   * The external signer given for the agent key (`signer`), when one was: the private key never left it and
   * `agentPrivateKey` is empty. Integrations sign with it. It lives only in this process and is not serialized.
   */
  signer?: import('./signer').AgentSigner;
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
   * Set by `AgentIdentity.create()`; each salt is present only for the value (`coreModel`, `systemPrompt`)
   * that was given.
   */
  metadataCommitmentSalts?: MetadataCommitmentSalts;
}

/** Salts (32-byte hex) of an agent's metadata commitments. */
export interface MetadataCommitmentSalts {
  coreModel?: string;
  systemPrompt?: string;
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
  /** Empty when `signer` was given. */
  agentPrivateKey: string;
  /**
   * The external signer given for the agent key (`signer`), when one was: the private key never left it and
   * `agentPrivateKey` is empty. Integrations sign with it. It lives only in this process and is not serialized.
   */
  signer?: import('./signer').AgentSigner;
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
  /**
   * The verification method (`keyid`) that matches the signing key, e.g. `document.authentication[0]` or the
   * `verificationMethodId` that `rotateVerificationMethod` returned. Required: there is no default, because a
   * fixed guess names the wrong key once the agent has rotated.
   */
  verificationMethodId: string;
  /** Signature expiration window in seconds (default: 30). */
  expiresInSeconds?: number;
  /** SSRF protection options. */
  httpSecurity?: import('./http-security').HttpTargetValidationOptions;
  /**
   * A capability to invoke (RFC-001 §6.7): sent in the `Agent-DID-Capability` field and covered as
   * `"agent-did-capability";key="sig1"` after the required components. The signing key must then be a
   * `capabilityInvocation` key of `agentDid`, which must be the capability's `controller`.
   */
  capability?: AgentCapability;
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
  /**
   * Accept only these agent DIDs (the `Agent-DID` member; exact match). Checked before any resolution, so a
   * request from any other DID costs no network call. A valid signature only proves which DID signed: without
   * `allowedDids` or `allowedControllers`, any DID with a valid key passes, and authorization is the caller's job
   * (read `result.did` / `result.controllers`).
   */
  allowedDids?: readonly string[];
  /**
   * Accept only agents whose controller chain (`result.controllers`) includes one of these DIDs, for example the
   * organization that operates them. Checked after the signature verifies. When both lists are set, both apply.
   */
  allowedControllers?: readonly string[];
}

/**
 * Why `verifyHttpRequestSignatureDetailed` rejected a request. When the request carries several
 * signatures, the reason is the one of the first signature that has `tag="agent-did"` (else the
 * first signature).
 *
 * - `missing_headers`: `Signature`, `Signature-Input` or `Agent-DID` is absent.
 * - `url_not_normalized`: the request URL is not in the normalized form of RFC-001 §6.5 item 4 (see
 *   `requestUrlFormProblem`); the SDK refuses to sign such a URL too.
 * - `malformed_headers`: `Signature` / `Signature-Input` / `Agent-DID` do not parse, no signature has a matching
 *   label, or the `Agent-DID` member of the signature's label is not a String without parameters.
 * - `digest_mismatch`: `Content-Digest` is absent or is not exactly the SHA-256 of the body.
 * - `tag_mismatch`: the `tag` parameter is not `agent-did` (for example another profile's signature).
 * - `alg_unsupported`: the `alg` parameter is not `ed25519`.
 * - `params_missing`: `created`, `expires`, `nonce` or `keyid` is absent or has the wrong type, or `nonce` is not 1 to
 *   256 characters of `A-Z a-z 0-9 . _ ~ + / = -` (RFC-001 §6.5 item 3).
 * - `keyid_not_bound`: `keyid` is not a DID URL of the agent DID (the `Agent-DID` member of the signature's label):
 *   it does not start with that DID followed by `#`. A `keyid` of the agent DID that the document does not list is
 *   `keyid_not_authorized`.
 * - `components_missing`: a required covered component is absent.
 * - `components_order`: the required components are all covered but not first and in order.
 * - `created_skew`: `created` is further from now than `maxCreatedSkewSeconds`.
 * - `expires_before_created`: `expires` is earlier than `created`.
 * - `lifetime_exceeded`: `expires - created` is greater than `maxSignatureLifetimeSeconds`.
 * - `expired`: now is after `expires`.
 * - `signed_component_missing`: a covered component has no value in the request (for example no `Date`, or no
 *   `Agent-DID` member for the signature's label).
 * - `did_resolution_failed`: the agent DID has no active verification chain: unknown,
 *   revoked, deactivated, inactive controller, or the resolver failed. The SDK does not tell a
 *   resolver outage from a revocation; treat this reason as "could not establish the key".
 * - `keyid_not_authorized`: `keyid` is not an `assertionMethod` key of the DID document (a fragment
 *   the document does not have, or a key listed only under another relationship).
 * - `signature_invalid`: the signature does not verify, or the key is no longer active.
 * - `nonce_replayed`: the `(keyid, nonce)` pair was already seen.
 * - `did_not_allowed`: `allowedDids` is set and the agent DID is not in it.
 * - `controller_not_allowed`: `allowedControllers` is set and no DID of the controller chain is in it.
 */
export type HttpSignatureRejection =
  | 'missing_headers'
  | 'url_not_normalized'
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
  | 'controller_not_bound'
  | 'keyid_not_authorized'
  | 'signature_invalid'
  | 'nonce_replayed'
  | 'did_not_allowed'
  | 'controller_not_allowed';

/**
 * Result of `verifyHttpRequestSignatureDetailed`. Always test `result.ok`: the object itself is
 * truthy for a rejection too, which is why `verifyHttpRequestSignature` keeps returning a boolean.
 */
export type VerifyHttpRequestSignatureResult =
  | {
      ok: true;
      /**
       * The agent DID (the `Agent-DID` member of the accepted signature's label): who signed. A valid signature
       * does not make it authorized.
       */
      did: string;
      /** The verification method that signed (`keyid`). */
      keyId: string;
      /** The controller chain of `did`, nearest first (empty for a DID that controls itself). */
      controllers: string[];
    }
  | { ok: false; reason: HttpSignatureRejection };

/**
 * Why a key was not authorized at the stated time (RFC-001 §6.2.2):
 * - `invalid_stated_time`: the stated time is not an RFC 3339 date-time.
 * - `did_not_yet_created`: the stated time is before the first entry of the DID log.
 * - `did_deactivated`: the DID was already deactivated at the stated time.
 * - `key_not_found`: the DID document at the stated time has no such key (or it has no public key).
 * - `key_deactivated`: the key was already deactivated at the stated time.
 * - `key_purpose_violation`: the key was not listed under the required relationship at the stated time.
 * - `key_revoked`: some entry of the log marks the key `revoked` (emergency revocation): it is not authorized at
 *   any stated time, even with trusted time evidence.
 */
export type KeyAtTimeRejection =
  | 'invalid_stated_time'
  | 'did_not_yet_created'
  | 'did_deactivated'
  | 'key_not_found'
  | 'key_deactivated'
  | 'key_purpose_violation'
  | 'key_revoked';

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

/** Options of `checkDidWebvhKeyAtTime`: the log's `did-witness.json` is needed when it has witnessed entries. */
export interface CheckDidWebvhKeyAtTimeOptions extends CheckKeyAtTimeOptions {
  witnessFile?: string;
}

export type VerifySignatureAtTimeOptions = Omit<CheckKeyAtTimeOptions, 'keyId' | 'did'> & {
  /**
   * An RFC 3161 timestamp token (DER `TimeStampResp` or `TimeStampToken`) over the raw signature bytes (ADR-007). The
   * SDK verifies it against `tsaTrustAnchors` and uses `genTime + accuracy` as `trustedTimeNotAfter`; a token that does
   * not verify makes the result `invalid` (`timestamp_invalid`). Not together with `trustedTimeNotAfter`.
   */
  timestampToken?: Uint8Array;
  /** TSA trust anchors (DER bytes or PEM text) for `timestampToken`; required with it. */
  tsaTrustAnchors?: (Uint8Array | string)[];
};

/**
 * Result of `verifySignatureAtTime`. `valid` only when the signature verifies and the key was authorized at
 * the stated time. Treat `indeterminate` as not accepted.
 * - `did_resolution_failed`: the did:webvh log (or a controller's) could not be fetched or failed verification.
 * - `key_not_authorized`: the key was not authorized at the stated time (see `key.reason`).
 * - `controller_not_bound`: the controller binding does not hold now (RFC-001 §6.6 item 7).
 * - `signature_invalid`: the signature does not verify with the key.
 * - `timestamp_invalid`: the RFC 3161 `timestampToken` does not verify (ADR-007).
 */
export type VerifySignatureAtTimeResult =
  | { status: 'valid'; key: Extract<KeyAtTimeResult, { status: 'authorized' }> }
  | {
      status: 'invalid';
      reason: 'did_resolution_failed' | 'key_not_authorized' | 'controller_not_bound' | 'signature_invalid';
      key?: KeyAtTimeResult;
    }
  | {
      status: 'invalid';
      /** `timestampToken` was given and does not verify (see `timestampRejection`). */
      reason: 'timestamp_invalid';
      timestampRejection: import('../crypto/timestamp').TimestampRejection;
      /** Never set: the key is not checked when the timestamp is invalid. Kept so `result.key` reads on every member. */
      key?: undefined;
    }
  | { status: 'indeterminate'; key: Extract<KeyAtTimeResult, { status: 'indeterminate' }> };

/**
 * An `AgentMetadataCredential` (RFC-001 §4.4): a W3C VC Data Model 2.0 credential in which the controller (`issuer`)
 * states the agent's metadata (`credentialSubject.agentMetadata`), secured with a Data Integrity proof
 * (`eddsa-jcs-2022`). It is presented out of band; DID resolution never fetches it.
 */
export interface AgentMetadataCredential {
  '@context': unknown[];
  id?: string;
  type: string[];
  /** The controller DID of the agent. */
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: {
    /** The agent DID. */
    id: string;
    /** All or some of the agent's metadata, as its controller states it. */
    agentMetadata: Partial<AgentMetadata>;
  };
  proof: import('../crypto/data-integrity').DataIntegrityProof;
}

/** Parameters of `AgentDidClient.issueAgentMetadataCredential`. */
export interface IssueAgentMetadataCredentialParams {
  /** The agent the credential is about (`credentialSubject.id`). Must resolve and not be deactivated. */
  agentDid: string;
  /** Signer that holds the controller key named by `verificationMethodId` (for example a KMS or HSM key). */
  signer: import('./signer').AgentSigner;
  /** An active `assertionMethod` key of the agent's controller (the issuer), e.g. `controllerDocument.assertionMethod[0]`. */
  verificationMethodId: string;
  /**
   * The metadata to state. Defaults to the agent document's `agentMetadata`; pass a subset to share only some
   * members. The values are the controller's assertion: they are not compared with the document.
   */
  agentMetadata?: Partial<AgentMetadata>;
  /** Optional credential `id` (a URL, URN or DID URL). */
  id?: string;
  /** RFC 3339 date-time from which the credential is valid. Defaults to now. */
  validFrom?: string;
  /** RFC 3339 date-time after which the credential is no longer valid. */
  validUntil?: string;
}

/** Options of `AgentDidClient.verifyAgentMetadataCredential`. */
export interface VerifyAgentMetadataCredentialOptions {
  /** Accept only credentials about this agent DID (`credentialSubject.id`), checked before any resolution. */
  expectedAgentDid?: string;
}

/**
 * Why `verifyAgentMetadataCredential` rejected a credential (RFC-001 §4.4):
 * - `malformed_credential`: not a VC 2.0 `AgentMetadataCredential` of the Agent-DID profile (`@context`, `type`,
 *   `issuer`, `credentialSubject.id`, `credentialSubject.agentMetadata`, `validFrom` / `validUntil` dates).
 * - `unsupported_proof`: the proof is absent, is a proof set, is not `DataIntegrityProof` / `eddsa-jcs-2022` /
 *   `assertionMethod`, its `verificationMethod` is not a key of `issuer`, or its `proofValue` is malformed.
 * - `subject_mismatch`: `expectedAgentDid` is set and `credentialSubject.id` differs.
 * - `not_yet_valid`: now is before `validFrom`.
 * - `expired`: now is after `validUntil` (or after the proof's `expires`).
 * - `did_deactivated`: the agent DID is deactivated.
 * - `did_resolution_failed`: the agent DID, or its controller, could not be resolved and verified.
 * - `controller_not_bound`: the agent is not bound to its controller now (RFC-001 §6.6 item 7).
 * - `issuer_not_controller`: `issuer` is not the agent document's `controller`.
 * - `key_not_authorized`: `proof.verificationMethod` is not an active Ed25519 `assertionMethod` key of the issuer.
 * - `signature_invalid`: the proof does not verify.
 */
export type AgentMetadataCredentialRejection =
  | 'malformed_credential'
  | 'unsupported_proof'
  | 'subject_mismatch'
  | 'not_yet_valid'
  | 'expired'
  | 'did_deactivated'
  | 'did_resolution_failed'
  | 'controller_not_bound'
  | 'issuer_not_controller'
  | 'key_not_authorized'
  | 'signature_invalid';

/** Result of `verifyAgentMetadataCredential`. Test `result.ok`. */
export type VerifyAgentMetadataCredentialResult =
  | {
      ok: true;
      /** The agent DID (`credentialSubject.id`). */
      agentDid: string;
      /** The controller that issued the credential. */
      issuer: string;
      /** The key of the issuer that made the proof. */
      verificationMethod: string;
      /** The metadata the controller states. An assertion of the controller, not evidence of what the agent runs. */
      agentMetadata: Partial<AgentMetadata>;
      /** The controller chain of the agent, nearest first (empty for an agent that controls itself). */
      controllers: string[];
    }
  | { ok: false; reason: AgentMetadataCredentialRejection };

/** JWS `alg` of an Ed25519 signature: `EdDSA` (RFC 8037) or `Ed25519` (RFC 9864). Both mean an Ed25519 key only. */
export type JwsEd25519Alg = 'EdDSA' | 'Ed25519';

/** The `eddsa-jcs-2022` proof of a delegated capability (RFC-001 §6.7). */
export interface CapabilityDelegationProof {
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  /** When the delegation was signed (RFC 3339). Asserted by the delegator; keys are checked at verification time. */
  created: string;
  /** DID URL of a `capabilityDelegation` key of the delegator (the parent's `controller`, or a root controller). */
  verificationMethod: string;
  proofPurpose: 'capabilityDelegation';
  /** Ancestor ids from the root; the last entry is the full parent capability when the parent is not the root. */
  capabilityChain: Array<string | AgentCapability>;
  proofValue: string;
}

/**
 * A delegated capability (RFC-001 §6.7, ADR-008 D-12a), shaped as an Authorization Capability (ZCAP v0.4 data
 * model): the delegator grants `controller` the authority to act on `invocationTarget` until `expires`.
 */
export interface AgentCapability {
  '@context': string[];
  /** `urn:uuid:` + a lowercase UUID. */
  id: string;
  /** The parent capability's `id` (`urn:zcap:root:…` for a delegation from the root). */
  parentCapability: string;
  /** An `https` URL in normalized form (RFC-001 §6.5 item 4), without a query. */
  invocationTarget: string;
  /** The delegate: the DID that may invoke the capability or delegate it further. */
  controller: string;
  /** Actions allowed (HTTP methods for an HTTP target). Absent: every action the parent allows. */
  allowedAction?: string[];
  /** RFC 3339; never later than the parent's. */
  expires: string;
  proof: CapabilityDelegationProof;
}

/**
 * Why a capability chain was rejected (RFC-001 §6.7), in the order the checks run:
 *
 * - `malformed_capability`: a capability or the chain structure does not have the form of §6.7.
 * - `unsupported_proof`: a proof is not one `eddsa-jcs-2022` `capabilityDelegation` proof of that form.
 * - `chain_too_long`: more delegated capabilities than `maxChainLength`.
 * - `root_controller_unknown`: the verifier configured no root controller for the root's target.
 * - `attenuation_violation`: a capability widens its parent's target, actions or expiry.
 * - `expired`: a capability in the chain is past its `expires`.
 * - `delegator_mismatch`: a proof is not by the parent's `controller` (or a root controller).
 * - `did_resolution_failed` / `did_deactivated`: a delegator DID does not resolve, or is deactivated.
 * - `key_purpose_violation`: the proof key is an active key of the delegator, not under `capabilityDelegation`.
 * - `key_not_authorized`: the proof key is not an active Ed25519 key of the delegator.
 * - `signature_invalid`: a proof does not verify.
 */
export type CapabilityRejection =
  | 'malformed_capability'
  | 'unsupported_proof'
  | 'chain_too_long'
  | 'root_controller_unknown'
  | 'attenuation_violation'
  | 'expired'
  | 'delegator_mismatch'
  | 'did_resolution_failed'
  | 'did_deactivated'
  | 'key_purpose_violation'
  | 'key_not_authorized'
  | 'signature_invalid';

/** Options of `verifyCapabilityChain`. */
export interface VerifyCapabilityChainOptions {
  /**
   * Who may delegate each target: root target URL (exact, normalized) -> DIDs. The resource server decides; a chain
   * whose root target is not a key here is `root_controller_unknown`.
   */
  rootControllers: Readonly<Record<string, readonly string[]>>;
  /** Delegated capabilities accepted after the root (default 5, at most 10). */
  maxChainLength?: number;
}

/** Result of `verifyCapabilityChain`. Test `result.ok`. */
export type VerifyCapabilityChainResult =
  | {
      ok: true;
      /** The verified capability (the leaf). */
      capability: AgentCapability;
      /** The DID that may invoke it (`capability.controller`). */
      controller: string;
      invocationTarget: string;
      /** The actions the chain allows (absent: every action). */
      allowedAction?: string[];
      /** The root capability `id`. */
      rootId: string;
      /** Who signed each link, from the root controller to the leaf's delegator. */
      delegators: string[];
    }
  | { ok: false; reason: CapabilityRejection; capabilityId?: string };

/** Parameters of `createCapability`. */
export interface CreateCapabilityParams {
  /** The target; within the parent's target (or the root target when there is no parent). */
  invocationTarget: string;
  /** The delegate DID. */
  controller: string;
  /** RFC 3339; not later than the parent's `expires`. */
  expires: string;
  /** Actions; a subset of the parent's. Absent: every action the parent allows. */
  allowedAction?: readonly string[];
  /**
   * The capability being delegated further, held by the signer's DID (its `controller`). Absent: a delegation from
   * the root of `rootTarget`, signed by a root controller.
   */
  parentCapability?: AgentCapability;
  /** The root target, for a delegation from the root (default: `invocationTarget`). */
  rootTarget?: string;
  /** DID URL of an active Ed25519 `capabilityDelegation` key of the delegator, held by `signer`. */
  verificationMethodId: string;
  signer: import('./signer').AgentSigner;
  /** `urn:uuid:…` (default: a random UUID). */
  id?: string;
}

/**
 * Why `verifyHttpCapabilityInvocation` rejected a request: the reasons of `verifyHttpRequestSignatureDetailed`, the
 * reasons of `verifyCapabilityChain`, and:
 *
 * - `capability_missing`: the signature does not cover `"agent-did-capability";key="<label>"`, or the field has no
 *   member for the label.
 * - `capability_too_large`: the `Agent-DID-Capability` field is longer than 8192 bytes.
 * - `invoker_not_controller`: the request's agent DID is not the capability's `controller`.
 * - `target_mismatch`: the request URL (without its query) is not the target nor within it.
 * - `action_not_allowed`: the request method is not in the chain's `allowedAction`.
 */
export type CapabilityInvocationRejection =
  | HttpSignatureRejection
  | CapabilityRejection
  | 'capability_missing'
  | 'capability_too_large'
  | 'invoker_not_controller'
  | 'target_mismatch'
  | 'action_not_allowed';

/** Parameters of `verifyHttpCapabilityInvocation`. */
export interface VerifyHttpCapabilityInvocationParams
  extends VerifyHttpRequestSignatureParams,
    VerifyCapabilityChainOptions {}

/** Result of `verifyHttpCapabilityInvocation`. Test `result.ok`. */
export type VerifyHttpCapabilityInvocationResult =
  | {
      ok: true;
      /** The invoking agent DID. */
      did: string;
      /** Its `capabilityInvocation` key that signed. */
      keyId: string;
      /** The controller chain of `did`, nearest first. */
      controllers: string[];
      /** The verified capability (the leaf). */
      capability: AgentCapability;
      /** The actions the chain allows (absent: every action). */
      allowedAction?: string[];
      rootId: string;
      delegators: string[];
    }
  | { ok: false; reason: CapabilityInvocationRejection; capabilityId?: string };

/**
 * Why `verifyClientAssertion` rejected a JWT client assertion (RFC-001 §6.8), in the order the checks run:
 * `malformed_assertion`, `alg_unsupported`, `type_invalid`, `kid_not_bound` (the `kid` is not a DID URL of the
 * expected DID), `client_id_mismatch` (`iss` or `sub`), `audience_invalid` (`aud` is not exactly the issuer, as a
 * single string), `lifetime_exceeded`, `not_yet_valid`, `expired`, `did_resolution_failed`, `controller_not_bound`,
 * `key_not_authorized` (not an active Ed25519 `authentication` key), `signature_invalid`, `jti_replayed`.
 */
export type ClientAssertionRejection =
  | 'malformed_assertion'
  | 'alg_unsupported'
  | 'type_invalid'
  | 'kid_not_bound'
  | 'client_id_mismatch'
  | 'audience_invalid'
  | 'lifetime_exceeded'
  | 'not_yet_valid'
  | 'expired'
  | 'did_resolution_failed'
  | 'controller_not_bound'
  | 'key_not_authorized'
  | 'signature_invalid'
  | 'jti_replayed';

/** Parameters of `verifyClientAssertion`. */
export interface VerifyClientAssertionParams {
  assertion: string;
  /** This authorization server's issuer identifier: the only `aud` value accepted. */
  issuer: string;
  /** The `client_id` of the token request: `iss` and `sub` must equal it. */
  clientId: string;
  /** The agent DID registered for `clientId` (for example a document's `agent_did`, after checking it). */
  did: string;
  /** Clock skew allowed on `iat`, `nbf` and `exp`, in seconds (default 30). */
  maxClockSkewSeconds?: number;
  /** Replay store for `jti` (default: the client's nonce store). */
  nonceStore?: import('./nonce-store').NonceStore;
}

/** Result of `verifyClientAssertion`. Test `result.ok`. */
export type VerifyClientAssertionResult =
  | { ok: true; did: string; keyId: string; clientId: string; jti: string; expiresAt: number; controllers: string[] }
  | { ok: false; reason: ClientAssertionRejection };
