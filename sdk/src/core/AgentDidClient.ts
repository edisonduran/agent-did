import {
  AddVerificationMethodOptions,
  AddVerificationMethodResult,
  AgentDocumentHistoryAction,
  AgentDocumentHistoryEntry,
  AgentDIDDocument,
  AgentMetadata,
  AgentMetadataCredential,
  AgentCapability,
  CapabilityInvocationRejection,
  CapabilityRejection,
  CreateAgentParams,
  CreateCapabilityParams,
  CreateAgentResult,
  DidDocument,
  DidWebvhControllerKeys,
  DidWebvhLifecycleOptions,
  IdentityCompositionRejection,
  IssueAgentMetadataCredentialParams,
  MetadataCommitmentSalts,
  RotateControllerKeyOptions,
  RetireVerificationMethodOptions,
  RotateVerificationMethodOptions,
  RotateVerificationMethodResult,
  UpdateAgentDocumentParams,
  VerifyAgentMetadataCredentialOptions,
  VerifyAgentCardResult,
  VerifyAgentMetadataCredentialResult,
  VerifyCapabilityChainOptions,
  VerifyCapabilityChainResult,
  VerifyClientAssertionParams,
  VerifyClientAssertionResult,
  VerifyHttpCapabilityInvocationParams,
  VerifyHttpCapabilityInvocationResult,
  VerifyHttpRequestSignatureParams,
  VerifyHttpRequestSignatureResult,
  VerifyIdentityCompositionParams,
  VerifyIdentityCompositionResult,
  VerifySignatureAtTimeOptions,
  VerifySignatureAtTimeResult,
  VerificationRelationship
} from './types';
import { createMetadataCommitment, generateCommitmentSalt } from '../crypto/hash';
import { didKeyFromPublicKey } from '../crypto/multibase';
import { AgentSigner, LocalKeySigner } from './signer';
import { InMemoryNonceStore, NonceStore } from './nonce-store';
import { DIDDocumentSource, DIDResolver, DidWebvhState, ResolutionLimits, ResolverResolutionEvent } from '../resolver/types';
import { InMemoryDIDResolver } from '../resolver/InMemoryDIDResolver';
import { UniversalResolverClient } from '../resolver/UniversalResolverClient';
import { HttpDIDDocumentSource } from '../resolver/HttpDIDDocumentSource';
import { JsonRpcDIDDocumentSource } from '../resolver/JsonRpcDIDDocumentSource';
import { WebvhDIDDocumentSource } from '../resolver/WebvhDIDDocumentSource';
import { AgentRegistry } from '../registry/types';
import {
  compareDidWebvhLogs,
  createDidWebvhLog,
  didWebvhLastEntrySigners,
  DidWebvhError,
  deactivateDidWebvhLog,
  DidWebvhLogResult,
  DidWebvhWitnessCollector,
  DidWebvhWitnessConfig,
  didWebvhUpdateKeyFor,
  resolveDidWebvhLog,
  updateDidWebvhLog
} from '../webvh/adapter';
import {
  additionalRelationshipEntries,
  buildAgentDocumentTemplate,
  buildBootstrapControllerTemplate,
  cloneDocument,
  computeDocumentReference,
  historyFromDidWebvhLog,
  normalizeDidPathSegment
} from '../webvh/documents';
import {
  assertUpdatePatch,
  buildAddedKeyDocument,
  buildRetiredKeyDocument,
  buildRotatedDocument,
  buildUpdatedDocument,
  nextDocumentTimestamp
} from '../lifecycle/documents';
import { verifyWithActiveKeys } from '../verification/signature';
import { checkDidWebvhKeyAtTime, parseRfc3339Millis, signatureResultForKey } from '../verification/key-at-time';
import { verifyTimestampToken } from '../crypto/timestamp';
import { decodeSignatureHex } from '../crypto/ed25519-verify';
import {
  SignatureCheck,
  SignatureCheckOutcome,
  verifyAgentDidHttpRequest,
  verifyAgentDidHttpRequestWith
} from '../http-signatures/verify-request';
import {
  compositionReasonForKey,
  DID_VERIFICATION_RELATIONSHIPS,
  IdentityCompositionError,
  REQUIRED_RELATIONSHIP_BY_ARTIFACT
} from './identity-composition';
import { InMemoryAgentRegistry } from '../registry/InMemoryAgentRegistry';
import { normalizeTimestampToIso } from './time';
import { messageSigningInput } from './message-signing';
import { assertBoundToController, ControllerBindingError } from './controller-binding';
import { agentDidDocumentProblem, assertAgentDidDocument, assertDidDocument } from './document-guard';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import {
  createEddsaJcs2022Proof,
  DATA_INTEGRITY_PROOF_TYPE,
  EDDSA_JCS_2022_CRYPTOSUITE,
  eddsaJcs2022HashData,
  encodeEddsaProofValue,
  verifyEddsaJcs2022Proof
} from '../crypto/data-integrity';
import { activeEd25519PublicKey, relationshipMethods } from './verification-method';
import { didOfKeyId, parseSignedAgentCard } from './agent-card';
import {
  actionAllowed,
  AGENT_DID_CAPABILITY_HTTP_HEADER,
  buildUnsignedCapability,
  CAPABILITY_DELEGATION_PURPOSE,
  capabilityFormProblem,
  checkCapabilityChain,
  childCapabilityChain,
  invocationTargetProblem,
  MAX_CAPABILITY_HEADER_BYTES,
  parseCapabilityHeader,
  rootCapabilityId,
  targetWithin
} from './capability';
import { parseClientAssertion } from './oauth-client';
import {
  agentMetadataProblem,
  buildUnsignedAgentMetadataCredential,
  checkAgentMetadataCredentialForm,
  cleanAgentMetadata
} from './agent-metadata-credential';

/** Attaches the external agent-key signer to a result without making it enumerable: it is not copied by a spread
 * and never reaches `JSON.stringify`. */
/**
 * Salted commitment to an optional metadata value (RFC-001 §4.3), or `undefined` when no value is given.
 * A salt without its value is a caller mistake and throws.
 */
function metadataCommitment(
  field: 'coreModel' | 'systemPrompt',
  value: string | undefined,
  salt: string | undefined
): { commitment: string; salt: string } | undefined {
  if (value === undefined || value === null) {
    if (salt !== undefined && salt !== null) {
      throw new Error(`${field}Salt was given without ${field}`);
    }
    return undefined;
  }
  const usedSalt = salt ?? generateCommitmentSalt();
  return { commitment: createMetadataCommitment(value, usedSalt), salt: usedSalt };
}

function withSigner<T extends object>(result: T, signer: AgentSigner | undefined): T & { signer?: AgentSigner } {
  if (signer) {
    Object.defineProperty(result, 'signer', { value: signer, enumerable: false, writable: false, configurable: false });
  }
  return result;
}

export interface ProductionResolverProfileConfig {
  registry: AgentRegistry;
  documentSource: DIDDocumentSource;
  wbaDocumentSource?: DIDDocumentSource;
  webvhDocumentSource?: DIDDocumentSource;
  cacheTtlMs?: number;
  /** Maximum documents kept in the resolver cache (least recently used evicted first). Default 1000. */
  maxCacheEntries?: number;
  onResolutionEvent?: (event: ResolverResolutionEvent) => void;
  /**
   * documentRef schemes (without `://`, e.g. `'ipfs'`) whose documents are accepted
   * without a content-hash check. Defaults to none: only `hash://sha256/` references,
   * which the SDK always produces, are accepted and they are always verified.
   * Each unverified resolution emits a `source-fetched` event saying so.
   */
  unverifiedDocumentRefSchemes?: string[];
  /** Negative cache, concurrency limit and host allow-list for did:webvh / did:wba fetches (see `ResolutionLimits`). */
  resolutionLimits?: ResolutionLimits;
}

export interface ProductionHttpResolverProfileConfig {
  registry: AgentRegistry;
  cacheTtlMs?: number;
  /** Maximum documents kept in the resolver cache (least recently used evicted first). Default 1000. */
  maxCacheEntries?: number;
  referenceToUrl?: (documentRef: string) => string;
  referenceToUrls?: (documentRef: string) => string[];
  fetchFn?: (url: string) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text?: () => Promise<string> }>;
  ipfsGateways?: string[];
  onResolutionEvent?: (event: ResolverResolutionEvent) => void;
  /**
   * documentRef schemes (without `://`, e.g. `'ipfs'`) whose documents are accepted
   * without a content-hash check. Defaults to none: only `hash://sha256/` references,
   * which the SDK always produces, are accepted and they are always verified.
   * Each unverified resolution emits a `source-fetched` event saying so.
   */
  unverifiedDocumentRefSchemes?: string[];
  httpSecurity?: import('./http-security').HttpSecurityOptions;
  /** Negative cache, concurrency limit and host allow-list for did:webvh / did:wba fetches (see `ResolutionLimits`). */
  resolutionLimits?: ResolutionLimits;
}

export interface ProductionJsonRpcResolverProfileConfig {
  registry: AgentRegistry;
  cacheTtlMs?: number;
  /** Maximum documents kept in the resolver cache (least recently used evicted first). Default 1000. */
  maxCacheEntries?: number;
  endpoint?: string;
  endpoints?: string[];
  method?: string;
  buildParams?: (documentRef: string) => unknown[];
  headers?: Record<string, string>;
  transport?: (url: string, body: string, headers: Record<string, string>) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;
  onResolutionEvent?: (event: ResolverResolutionEvent) => void;
  httpSecurity?: import('./http-security').HttpSecurityOptions;
  /** Negative cache, concurrency limit and host allow-list for did:webvh / did:wba fetches (see `ResolutionLimits`). */
  resolutionLimits?: ResolutionLimits;
}


export interface AgentDidClientOptions {
  /** DID resolver. Defaults to a fresh in-memory resolver. */
  resolver?: DIDResolver;
  /** Agent registry. Defaults to a fresh in-memory registry. */
  registry?: AgentRegistry;
  /** Replay store for `verifyHttpRequestSignature`. Defaults to a fresh in-memory store. */
  nonceStore?: NonceStore;
  /** Time source for document timestamps and signature validity checks. Defaults to `new Date()`. */
  clock?: () => Date;
  /** Domain of the implicit local did:webvh profile. Defaults to `agents.local`. */
  webvhDomain?: string;
  /**
   * Obtains witness approvals for did:webvh entries governed by a witness rule (ADR-007): when the DID was created
   * with `webvh.witness` or `setDidWebvhWitnesses`. Without it, changing such a DID fails before anything is stored.
   */
  collectWitnessProofs?: DidWebvhWitnessCollector;
}

/**
 * Owns all mutable identity state (resolver, registry, replay store, document history,
 * did:webvh logs and controller signers). Each client is an isolated instance: two clients
 * never share state. `AgentIdentity`'s static API is a facade over a default client.
 */
export class AgentDidClient {
  private readonly nonceStore: NonceStore;
  private readonly defaultWebvhDomain: string;
  private readonly clock: () => Date;
  private resolver: DIDResolver;
  private registry: AgentRegistry;
  private readonly documentHistoryStore: Map<string, AgentDocumentHistoryEntry[]> = new Map();
  /** did:webvh v1.0 logs (`did.jsonl`) of the DIDs created or imported in this process. */
  private readonly didWebvhLogStore: Map<string, string> = new Map();
  /** `did-witness.json` of the stored logs that have witnessed entries (ADR-007), keyed by DID. */
  private readonly didWebvhWitnessStore: Map<string, string> = new Map();
  private readonly collectWitnessProofs: DidWebvhWitnessCollector | undefined;
  /**
   * Deactivation state derived from the verified log, keyed by DID and tied to the exact
   * log text it was computed from. It is recomputed whenever the stored log changes.
   */
  private readonly didWebvhStateCache: Map<
    string,
    { log: string; witnessFile: string | undefined; deactivated: boolean; document: DidDocument }
  > = new Map();
  /** Controller signers (did:webvh `updateKeys`) retained for DIDs created in this process. */
  private readonly didWebvhSignerStore: Map<string, AgentSigner> = new Map();
  /** Local bootstrap controllers, keyed by the creator's did:key. */
  private readonly bootstrapControllers: Map<string, { did: string; signer: AgentSigner }> = new Map();
  /** Serializes the creation of a bootstrap controller per creator key. */
  private readonly bootstrapControllerLocks: Map<string, Promise<void>> = new Map();
  /** One lifecycle operation (update, rotation, revocation, import) at a time per DID, so none is lost. */
  private readonly didLocks: Map<string, Promise<void>> = new Map();

  constructor(options: AgentDidClientOptions = {}) {
    this.resolver = options.resolver ?? new InMemoryDIDResolver();
    this.registry = options.registry ?? new InMemoryAgentRegistry();
    // The default store reads the client's clock, like the signature window it protects
    this.nonceStore = options.nonceStore ?? new InMemoryNonceStore({ now: () => Math.floor(this.clock().getTime() / 1000) });
    this.clock = options.clock ?? (() => new Date());
    this.defaultWebvhDomain = options.webvhDomain ?? 'agents.local';
    this.collectWitnessProofs = options.collectWitnessProofs;
  }

  /** Stores a verified log and its witness file (or drops the stale one when the log has none). */
  private storeDidWebvhLog(did: string, result: Pick<DidWebvhLogResult, 'log' | 'witnessFile'>): void {
    this.didWebvhLogStore.set(did, result.log);
    if (result.witnessFile !== undefined) {
      this.didWebvhWitnessStore.set(did, result.witnessFile);
    } else {
      this.didWebvhWitnessStore.delete(did);
    }
  }

  /** The stored witness file of `did` and the client's collector, as adapter options. */
  private didWebvhWitnessOptions(did: string): { witnessFile?: string; collectWitnessProofs?: DidWebvhWitnessCollector } {
    const witnessFile = this.didWebvhWitnessStore.get(did);
    return {
      ...(witnessFile !== undefined ? { witnessFile } : {}),
      ...(this.collectWitnessProofs ? { collectWitnessProofs: this.collectWitnessProofs } : {})
    };
  }

  /** The stored witness file of `did`, as a `resolveDidWebvhLog` option. */
  private storedWitnessFileOption(did: string): { witnessFile?: string } {
    const witnessFile = this.didWebvhWitnessStore.get(did);
    return witnessFile !== undefined ? { witnessFile } : {};
  }

  private nowIsoTimestamp(): string {
    return normalizeTimestampToIso(this.clock().toISOString()) as string;
  }

  /**
   * Creates a new Agent-DID Document (Passport) from raw parameters.
   * Automatically hashes sensitive IP (coreModel, systemPrompt) and generates the DID.
   * 
   * @param params The raw agent configuration (name, prompt, capabilities, etc.)
   * @returns A fully formed AgentDIDDocument compliant with RFC-001 and the Agent's private key
   */
  public async createAgent(controllerSigner: AgentSigner, params: CreateAgentParams): Promise<CreateAgentResult> {
    // Reject an unsupported relationship before generating keys or touching any store
    additionalRelationshipEntries(params.additionalVerificationRelationships, '');
    const timestamp = this.nowIsoTimestamp();
    // The creator is identified by its Ed25519 key, never by an EVM address
    const controllerKeyDid = didKeyFromPublicKey(await controllerSigner.getPublicKey());

    // Commit to the sensitive metadata with salted HMACs so it cannot be guessed by dictionary. Both
    // commitments are optional controller assertions (RFC-001 §4.3): no value, no commitment and no salt.
    const coreModel = metadataCommitment('coreModel', params.coreModel, params.coreModelSalt);
    const systemPrompt = metadataCommitment('systemPrompt', params.systemPrompt, params.systemPromptSalt);
    const metadataCommitmentSalts: MetadataCommitmentSalts = {};
    const agentMetadata: AgentMetadata = {
      name: params.name,
      description: params.description,
      version: params.version || '1.0.0',
      capabilities: params.capabilities || [],
      memberOf: params.memberOf
    };
    if (coreModel) {
      agentMetadata.coreModelHash = coreModel.commitment;
      metadataCommitmentSalts.coreModel = coreModel.salt;
    }
    if (systemPrompt) {
      agentMetadata.systemPromptHash = systemPrompt.commitment;
      metadataCommitmentSalts.systemPrompt = systemPrompt.salt;
    }

    // The agent's own Ed25519 key (RFC-001 assertion/authentication key)
    let privateKeyHex = '';
    let publicKeyBytes: Uint8Array;
    if (params.signer) {
      publicKeyBytes = await params.signer.getPublicKey();
    } else {
      const [localSigner, localKeyHex] = LocalKeySigner.generate();
      privateKeyHex = localKeyHex;
      publicKeyBytes = await localSigner.getPublicKey();
    }

    return this.createDidWebvhAgent(params, controllerKeyDid, {
      timestamp,
      agentMetadata,
      publicKeyBytes,
      privateKeyHex,
      metadataCommitmentSalts
    });
  }

  /**
   * Canonical did:webvh v1.0 profile: the agent document is the genesis entry of a
   * `did.jsonl` log signed by the controller key (the log's only `updateKeys` entry).
   */
  private async createDidWebvhAgent(
    params: CreateAgentParams,
    controllerKeyDid: string,
    agent: {
      timestamp: string;
      agentMetadata: AgentDIDDocument['agentMetadata'];
      publicKeyBytes: Uint8Array;
      privateKeyHex: string;
      metadataCommitmentSalts: NonNullable<CreateAgentResult['metadataCommitmentSalts']>;
    }
  ): Promise<CreateAgentResult> {
    let domain: string;
    let pathSegments: string[];
    let controllerDid: string;
    let controllerSigner: AgentSigner;
    let controllerPrivateKey: string | undefined;
    let nextUpdateKeys: string[] | undefined;
    let witness: DidWebvhWitnessConfig | undefined;

    if (params.webvh?.domain?.trim()) {
      const options = this.requireWebvhCreateOptions(params);
      domain = options.domain.trim();
      pathSegments = options.pathSegments ?? [];
      controllerDid = options.controllerDid.trim();
      controllerSigner = options.controllerSigner;
      nextUpdateKeys = options.nextUpdateKeys;
      witness = options.witness;
    } else {
      // Only the implicit local profile bootstraps a controller. An explicitly supplied
      // controller DID must be published by its owner; the SDK never fabricates it.
      const bootstrap = await this.ensureBootstrapController(controllerKeyDid);
      domain = this.defaultWebvhDomain;
      pathSegments = ['agents', normalizeDidPathSegment(params.name)];
      controllerDid = bootstrap.did;
      controllerSigner = bootstrap.signer;
      controllerPrivateKey = bootstrap.privateKey;
    }

    const template = buildAgentDocumentTemplate({
      controllerDid,
      timestamp: agent.timestamp,
      agentMetadata: agent.agentMetadata,
      publicKeyBytes: agent.publicKeyBytes,
      additionalVerificationRelationships: params.additionalVerificationRelationships
    });

    const created = await createDidWebvhLog({
      domain,
      pathSegments,
      document: template,
      signer: controllerSigner,
      ...(nextUpdateKeys !== undefined ? { nextUpdateKeys } : {}),
      ...(witness !== undefined ? { witness } : {}),
      ...(this.collectWitnessProofs ? { collectWitnessProofs: this.collectWitnessProofs } : {})
    });
    const document = cloneDocument(created.state as unknown as AgentDIDDocument);
    this.storeDidWebvhLog(document.id, created);
    this.didWebvhSignerStore.set(document.id, controllerSigner);

    this.resolver.registerDocument(document);
    await this.registry.register(document.id, document.controller, computeDocumentReference(document));
    this.appendHistory(document, 'created');

    return withSigner({
      document,
      agentPrivateKey: agent.privateKeyHex,
      ...(controllerPrivateKey ? { controllerPrivateKey } : {}),
      metadataCommitmentSalts: agent.metadataCommitmentSalts
    }, params.signer);
  }

  private requireWebvhCreateOptions(params: CreateAgentParams): NonNullable<CreateAgentParams['webvh']> {
    const options = params.webvh;
    if (!options?.domain?.trim()) {
      throw new Error('webvh.domain is required');
    }
    if (!options.controllerDid?.trim()) {
      throw new Error('webvh.controllerDid is required');
    }
    if (!options.controllerSigner) {
      throw new Error('webvh.controllerSigner is required: the controller key signs the did:webvh log (updateKeys)');
    }
    if ('scid' in (options as unknown as Record<string, unknown>)) {
      throw new Error('webvh.scid is no longer supported: did:webvh v1.0 derives the SCID from the genesis log entry');
    }
    return options;
  }

  /** Runs `operation` after every earlier lifecycle operation of `did` in this client has settled. */
  private async withDidLock<T>(did: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.didLocks.get(did) ?? Promise.resolve();
    const run = previous.then(operation);
    const settled = run.then(
      () => undefined,
      () => undefined
    );
    this.didLocks.set(did, settled);
    try {
      return await run;
    } finally {
      if (this.didLocks.get(did) === settled) {
        this.didLocks.delete(did);
      }
    }
  }

  /**
   * Returns the local bootstrap controller for a creator's `did:key`, creating it on first use.
   * Its did:webvh log is signed by a controller key generated with a CSPRNG; the key is
   * returned to the caller exactly once (`privateKey`) and never derived from public data.
   */
  private async ensureBootstrapController(
    controllerKeyDid: string
  ): Promise<{ did: string; signer: AgentSigner; privateKey?: string }> {
    // Concurrent creates for the same creator share one bootstrap controller: the later ones wait for the first
    const address = controllerKeyDid.trim();
    const pending = this.bootstrapControllerLocks.get(address) ?? Promise.resolve();
    const run = pending.then(() => this.createOrReuseBootstrapController(address));
    const settled = run.then(
      () => undefined,
      () => undefined
    );
    this.bootstrapControllerLocks.set(address, settled);
    try {
      return await run;
    } finally {
      if (this.bootstrapControllerLocks.get(address) === settled) {
        this.bootstrapControllerLocks.delete(address);
      }
    }
  }

  private async createOrReuseBootstrapController(
    address: string
  ): Promise<{ did: string; signer: AgentSigner; privateKey?: string }> {
    const keyId = address.replace(/^did:key:/u, '');
    const existing = this.bootstrapControllers.get(address);
    if (existing && await this.registry.getRecord(existing.did)) {
      return existing;
    }

    const [signer, privateKey] = LocalKeySigner.generate();
    const template = buildBootstrapControllerTemplate({
      creatorKeyDid: address,
      timestamp: this.nowIsoTimestamp(),
      publicKeyBytes: await signer.getPublicKey()
    });

    const created = await createDidWebvhLog({
      domain: this.defaultWebvhDomain,
      pathSegments: ['controllers', normalizeDidPathSegment(keyId)],
      document: template,
      signer
    });
    const document = cloneDocument(created.state as unknown as AgentDIDDocument);
    this.storeDidWebvhLog(document.id, created);
    this.didWebvhSignerStore.set(document.id, signer);
    this.bootstrapControllers.set(address, { did: document.id, signer });

    this.resolver.registerDocument(document);
    await this.registry.register(document.id, document.controller, computeDocumentReference(document));
    this.appendHistory(document, 'created');
    return { did: document.id, signer, privateKey };
  }

  /**
   * Appends a controller-signed entry with `document` to the DID's did:webvh log and
   * returns the state as signed. The signer is `controllerSigner` when given, otherwise
   * the controller signer retained when the DID was created in this process.
   */
  private async appendDidWebvhEntry(
    did: string,
    document: AgentDIDDocument,
    controllerSigner?: AgentSigner
  ): Promise<AgentDIDDocument> {
    const { log, signer } = this.requireDidWebvhLifecycle(did, controllerSigner);
    const updated = await updateDidWebvhLog({
      log,
      signer,
      document: document as unknown as Record<string, unknown>,
      ...this.didWebvhWitnessOptions(did)
    });
    this.storeDidWebvhLog(did, updated);
    // With pre-rotation active the signer was a committed key and is now the active controller key.
    if (updated.metadata.updateKeys.includes(await didWebvhUpdateKeyFor(signer))) {
      this.didWebvhSignerStore.set(did, signer);
    }
    return cloneDocument(updated.state as unknown as AgentDIDDocument);
  }

  private requireDidWebvhLifecycle(did: string, controllerSigner?: AgentSigner): { log: string; signer: AgentSigner } {
    const log = this.didWebvhLogStore.get(did);
    if (!log) {
      throw new Error(`No did:webvh log for ${did} in this process; import it with importDidWebvhHistory first`);
    }
    const signer = controllerSigner ?? this.didWebvhSignerStore.get(did);
    if (!signer) {
      throw new Error(`A controller signer is required to change ${did}: pass options.controllerSigner`);
    }
    return { log, signer };
  }

  /**
   * The agent's document and its controller chain, every link active and (did:webvh) bound. The first document is
   * the agent's and must be an Agent-DID document; the controllers may be any DID Core documents (RFC-001 §4.2.1).
   */
  private async resolveActiveVerificationChain(did: string): Promise<[AgentDIDDocument, ...DidDocument[]]> {
    let chain: [AgentDIDDocument, ...DidDocument[]];
    if (did.startsWith('did:webvh:')) {
      const [agent, ...controllers] = await this.resolveControllerChain(did);
      assertAgentDidDocument(agent, `The document of ${did}`);
      chain = [agent, ...controllers];
    } else {
      chain = [await this.resolve(did)];
    }

    if (chain.some((document) => !this.hasActiveVerificationMethod(document))) {
      throw new Error(`DID is not active: ${did}`);
    }

    if (did.startsWith('did:webvh:')) {
      await this.assertControllerChainBound(chain);
    }

    return chain;
  }

  /**
   * Every link of a controller chain (agent -> controller -> its controller ...) must be bound: the last entry of the
   * agent's did:webvh log was signed by a key that is active now under `capabilityInvocation` of the controller
   * (RFC-001 §6.6 item 7). Fails closed with `ControllerBindingError`, also when no log is available to check.
   */
  private async assertControllerChainBound(chain: DidDocument[]): Promise<void> {
    for (let index = 0; index + 1 < chain.length; index += 1) {
      const agent = chain[index];
      const controller = chain[index + 1];
      const state = agent.id.startsWith('did:webvh:') ? await this.resolveDidWebvhState(agent.id) : undefined;
      if (!state) {
        throw new ControllerBindingError(agent.id, controller.id, 'no did:webvh log is available to check the binding');
      }
      if (state.deactivated && index > 0) {
        throw new ControllerBindingError(agent.id, controller.id, 'the controller DID is deactivated');
      }
      assertBoundToController(agent, state.lastEntrySignerKeys, controller);
    }
  }

  /**
   * The verified did:webvh log behind `did` and what it says: the document in force, `versionId`, the `updateKeys`
   * in force, the keys that signed the last entry and the provenance of the log. A DID created or changed in this
   * client is answered from its local log; any other is answered by the resolver (`DIDResolver.resolveDidWebvhLog`),
   * which rejects when the log cannot be fetched or verified, and otherwise from the log imported in this client.
   * Returns `undefined` for a DID that is not did:webvh or has no log available (a resolver that holds only documents).
   */
  public async resolveDidWebvhState(did: string): Promise<DidWebvhState | undefined> {
    if (!did.startsWith('did:webvh:')) {
      return undefined;
    }
    const local = this.didWebvhLogStore.get(did);
    if (local !== undefined && this.didWebvhSignerStore.has(did)) {
      return this.didWebvhStateFromLog(did, local, 'local');
    }
    const fetched = await this.resolver.resolveDidWebvhLog?.(did);
    if (fetched) {
      return { ...fetched, provenance: 'fetched' };
    }
    return local !== undefined ? this.didWebvhStateFromLog(did, local, 'imported') : undefined;
  }

  private async didWebvhStateFromLog(
    did: string,
    log: string,
    provenance: DidWebvhState['provenance']
  ): Promise<DidWebvhState> {
    const resolved = await resolveDidWebvhLog(log, { did, ...this.storedWitnessFileOption(did) });
    assertDidDocument(resolved.state, `The did:webvh state of ${did}`);
    return {
      document: cloneDocument(resolved.state),
      log: resolved.log,
      versionId: resolved.metadata.versionId,
      updateKeys: [...resolved.metadata.updateKeys],
      lastEntrySignerKeys: didWebvhLastEntrySigners(resolved.log),
      deactivated: resolved.metadata.deactivated,
      ...(resolved.witnessFile !== undefined ? { witnessFile: resolved.witnessFile } : {}),
      provenance
    };
  }

  /** Whether `document` has an active `publicKeyMultibase` key, declared or embedded in a relationship. */
  private hasActiveVerificationMethod(document: DidDocument): boolean {
    const listed = DID_VERIFICATION_RELATIONSHIPS.flatMap((relationship) => relationshipMethods(document, relationship));
    return [...(document.verificationMethod ?? []), ...listed].some(
      (method) => Boolean(method.publicKeyMultibase) && !method.deactivated
    );
  }

  /**
   * Verifies an Agent-DID RFC 9421 HTTP Message Signature.
   *
   * Requires the Agent-DID profile (covered components, `tag="agent-did"`, `alg="ed25519"`,
   * `created`, `expires`, `nonce`, a `keyid` under the DID of the `Agent-DID` member), a matching
   * `Content-Digest`, and a signature by an active `assertionMethod` key. The nonce is then
   * recorded in `nonceStore` (default: a process-wide `InMemoryNonceStore`), so a replayed
   * request is rejected. Returns `false` on any failure; use `verifyHttpRequestSignatureDetailed`
   * to learn why.
   */
  public async verifyHttpRequestSignature(params: VerifyHttpRequestSignatureParams): Promise<boolean> {
    return (await this.verifyHttpRequestSignatureDetailed(params)).ok;
  }

  /**
   * Same verification as `verifyHttpRequestSignature`, returning the reason of a rejection
   * (see `HttpSignatureRejection`). Test `result.ok`: the result object is truthy for a rejection too.
   */
  public async verifyHttpRequestSignatureDetailed(
    params: VerifyHttpRequestSignatureParams
  ): Promise<VerifyHttpRequestSignatureResult> {
    return verifyAgentDidHttpRequest(params, {
      verifySignature: (did, payload, signature, keyId, purpose) =>
        this.checkSignature(did, payload, signature, keyId, purpose),
      nonceStore: this.nonceStore,
      now: this.clock()
    });
  }

  /**
   * Verifies a signed A2A Agent Card (composition contract §1.1, §3.1; A2A 1.0 §8.4): its format
   * (`parseSignedAgentCard`), then every signature against an active `assertionMethod` key of the card's agent DID,
   * resolved as for any other signature. A card without signatures is `format_drift`: the contract needs a signed card.
   */
  public async verifyAgentCard(card: unknown): Promise<VerifyAgentCardResult> {
    const parsed = parseSignedAgentCard(card);
    if (!parsed) {
      return { ok: false, reason: 'format_drift' };
    }
    for (const entry of parsed.signatures) {
      const check = await this.checkSignature(
        parsed.did,
        entry.signingInput,
        bytesToHex(entry.signature),
        entry.keyId,
        REQUIRED_RELATIONSHIP_BY_ARTIFACT.assertion
      );
      if (check.outcome !== 'valid') {
        return { ok: false, reason: await this.compositionReason(parsed.did, entry.keyId, check.outcome), keyId: entry.keyId };
      }
    }
    return { ok: true, did: parsed.did, publishedKeyIds: parsed.publishedKeyIds };
  }

  /**
   * The identity composition check (composition contract §2, §3): the Agent Card must verify (`verifyAgentCard`),
   * the request must verify as `verifyHttpRequestSignatureDetailed` checks it, the request's agent DID must be the
   * card's, and its `keyid` must be a key the card publishes. The card is checked first, so a request against a bad
   * card does not consume its nonce. Contract reasons are derived from the current DID document: a retired key is
   * `rotation_window_closed`, a revoked one `emergency_revoked`.
   */
  public async verifyIdentityComposition(
    params: VerifyIdentityCompositionParams
  ): Promise<VerifyIdentityCompositionResult> {
    const { agentCard, ...request } = params;
    const card = await this.verifyAgentCard(agentCard);
    if (!card.ok) {
      return { ok: false, stage: 'agent_card', reason: card.reason, ...(card.keyId ? { keyId: card.keyId } : {}) };
    }
    // The HTTP verifier reports a reason; the contract reason needs the key and the outcome of its signature check.
    let lastCheck: { did: string; keyId: string; outcome: SignatureCheckOutcome } | undefined;
    const result = await verifyAgentDidHttpRequest(request, {
      verifySignature: async (did, payload, signature, keyId, purpose) => {
        const check = await this.checkSignature(did, payload, signature, keyId, purpose);
        lastCheck = { did, keyId, outcome: check.outcome };
        return check;
      },
      nonceStore: this.nonceStore,
      now: this.clock()
    });
    if (!result.ok) {
      const checked =
        lastCheck !== undefined &&
        lastCheck.outcome !== 'valid' &&
        ['did_resolution_failed', 'controller_not_bound', 'keyid_not_authorized', 'signature_invalid'].includes(result.reason)
          ? lastCheck
          : undefined;
      return {
        ok: false,
        stage: 'request',
        reason: checked ? await this.compositionReason(checked.did, checked.keyId, checked.outcome) : 'request_rejected',
        httpReason: result.reason,
        ...(checked ? { keyId: checked.keyId } : {})
      };
    }
    if (result.did !== card.did || !card.publishedKeyIds.includes(result.keyId)) {
      return { ok: false, stage: 'request', reason: 'card_keyid_mismatch', keyId: result.keyId };
    }
    return {
      ok: true,
      did: result.did,
      keyId: result.keyId,
      controllers: result.controllers,
      publishedKeyIds: card.publishedKeyIds
    };
  }

  /** Contract reason for a signature check that failed, from the current document of `did`. */
  private async compositionReason(
    did: string,
    keyId: string,
    outcome: SignatureCheckOutcome
  ): Promise<IdentityCompositionRejection> {
    if (outcome === 'did_resolution_failed' || outcome === 'controller_not_bound') {
      return 'did_document_unresolvable';
    }
    let document: AgentDIDDocument;
    try {
      document = await this.resolve(did);
    } catch {
      return 'did_document_unresolvable';
    }
    return compositionReasonForKey(document, keyId);
  }

  /** `verifySignature` that tells apart the ways a verification can fail, with the controller chain. */
  private async checkSignature(
    did: string,
    payload: string,
    signature: string,
    keyId: string,
    requiredPurpose: VerificationRelationship
  ): Promise<SignatureCheck> {
    let verificationChain: [AgentDIDDocument, ...DidDocument[]];
    try {
      verificationChain = await this.resolveActiveVerificationChain(did);
    } catch (error) {
      return { outcome: error instanceof ControllerBindingError ? 'controller_not_bound' : 'did_resolution_failed' };
    }
    let outcome: SignatureCheckOutcome;
    try {
      outcome = verifyWithActiveKeys(verificationChain[0], payload, signature, keyId, requiredPurpose) ? 'valid' : 'invalid';
    } catch (error) {
      if (error instanceof IdentityCompositionError) {
        return { outcome: 'key_not_authorized' };
      }
      throw error;
    }
    return { outcome, controllers: verificationChain.slice(1).map((document) => document.id) };
  }

  /**
   * Verifies that a payload signature (`signMessage`, which covers `AGENT_DID_MESSAGE_SIGNING_PREFIX + payload`)
   * was produced by a specific Agent-DID. Uses the configured resolver and registry to validate against active
   * verification methods. HTTP request signatures are verified with `verifyHttpRequestSignature`, not here.
   */
  public async verifySignature(
    did: string,
    payload: string,
    signature: string,
    keyId?: string,
    requiredPurpose: VerificationRelationship = REQUIRED_RELATIONSHIP_BY_ARTIFACT.assertion
  ): Promise<boolean> {
    let verificationChain: [AgentDIDDocument, ...DidDocument[]];
    try {
      verificationChain = await this.resolveActiveVerificationChain(did);
    } catch {
      return false;
    }

    return verifyWithActiveKeys(verificationChain[0], messageSigningInput(payload), signature, keyId, requiredPurpose);
  }

  /**
   * Verifies a signature made with `keyId` at the time the signed artifact states (RFC-001 §6.2.2), against the
   * DID's verified did:webvh log as `resolveDidWebvhState` gives it: the local log for a DID created or changed in
   * this client, otherwise the log the resolver fetches (the longer of it and a log imported with
   * `importDidWebvhHistory`), and the imported log only when the resolver does not fetch logs. A key retired by a
   * later entry of the log host is therefore seen even when an older log was imported.
   *
   * - `valid`: the signature verifies and the key was authorized for `requiredPurpose` at `statedTime`, with no
   *   later change that retires it, or with `trustedTimeNotAfter` earlier than that change.
   * - `invalid`: the signature does not verify, the key was not authorized at `statedTime`, the log cannot be
   *   fetched or fails verification (`did_resolution_failed`), or the controller binding does not hold now.
   * - `indeterminate`: the key was retired or the DID deactivated after `statedTime` and there is no trusted
   *   time evidence, or no did:webvh log is available for the DID. Do not accept it.
   *
   * The stated time is asserted by the signer, so a retired key is never accepted on the signer's word alone. With
   * `timestampToken` (an RFC 3161 token over the raw signature bytes) and `tsaTrustAnchors`, the SDK verifies the
   * token and uses its `genTime + accuracy` as the trusted time evidence (ADR-007); a token that does not verify gives
   * `invalid` / `timestamp_invalid`.
   */
  public async verifySignatureAtTime(
    did: string,
    payload: string,
    signature: string,
    keyId: string,
    options: VerifySignatureAtTimeOptions
  ): Promise<VerifySignatureAtTimeResult> {
    const { timestampToken, tsaTrustAnchors, ...keyOptions } = options;
    if (timestampToken !== undefined) {
      if (keyOptions.trustedTimeNotAfter !== undefined) {
        throw new TypeError('Pass either timestampToken or trustedTimeNotAfter, not both');
      }
      if (tsaTrustAnchors === undefined) {
        throw new TypeError('timestampToken needs tsaTrustAnchors');
      }
      let signatureBytes: Uint8Array;
      try {
        signatureBytes = decodeSignatureHex(signature);
      } catch {
        return { status: 'invalid', reason: 'signature_invalid' };
      }
      const timestamp = await verifyTimestampToken(timestampToken, signatureBytes, { trustAnchors: tsaTrustAnchors });
      if (timestamp.status === 'invalid') {
        return { status: 'invalid', reason: 'timestamp_invalid', timestampRejection: timestamp.reason };
      }
      keyOptions.trustedTimeNotAfter = timestamp.trustedTimeNotAfter;
    }
    let state: DidWebvhState | undefined;
    try {
      state = await this.resolveDidWebvhState(did);
    } catch {
      return { status: 'invalid', reason: 'did_resolution_failed' };
    }
    if (state === undefined) {
      return { status: 'indeterminate', key: { status: 'indeterminate', keyId, reason: 'history_unavailable' } };
    }
    if (agentDidDocumentProblem(state.document) !== undefined) {
      // Signatures are verified for agents; a plain DID Core document (a controller) is not one
      return { status: 'invalid', reason: 'did_resolution_failed' };
    }
    let key;
    try {
      key = await checkDidWebvhKeyAtTime(state.log, {
        ...keyOptions,
        did,
        keyId,
        ...(state.witnessFile !== undefined ? { witnessFile: state.witnessFile } : {})
      });
    } catch (error) {
      if (error instanceof TypeError) {
        throw error;
      }
      return { status: 'invalid', reason: 'did_resolution_failed' };
    }
    const result = signatureResultForKey(key, messageSigningInput(payload), signature);
    if (result.status === 'valid') {
      // The binding is evaluated against the controller as it is now, never at the stated time
      try {
        await this.assertDidWebvhBoundNow(did, state);
      } catch (error) {
        if (error instanceof ControllerBindingError) {
          return { status: 'invalid', reason: 'controller_not_bound', key: result.key };
        }
        return { status: 'invalid', reason: 'did_resolution_failed', key: result.key };
      }
    }
    return result;
  }

  /** The binding of `did` (and of its controllers) to its controller chain as it is now. */
  private async assertDidWebvhBoundNow(did: string, state: DidWebvhState): Promise<void> {
    const document = state.document;
    if (!document || typeof document.controller !== 'string' || !document.controller.trim() || document.controller === did) {
      return;
    }
    let controllers: DidDocument[];
    try {
      controllers = await this.resolveControllerChain(document.controller);
    } catch (error) {
      throw new ControllerBindingError(did, document.controller, `the controller does not resolve (${String(error)})`);
    }
    await this.assertControllerChainBound([document, ...controllers]);
  }

  /**
   * Issues an `AgentMetadataCredential` (RFC-001 §4.4): the agent's controller states the agent's metadata in a W3C
   * VC 2.0 credential secured with an `eddsa-jcs-2022` Data Integrity proof. `verificationMethodId` must be an active
   * Ed25519 `assertionMethod` key of the controller held by `signer`. The credential is presented out of band (an
   * A2A Agent Card, an MCP exchange, a request body); DID resolution never fetches it.
   */
  public async issueAgentMetadataCredential(params: IssueAgentMetadataCredentialParams): Promise<AgentMetadataCredential> {
    const agent = await this.resolve(params.agentDid);
    const issuer = agent.controller?.trim() || agent.id;
    if (typeof params.verificationMethodId !== 'string' || !params.verificationMethodId.startsWith(`${issuer}#`)) {
      throw new Error(`verificationMethodId must be a key of the agent's controller ${issuer}`);
    }
    const issuerDocument: DidDocument = issuer === agent.id ? agent : await this.resolveDocument(issuer);
    const publicKey = activeAssertionKey(issuerDocument, params.verificationMethodId);
    if (publicKey === undefined) {
      throw new Error(`${params.verificationMethodId} is not an active Ed25519 assertionMethod key of ${issuer}`);
    }
    if (bytesToHex(await params.signer.getPublicKey()) !== bytesToHex(publicKey)) {
      throw new Error(`The signer does not hold ${params.verificationMethodId}`);
    }
    const agentMetadata = cleanAgentMetadata(params.agentMetadata ?? agent.agentMetadata);
    const problem = agentMetadataProblem(agentMetadata);
    if (problem !== undefined) {
      throw new TypeError(problem);
    }
    const now = this.nowIsoTimestamp();
    const validFrom = params.validFrom ?? now;
    const validFromMillis = parseRfc3339Millis(validFrom);
    if (validFromMillis === undefined) {
      throw new TypeError('validFrom must be an RFC 3339 date-time');
    }
    if (params.validUntil !== undefined) {
      const validUntilMillis = parseRfc3339Millis(params.validUntil);
      if (validUntilMillis === undefined || validUntilMillis < validFromMillis) {
        throw new TypeError('validUntil must be an RFC 3339 date-time not earlier than validFrom');
      }
    }
    if (params.id !== undefined && (typeof params.id !== 'string' || params.id.length === 0)) {
      throw new TypeError('id must be a non-empty string');
    }
    const unsigned = buildUnsignedAgentMetadataCredential({
      issuer,
      agentDid: agent.id,
      agentMetadata,
      validFrom,
      ...(params.validUntil !== undefined ? { validUntil: params.validUntil } : {}),
      ...(params.id !== undefined ? { id: params.id } : {})
    });
    const proof = await createEddsaJcs2022Proof(
      unsigned,
      { created: now, verificationMethod: params.verificationMethodId, proofPurpose: 'assertionMethod' },
      async (hashData) => hexToBytes(await params.signer.sign(hashData))
    );
    const credential: AgentMetadataCredential = { ...unsigned, proof };
    if (!verifyEddsaJcs2022Proof(credential, publicKey)) {
      throw new Error('The signer produced a signature that does not match its public key');
    }
    return credential;
  }

  /**
   * Verifies an `AgentMetadataCredential` (RFC-001 §4.4): its form and validity period, that the agent DID resolves,
   * is not deactivated and is bound to its controller (RFC-001 §6.6 item 7), that `issuer` is that controller, and the
   * `eddsa-jcs-2022` proof by an active `assertionMethod` key of the issuer. Never throws for a bad credential: test
   * `result.ok`. The metadata in an accepted credential is the controller's assertion, not evidence of what runs.
   */
  public async verifyAgentMetadataCredential(
    credential: unknown,
    options: VerifyAgentMetadataCredentialOptions = {}
  ): Promise<VerifyAgentMetadataCredentialResult> {
    let form: ReturnType<typeof checkAgentMetadataCredentialForm>;
    try {
      form = checkAgentMetadataCredentialForm(credential, this.clock().getTime());
    } catch {
      return { ok: false, reason: 'malformed_credential' };
    }
    if (!form.ok) {
      return form;
    }
    const { issuer, agentDid, verificationMethod, agentMetadata } = form.value;
    if (options.expectedAgentDid !== undefined && options.expectedAgentDid !== agentDid) {
      return { ok: false, reason: 'subject_mismatch' };
    }
    try {
      if ((await this.resolveDidWebvhState(agentDid))?.deactivated) {
        return { ok: false, reason: 'did_deactivated' };
      }
    } catch {
      return { ok: false, reason: 'did_resolution_failed' };
    }
    let chain: [AgentDIDDocument, ...DidDocument[]];
    try {
      chain = await this.resolveActiveVerificationChain(agentDid);
    } catch (error) {
      return { ok: false, reason: error instanceof ControllerBindingError ? 'controller_not_bound' : 'did_resolution_failed' };
    }
    const agent = chain[0];
    if (issuer !== (agent.controller?.trim() || agent.id)) {
      return { ok: false, reason: 'issuer_not_controller' };
    }
    let issuerDocument: DidDocument;
    if (issuer === agent.id) {
      issuerDocument = agent;
    } else if (chain.length > 1 && chain[1].id === issuer) {
      issuerDocument = chain[1];
    } else {
      try {
        issuerDocument = await this.resolveDocument(issuer);
      } catch {
        return { ok: false, reason: 'did_resolution_failed' };
      }
    }
    const publicKey = activeAssertionKey(issuerDocument, verificationMethod);
    if (publicKey === undefined) {
      return { ok: false, reason: 'key_not_authorized' };
    }
    if (!verifyEddsaJcs2022Proof(credential, publicKey)) {
      return { ok: false, reason: 'signature_invalid' };
    }
    return {
      ok: true,
      agentDid,
      issuer,
      verificationMethod,
      agentMetadata,
      controllers: chain.slice(1).map((document) => document.id)
    };
  }

  /**
   * Delegates a capability (RFC-001 §6.7): grants `params.controller` the authority to act on `invocationTarget`
   * until `expires`, signed with an `eddsa-jcs-2022` proof by a `capabilityDelegation` key of the delegator. Without
   * `parentCapability` the delegator is a root controller of `rootTarget` (whether it is one is the verifier's
   * configuration); with it, the delegator must be the parent's `controller`, and the new capability may only narrow
   * the parent's target, actions and expiry.
   */
  public async createCapability(params: CreateCapabilityParams): Promise<AgentCapability> {
    const delegator = didOfKeyId(params.verificationMethodId);
    if (delegator === undefined) {
      throw new TypeError(`verificationMethodId must be a DID URL with a fragment: ${String(params.verificationMethodId)}`);
    }
    const targetProblem = invocationTargetProblem(params.invocationTarget);
    if (targetProblem !== undefined) {
      throw new TypeError(targetProblem);
    }
    const expiresMillis = parseRfc3339Millis(params.expires);
    if (expiresMillis === undefined) {
      throw new TypeError('expires must be an RFC 3339 date-time');
    }
    if (params.allowedAction !== undefined) {
      const actions = params.allowedAction;
      if (actions.length === 0 || actions.some((action) => typeof action !== 'string' || action.length === 0) || new Set(actions).size !== actions.length) {
        throw new TypeError('allowedAction must be a non-empty list of distinct non-empty strings');
      }
    }
    const id = params.id ?? `urn:uuid:${globalThis.crypto.randomUUID()}`;
    let parentId: string;
    let parentForChain: AgentCapability | string;
    if (params.parentCapability !== undefined) {
      const parent = params.parentCapability;
      if (parent.controller !== delegator) {
        throw new Error(`Only the parent's controller ${parent.controller} can delegate it`);
      }
      const parentExpires = parseRfc3339Millis(parent.expires);
      if (
        !targetWithin(params.invocationTarget, parent.invocationTarget) ||
        (parent.allowedAction !== undefined && params.allowedAction !== undefined &&
          !params.allowedAction.every((action) => parent.allowedAction?.includes(action))) ||
        parentExpires === undefined || expiresMillis > parentExpires
      ) {
        throw new Error("The capability must not widen the parent's target, actions or expiry");
      }
      parentId = parent.id;
      parentForChain = parent;
    } else {
      const rootTarget = params.rootTarget ?? params.invocationTarget;
      const rootProblem = invocationTargetProblem(rootTarget);
      if (rootProblem !== undefined) {
        throw new TypeError(rootProblem);
      }
      if (!targetWithin(params.invocationTarget, rootTarget)) {
        throw new Error('invocationTarget must be the root target or within it');
      }
      parentId = rootCapabilityId(rootTarget);
      parentForChain = parentId;
    }
    const delegatorDocument = await this.resolveDocument(delegator);
    const publicKey = activeKeyUnder(delegatorDocument, params.verificationMethodId, 'capabilityDelegation');
    if (publicKey === undefined) {
      throw new Error(`${params.verificationMethodId} is not an active Ed25519 capabilityDelegation key of ${delegator}`);
    }
    if (bytesToHex(await params.signer.getPublicKey()) !== bytesToHex(publicKey)) {
      throw new Error(`The signer does not hold ${params.verificationMethodId}`);
    }
    const unsigned = buildUnsignedCapability({
      id,
      parentCapability: parentId,
      invocationTarget: params.invocationTarget,
      controller: params.controller,
      expires: params.expires,
      ...(params.allowedAction !== undefined ? { allowedAction: params.allowedAction } : {})
    });
    const proofOptions = {
      type: DATA_INTEGRITY_PROOF_TYPE,
      cryptosuite: EDDSA_JCS_2022_CRYPTOSUITE,
      created: this.nowIsoTimestamp(),
      verificationMethod: params.verificationMethodId,
      proofPurpose: CAPABILITY_DELEGATION_PURPOSE,
      capabilityChain: childCapabilityChain(parentForChain)
    };
    const config = { ...proofOptions, '@context': unsigned['@context'] };
    const signature = hexToBytes(await params.signer.sign(eddsaJcs2022HashData(unsigned, config)));
    const capability = {
      ...unsigned,
      proof: { ...config, proofValue: encodeEddsaProofValue(signature) }
    } as unknown as AgentCapability;
    if (capabilityFormProblem(capability) !== undefined || !verifyEddsaJcs2022Proof(capability, publicKey)) {
      throw new Error('The signer produced a capability that does not verify');
    }
    return capability;
  }

  /**
   * Verifies a delegated capability and its chain (RFC-001 §6.7): form, chain structure, the root controller the
   * verifier configured for the root target, attenuation at every link, validity period, and each proof by an active
   * Ed25519 `capabilityDelegation` key of its delegator, resolved now. Never throws for a bad capability: test
   * `result.ok`.
   */
  public async verifyCapabilityChain(
    capability: unknown,
    options: VerifyCapabilityChainOptions
  ): Promise<VerifyCapabilityChainResult> {
    const checked = checkCapabilityChain(capability, options.rootControllers ?? {}, this.clock().getTime(), options.maxChainLength);
    if (!checked.ok) {
      return checked;
    }
    const { capabilities, rootControllers, rootId } = checked.value;
    const delegators: string[] = [];
    for (const [index, item] of capabilities.entries()) {
      const delegator = didOfKeyId(item.proof.verificationMethod) as string;
      const allowed = index === 0 ? rootControllers.includes(delegator) : capabilities[index - 1].controller === delegator;
      if (!allowed) {
        return { ok: false, reason: 'delegator_mismatch', capabilityId: item.id };
      }
      const keyCheck = await this.delegationKeyCheck(delegator, item.proof.verificationMethod);
      if (!keyCheck.ok) {
        return { ok: false, reason: keyCheck.reason, capabilityId: item.id };
      }
      if (!verifyEddsaJcs2022Proof(item, keyCheck.publicKey)) {
        return { ok: false, reason: 'signature_invalid', capabilityId: item.id };
      }
      delegators.push(delegator);
    }
    const leaf = capabilities[capabilities.length - 1];
    return {
      ok: true,
      capability: leaf,
      controller: leaf.controller,
      invocationTarget: leaf.invocationTarget,
      ...(checked.value.allowedAction !== undefined ? { allowedAction: checked.value.allowedAction } : {}),
      rootId,
      delegators
    };
  }

  /** The delegation key `keyId` of `did`, resolved now, or why it cannot sign a delegation. */
  private async delegationKeyCheck(
    did: string,
    keyId: string
  ): Promise<{ ok: true; publicKey: Uint8Array } | { ok: false; reason: CapabilityRejection }> {
    let document: DidDocument;
    try {
      if (did.startsWith('did:webvh:') && (await this.resolveDidWebvhState(did))?.deactivated) {
        return { ok: false, reason: 'did_deactivated' };
      }
      document = await this.resolveDocument(did);
    } catch {
      return { ok: false, reason: 'did_resolution_failed' };
    }
    const publicKey = activeKeyUnder(document, keyId, 'capabilityDelegation');
    if (publicKey !== undefined) {
      return { ok: true, publicKey };
    }
    const elsewhere = DID_VERIFICATION_RELATIONSHIPS.some((relationship) =>
      relationship !== 'capabilityDelegation' && activeKeyUnder(document, keyId, relationship) !== undefined);
    return { ok: false, reason: elsewhere ? 'key_purpose_violation' : 'key_not_authorized' };
  }

  /**
   * Verifies a request that invokes a capability (RFC-001 §6.5, §6.7): the request profile of
   * `verifyHttpRequestSignatureDetailed`, with the signing key under `capabilityInvocation` instead of
   * `assertionMethod`; the signature must cover `"agent-did-capability";key="<label>"`; the request's agent DID must
   * be the capability's `controller`, its URL within the target and its method allowed; then the capability chain
   * (`verifyCapabilityChain`). The nonce is recorded only when everything passes.
   */
  public async verifyHttpCapabilityInvocation(
    params: VerifyHttpCapabilityInvocationParams
  ): Promise<VerifyHttpCapabilityInvocationResult> {
    const { rootControllers, maxChainLength, ...request } = params;
    const headers = Object.fromEntries(Object.entries(request.headers).map(([key, value]) => [key.toLowerCase(), value]));
    const field = headers[AGENT_DID_CAPABILITY_HTTP_HEADER.toLowerCase()];
    const method = request.method.toUpperCase();
    const requestTarget = request.url.split('?')[0];
    const result = await verifyAgentDidHttpRequestWith<AgentCapability, VerifyCapabilityChainResult & { ok: true }>(
      request,
      {
        verifySignature: (did, payload, signature, keyId, purpose) => this.checkSignature(did, payload, signature, keyId, purpose),
        nonceStore: this.nonceStore,
        now: this.clock()
      },
      {
        relationship: REQUIRED_RELATIONSHIP_BY_ARTIFACT.invocation,
        beforeSignature: (label, input, agentDid) => {
          const covered = input.components.some((component) =>
            typeof component !== 'string' && component.name === 'agent-did-capability' && component.key === label);
          if (!covered || field === undefined) {
            return { ok: false, reason: 'capability_missing' };
          }
          if (new TextEncoder().encode(field).length > MAX_CAPABILITY_HEADER_BYTES) {
            return { ok: false, reason: 'capability_too_large' };
          }
          const parsed = parseCapabilityHeader(field, label);
          if (parsed === 'missing') {
            return { ok: false, reason: 'capability_missing' };
          }
          if (parsed === undefined) {
            return { ok: false, reason: 'malformed_capability' };
          }
          if (parsed.controller !== agentDid) {
            return { ok: false, reason: 'invoker_not_controller', capabilityId: parsed.id };
          }
          if (typeof parsed.invocationTarget !== 'string' || !targetWithin(requestTarget, parsed.invocationTarget)) {
            return { ok: false, reason: 'target_mismatch', capabilityId: parsed.id };
          }
          return { ok: true, state: parsed };
        },
        afterSignature: async (capability) => {
          const chain = await this.verifyCapabilityChain(capability, {
            rootControllers,
            ...(maxChainLength !== undefined ? { maxChainLength } : {})
          });
          if (!chain.ok) {
            return chain;
          }
          if (!actionAllowed(method, chain.allowedAction)) {
            return { ok: false, reason: 'action_not_allowed', capabilityId: chain.capability.id };
          }
          return { ok: true, extra: chain };
        }
      }
    );
    if (!result.ok) {
      return {
        ok: false,
        reason: result.reason as CapabilityInvocationRejection,
        ...(result.capabilityId !== undefined ? { capabilityId: result.capabilityId } : {})
      };
    }
    const chain = result.extra as VerifyCapabilityChainResult & { ok: true };
    return {
      ok: true,
      did: result.did,
      keyId: result.keyId,
      controllers: result.controllers,
      capability: chain.capability,
      ...(chain.allowedAction !== undefined ? { allowedAction: chain.allowedAction } : {}),
      rootId: chain.rootId,
      delegators: chain.delegators
    };
  }

  /**
   * Verifies a JWT client assertion (`private_key_jwt`) against the agent DID registered for the client (RFC-001
   * §6.8): JWS form, `alg` (`EdDSA` or `Ed25519`), `typ` (absent or `client-authentication+jwt`), `kid` a DID URL of
   * `did`, `iss` = `sub` = `clientId`, `aud` exactly `issuer`, lifetime at most 300 s and times within the clock
   * skew, then the signature by an active Ed25519 `authentication` key of the resolved DID, and finally `jti` in the
   * nonce store. For an authorization server or MCP server that knows Agent-DID. Never throws: test `result.ok`.
   */
  public async verifyClientAssertion(params: VerifyClientAssertionParams): Promise<VerifyClientAssertionResult> {
    const parsed = parseClientAssertion(params.assertion, {
      clientId: params.clientId,
      issuer: params.issuer,
      did: params.did,
      nowSeconds: Math.floor(this.clock().getTime() / 1000),
      maxClockSkewSeconds: params.maxClockSkewSeconds ?? 30
    });
    if (!parsed.ok) {
      return parsed;
    }
    const { keyId, signingInput, signature, jti, expiresAt } = parsed.value;
    const check = await this.checkSignature(
      params.did,
      signingInput,
      bytesToHex(signature),
      keyId,
      REQUIRED_RELATIONSHIP_BY_ARTIFACT.authentication
    );
    if (check.outcome !== 'valid') {
      return {
        ok: false,
        reason:
          check.outcome === 'invalid' ? 'signature_invalid'
            : check.outcome === 'key_not_authorized' ? 'key_not_authorized'
              : check.outcome
      };
    }
    const store = params.nonceStore ?? this.nonceStore;
    const skew = params.maxClockSkewSeconds ?? 30;
    if (!(await store.checkAndStore(`client-assertion ${params.clientId} ${jti}`, expiresAt + skew))) {
      return { ok: false, reason: 'jti_replayed' };
    }
    return {
      ok: true,
      did: params.did,
      keyId,
      clientId: params.clientId,
      jti,
      expiresAt,
      controllers: check.controllers ?? []
    };
  }

  /**
   * Drops the resolver's cached resolution of `did`, so the next verification fetches and verifies it again (for a
   * check that must not rely on a cached state, such as an irreversible action). A no-op with a resolver that does
   * not cache (`DIDResolver.evict` not implemented).
   */
  public evictCachedResolution(did: string): void {
    this.resolver.evict?.(did);
  }

  /**
   * Resolves a DID into its corresponding Agent-DID Document.
   * Uses the configured resolver (in-memory or production) to retrieve the document.
   */
  /**
   * The Agent-DID document of `did`. Rejects when the DID resolves to a DID Core document that is not an Agent-DID
   * document (a plain controller: use `resolveDocument`).
   */
  public async resolve(did: string): Promise<AgentDIDDocument> {
    if (did.startsWith('did:webvh:')) {
      const document = await this.resolveDocument(did);
      assertAgentDidDocument(document, `The document of ${did}`);
      return document;
    }

    const isRevoked = await this.registry.isRevoked(did);

    if (isRevoked) {
      throw new Error(`DID is revoked: ${did}`);
    }

    return this.resolver.resolve(did);
  }

  /**
   * The DID Core document of `did`. A did:webvh DID may resolve to any DID Core document (a controller, RFC-001
   * §4.2.1), with the same log verification and revocation rules as `resolve`; any other DID is answered by
   * `resolve`, so its document must be an Agent-DID document.
   */
  public async resolveDocument(did: string): Promise<DidDocument> {
    if (did.startsWith('did:webvh:')) {
      // For did:webvh the verified log is the only source of revocation state: a DID is
      // revoked only by a controller-signed deactivation entry. The registry record is a
      // derived index and is not consulted.
      //
      // A DID created or changed in this process (its controller signer is retained) is
      // authoritative here: its local log is served without asking the resolver, so it does not
      // stop resolving when a resolver cache entry expires or its host is down. Any other DID
      // is resolved (and its log verified) by the configured resolver, which treats an imported
      // log as a cache and fails closed when it cannot refresh it.
      const state = await this.didWebvhState(did);
      if (state?.deactivated) {
        throw new Error(`DID is revoked: ${did}`);
      }
      if (state && this.didWebvhSignerStore.has(did)) {
        return cloneDocument(state.document);
      }
      return this.resolver.resolveDocument ? this.resolver.resolveDocument(did) : this.resolver.resolve(did);
    }
    return this.resolve(did);
  }

  /**
   * State of the locally stored did:webvh log: whether it ends in a deactivation entry and its
   * latest document. The log is verified (SCID, hash chain, controller proofs) before its state is
   * trusted; a log that fails verification is an error, never "not revoked". Returns undefined when
   * no log is stored for the DID.
   */
  private async didWebvhState(did: string): Promise<{ deactivated: boolean; document: DidDocument } | undefined> {
    const log = this.didWebvhLogStore.get(did);
    if (log === undefined) {
      return undefined;
    }
    const witnessFile = this.didWebvhWitnessStore.get(did);
    const cached = this.didWebvhStateCache.get(did);
    if (cached?.log === log && cached.witnessFile === witnessFile) {
      return cached;
    }
    const resolved = await resolveDidWebvhLog(log, { did, ...this.storedWitnessFileOption(did) });
    assertDidDocument(resolved.state, `The did:webvh state of ${did}`);
    const state = {
      log,
      witnessFile,
      deactivated: resolved.metadata.deactivated,
      document: cloneDocument(resolved.state)
    };
    this.didWebvhStateCache.set(did, state);
    return state;
  }

  public async resolveControllerChain(did: string, maxDepth = 8): Promise<DidDocument[]> {
    if (!Number.isInteger(maxDepth) || maxDepth < 1) {
      throw new Error('maxDepth must be a positive integer');
    }

    const chain: DidDocument[] = [];
    const visited = new Set<string>();
    let currentDid = did;

    while (true) {
      if (visited.has(currentDid)) {
        throw new Error(`Controller chain cycle detected at DID: ${currentDid}`);
      }

      if (chain.length >= maxDepth) {
        throw new Error(`Controller chain exceeded max depth of ${maxDepth} starting from DID: ${did}`);
      }

      visited.add(currentDid);
      const current = await this.resolveDocument(currentDid);
      chain.push(current);

      // A list of controllers is not followed in 1.0: the chain fails closed instead of skipping them (RFC-001 §4.2.1)
      if (Array.isArray(current.controller)) {
        throw new Error(`Controller chain cannot follow a list of controllers at DID: ${currentDid}`);
      }
      const controllerDid = current.controller?.trim();
      if (!controllerDid || controllerDid === currentDid || !controllerDid.startsWith('did:')) {
        return chain;
      }

      currentDid = controllerDid;
    }
  }

  /**
   * Revokes a DID. For did:webvh DIDs this appends a controller-signed deactivation entry
   * (`deactivated: true`) to the DID's log, which is what makes the DID revoked; the
   * registry record is then updated as a derived index. Other DID methods are revoked in
   * the registry.
   */
  public async revokeDid(did: string, options: DidWebvhLifecycleOptions = {}): Promise<void> {
    return this.withDidLock(did, () => this.revokeDidLocked(did, options));
  }

  private async revokeDidLocked(did: string, options: DidWebvhLifecycleOptions): Promise<void> {
    const existing = await this.resolve(did);
    if (did.startsWith('did:webvh:')) {
      const { log, signer } = this.requireDidWebvhLifecycle(did, options.controllerSigner);
      const deactivated = await deactivateDidWebvhLog({ log, signer, ...this.didWebvhWitnessOptions(did) });
      this.storeDidWebvhLog(did, deactivated);
    }
    await this.registry.revoke(did);
    this.appendHistory(existing, 'revoked');
  }

  public async updateDidDocument(
    did: string,
    patch: UpdateAgentDocumentParams,
    options: DidWebvhLifecycleOptions = {}
  ): Promise<AgentDIDDocument> {
    return this.withDidLock(did, () => this.updateDidDocumentLocked(did, patch, options));
  }

  private async updateDidDocumentLocked(
    did: string,
    patch: UpdateAgentDocumentParams,
    options: DidWebvhLifecycleOptions
  ): Promise<AgentDIDDocument> {
    assertUpdatePatch(did, patch);

    const existing = await this.resolve(did);
    let updatedDocument = buildUpdatedDocument(existing, patch, this.nextTimestamp(existing.updated));

    if (did.startsWith('did:webvh:')) {
      updatedDocument = await this.appendDidWebvhEntry(did, updatedDocument, options.controllerSigner);
    }

    this.resolver.registerDocument(updatedDocument);
    await this.registry.setDocumentReference(did, computeDocumentReference(updatedDocument));
    this.appendHistory(updatedDocument, 'updated');
    return updatedDocument;
  }

  public async rotateVerificationMethod(
    did: string,
    options: RotateVerificationMethodOptions = {}
  ): Promise<RotateVerificationMethodResult> {
    return this.withDidLock(did, () => this.rotateVerificationMethodLocked(did, options));
  }

  private async rotateVerificationMethodLocked(
    did: string,
    options: RotateVerificationMethodOptions
  ): Promise<RotateVerificationMethodResult> {
    const existing = await this.resolve(did);
    const rotated = buildRotatedDocument(
      did,
      existing,
      this.nextTimestamp(existing.updated),
      options.signer ? await options.signer.getPublicKey() : undefined,
      options.emergency === true
    );
    let updatedDocument = rotated.document;

    if (did.startsWith('did:webvh:')) {
      updatedDocument = await this.appendDidWebvhEntry(did, updatedDocument, options.controllerSigner);
    }

    this.resolver.registerDocument(updatedDocument);
    await this.registry.setDocumentReference(did, computeDocumentReference(updatedDocument));
    this.appendHistory(updatedDocument, 'rotated-key');

    return withSigner({
      document: updatedDocument,
      verificationMethodId: rotated.verificationMethodId,
      agentPrivateKey: rotated.agentPrivateKey
    }, options.signer);
  }

  /**
   * Retires one key of `did` and leaves the others as they are (RFC-001 §6.6): the key gets a `deactivated` time and
   * leaves every verification relationship. A planned retirement ends the overlap of a rotation started with
   * `addVerificationMethod`; signatures under the key are then rejected (`rotation_window_closed` in the composition
   * contract). With `emergency` the key also gets `revoked` and is never accepted again, whatever time a signature
   * states (`emergency_revoked`); an already retired key can still be revoked this way.
   *
   * Refuses an unknown key, a key already retired (without `emergency`) or revoked, and the last `authentication` or
   * `assertionMethod` key: use `rotateVerificationMethod` or `revokeDid` for those.
   */
  public async retireVerificationMethod(
    did: string,
    keyId: string,
    options: RetireVerificationMethodOptions = {}
  ): Promise<AgentDIDDocument> {
    return this.withDidLock(did, () => this.retireVerificationMethodLocked(did, keyId, options));
  }

  private async retireVerificationMethodLocked(
    did: string,
    keyId: string,
    options: RetireVerificationMethodOptions
  ): Promise<AgentDIDDocument> {
    const existing = await this.resolve(did);
    const wasActive = existing.verificationMethod.some((method) => method.id === keyId && !method.deactivated);
    let updatedDocument = buildRetiredKeyDocument(
      existing,
      keyId,
      this.nextTimestamp(existing.updated),
      options.emergency === true
    );

    if (did.startsWith('did:webvh:')) {
      updatedDocument = await this.appendDidWebvhEntry(did, updatedDocument, options.controllerSigner);
    }

    this.resolver.registerDocument(updatedDocument);
    await this.registry.setDocumentReference(did, computeDocumentReference(updatedDocument));
    this.appendHistory(updatedDocument, wasActive ? 'rotated-key' : 'updated');
    return updatedDocument;
  }

  /**
   * Adds a key to the document of `did` without retiring any other key, listed under `options.relationships`
   * (default: `capabilityInvocation`). It is the first step of rotating the key that endorses the agents a DID
   * controls without unbinding them: add the new key, give each agent an entry signed by the new key, then retire
   * the old one with `rotateVerificationMethod` (RFC-001 §6.6 item 7).
   */
  public async addVerificationMethod(
    did: string,
    options: AddVerificationMethodOptions = {}
  ): Promise<AddVerificationMethodResult> {
    return this.withDidLock(did, () => this.addVerificationMethodLocked(did, options));
  }

  private async addVerificationMethodLocked(
    did: string,
    options: AddVerificationMethodOptions
  ): Promise<AddVerificationMethodResult> {
    const existing = await this.resolve(did);
    const added = buildAddedKeyDocument(
      did,
      existing,
      this.nextTimestamp(existing.updated),
      options.relationships ?? ['capabilityInvocation'],
      options.signer ? await options.signer.getPublicKey() : undefined
    );
    let updatedDocument = added.document;

    if (did.startsWith('did:webvh:')) {
      updatedDocument = await this.appendDidWebvhEntry(did, updatedDocument, options.controllerSigner);
    }

    this.resolver.registerDocument(updatedDocument);
    await this.registry.setDocumentReference(did, computeDocumentReference(updatedDocument));
    this.appendHistory(updatedDocument, 'updated');

    return withSigner({
      document: updatedDocument,
      verificationMethodId: added.verificationMethodId,
      agentPrivateKey: added.agentPrivateKey
    }, options.signer);
  }

  /**
   * Rotates the controller key of a did:webvh DID: appends a log entry whose `updateKeys` is
   * `newControllerSigner`'s key. This is the recovery path after a compromise of the controller key,
   * and it only works if the DID committed to a successor (pre-rotation: `webvh.nextUpdateKeys` at
   * creation, or a previous rotation that set `nextUpdateKeys`).
   *
   * - Pre-rotation active: `newControllerSigner` must be a committed key and signs the entry; the key
   *   that was active can no longer sign.
   * - Not active: the current controller signer (`options.controllerSigner`, or the one retained in this
   *   process) signs, and `nextUpdateKeys` may start pre-rotation.
   *
   * Commit to the following key in `nextUpdateKeys`, or the key you rotate to stays the only valid next key.
   */
  public async rotateControllerKey(did: string, options: RotateControllerKeyOptions): Promise<DidWebvhControllerKeys> {
    return this.withDidLock(did, () => this.rotateControllerKeyLocked(did, options));
  }

  private async rotateControllerKeyLocked(did: string, options: RotateControllerKeyOptions): Promise<DidWebvhControllerKeys> {
    if (!did.startsWith('did:webvh:')) {
      throw new Error(`did:webvh DID is required to rotate the controller key: ${did}`);
    }
    const log = this.didWebvhLogStore.get(did);
    if (!log) {
      throw new Error(`No did:webvh log for ${did} in this process; import it with importDidWebvhHistory first`);
    }
    const current = await resolveDidWebvhLog(log, { did, ...this.storedWitnessFileOption(did) });
    const signer = current.metadata.nextKeyHashes.length > 0
      ? options.newControllerSigner
      : options.controllerSigner ?? this.didWebvhSignerStore.get(did);
    if (!signer) {
      throw new Error(`A controller signer is required to change ${did}: pass options.controllerSigner`);
    }
    const newKey = await didWebvhUpdateKeyFor(options.newControllerSigner);
    const updated = await updateDidWebvhLog({
      log,
      signer,
      updateKeys: [newKey],
      ...(options.nextUpdateKeys !== undefined ? { nextUpdateKeys: options.nextUpdateKeys } : {}),
      ...this.didWebvhWitnessOptions(did)
    });
    this.storeDidWebvhLog(did, updated);
    this.didWebvhSignerStore.set(did, options.newControllerSigner);
    return { updateKeys: [...updated.metadata.updateKeys], nextKeyHashes: [...updated.metadata.nextKeyHashes] };
  }

  /** The controller keys of a did:webvh DID, from its verified log (including pre-rotation commitments). */
  public async getDidWebvhControllerKeys(did: string): Promise<DidWebvhControllerKeys> {
    const log = this.didWebvhLogStore.get(did);
    if (!did.startsWith('did:webvh:') || !log) {
      throw new Error(`No did:webvh log for ${did} in this process; import it with importDidWebvhHistory first`);
    }
    const { metadata } = await resolveDidWebvhLog(log, { did, ...this.storedWitnessFileOption(did) });
    return { updateKeys: [...metadata.updateKeys], nextKeyHashes: [...metadata.nextKeyHashes] };
  }

  /**
   * Sets, changes or (with `null`) removes the witnesses of a did:webvh DID (ADR-007) by appending a log entry. The
   * witnesses in force approve that entry (through `AgentDidClientOptions.collectWitnessProofs`); the new rule
   * governs the entries after it. Returns the witness configuration now in force.
   */
  public async setDidWebvhWitnesses(
    did: string,
    witness: DidWebvhWitnessConfig | null,
    options: DidWebvhLifecycleOptions = {}
  ): Promise<{ threshold: number; witnesses: string[] }> {
    return this.withDidLock(did, async () => {
      if (!did.startsWith('did:webvh:')) {
        throw new Error(`did:webvh DID is required to set witnesses: ${did}`);
      }
      const { log, signer } = this.requireDidWebvhLifecycle(did, options.controllerSigner);
      const updated = await updateDidWebvhLog({ log, signer, witness, ...this.didWebvhWitnessOptions(did) });
      this.storeDidWebvhLog(did, updated);
      return {
        threshold: Number(updated.metadata.witnessThreshold),
        witnesses: [...updated.metadata.witnesses]
      };
    });
  }

  /**
   * The `did-witness.json` of a did:webvh DID created, changed or imported in this process, or `undefined` when its
   * log has no witnessed entries. Publish it next to `did.jsonl`, and before it.
   */
  public exportDidWebvhWitnessFile(did: string): string | undefined {
    if (!did.startsWith('did:webvh:') || !this.didWebvhLogStore.has(did)) {
      throw new Error(`No did:webvh log for ${did} in this process; import it with importDidWebvhHistory first`);
    }
    return this.didWebvhWitnessStore.get(did);
  }

  public getDocumentHistory(did: string): AgentDocumentHistoryEntry[] {
    const history = this.documentHistoryStore.get(did) || [];
    return JSON.parse(JSON.stringify(history)) as AgentDocumentHistoryEntry[];
  }

  /** Returns the DID's did:webvh v1.0 log (`did.jsonl`) as created or imported in this process. */
  public exportDidWebvhHistory(did: string): string {
    if (!did.startsWith('did:webvh:')) {
      throw new Error(`did:webvh DID is required for history export: ${did}`);
    }
    const log = this.didWebvhLogStore.get(did);
    if (!log) {
      throw new Error(`No document history found for DID: ${did}`);
    }
    return log;
  }

  /**
   * Verifies a did:webvh v1.0 log (SCID, hash chain, controller-signed proofs) and loads it
   * into this process: latest document, registry record and document history. Changing the
   * DID afterwards requires its controller signer (`options.controllerSigner`).
   *
   * The imported log is a copy of what the log host serves. With a resolver that fetches logs, it is not cached
   * as the DID's current document: the next resolution fetches the host's log and the longer of the two wins.
   */
  public async importDidWebvhHistory(didLog: string, witnessFile?: string): Promise<AgentDIDDocument> {
    const resolved = await resolveDidWebvhLog(didLog, witnessFile !== undefined ? { witnessFile } : {});
    return this.withDidLock(resolved.did, () => this.importResolvedDidWebvhLog(resolved));
  }

  private async importResolvedDidWebvhLog(
    resolved: Awaited<ReturnType<typeof resolveDidWebvhLog>>
  ): Promise<AgentDIDDocument> {
    const did = resolved.did;
    assertAgentDidDocument(resolved.state, `The did:webvh state of ${did}`);
    const latestDocument = cloneDocument(resolved.state);
    const documentRef = computeDocumentReference(latestDocument);

    // A log can only replace the stored one by extending it: an older prefix (it would reinstate
    // a revoked DID or an earlier key set) or a different history is rejected. The same log is a no-op.
    const stored = this.didWebvhLogStore.get(did);
    const relation = stored === undefined ? 'extends' : compareDidWebvhLogs(stored, resolved.log);
    if (relation === 'prefix' || relation === 'diverged') {
      throw new DidWebvhError(
        'invalidInput',
        `did:webvh log for ${did} does not extend the log already stored in this client (${relation === 'prefix' ? 'it is older' : 'it diverges'})`
      );
    }
    if (relation === 'extends') {
      this.documentHistoryStore.set(did, historyFromDidWebvhLog(resolved.log));
      this.storeDidWebvhLog(did, resolved);
      // The retained controller signer stays only while its key is still one of the log's updateKeys.
      const signer = this.didWebvhSignerStore.get(did);
      if (signer && !resolved.metadata.updateKeys.includes(await didWebvhUpdateKeyFor(signer))) {
        this.didWebvhSignerStore.delete(did);
      }
    }

    // An imported log is a copy of what the log host serves, not an authority: a resolver that fetches logs must not
    // answer from it as a fresh entry, or an older prefix would be served until the entry expires. Dropping its entry
    // makes the next resolution fetch, and the longer of the fetched and the imported log wins at once. A DID whose
    // controller signer this client retains (created or changed here) is registered as before, and so is any DID when
    // the resolver cannot fetch logs (then the imported log is all there is: see the README).
    if (!this.didWebvhSignerStore.has(did) && this.resolver.resolveDidWebvhLog && this.resolver.evict) {
      this.resolver.evict(did);
    } else {
      this.resolver.registerDocument(latestDocument);
    }
    await this.registry.register(latestDocument.id, latestDocument.controller, documentRef);
    await this.registry.setDocumentReference(latestDocument.id, documentRef);
    if (resolved.metadata.deactivated) {
      await this.registry.revoke(did);
    }

    return latestDocument;
  }

  /**
   * Writes the DID's `did.jsonl` to `filePath`. A DID with witnessed entries also needs `witnessFilePath` for its
   * `did-witness.json` (written first, as when publishing).
   */
  public async saveDidWebvhHistoryToFile(did: string, filePath: string, witnessFilePath?: string): Promise<void> {
    const fs = await import('node:fs/promises');
    const log = this.exportDidWebvhHistory(did);
    const witnessFile = this.didWebvhWitnessStore.get(did);
    if (witnessFile !== undefined) {
      if (witnessFilePath === undefined) {
        throw new Error(`${did} has witnessed entries: pass witnessFilePath for its did-witness.json`);
      }
      await fs.writeFile(witnessFilePath, witnessFile, 'utf8');
    }
    await fs.writeFile(filePath, log, 'utf8');
  }

  /** Imports a `did.jsonl` file, with its `did-witness.json` when the log has witnessed entries. */
  public async loadDidWebvhHistoryFromFile(filePath: string, witnessFilePath?: string): Promise<AgentDIDDocument> {
    const fs = await import('node:fs/promises');
    const didLog = await fs.readFile(filePath, 'utf8');
    const witnessFile = witnessFilePath !== undefined ? await fs.readFile(witnessFilePath, 'utf8') : undefined;
    return this.importDidWebvhHistory(didLog, witnessFile);
  }

  /**
   * Stores the DID's log in `source` under `documentRef`. A DID with witnessed entries also needs `witnessRef`, where
   * its `did-witness.json` is stored first.
   */
  public async persistDidWebvhHistoryToSource(
    did: string,
    documentRef: string,
    source: DIDDocumentSource,
    witnessRef?: string
  ): Promise<void> {
    if (!source.storeDidLogByReference) {
      throw new Error('DIDDocumentSource does not support did:webvh log persistence');
    }
    const log = this.exportDidWebvhHistory(did);
    const witnessFile = this.didWebvhWitnessStore.get(did);
    if (witnessFile !== undefined) {
      if (witnessRef === undefined || !source.storeDidWitnessFileByReference) {
        throw new Error(`${did} has witnessed entries: pass witnessRef and a source that stores did-witness.json`);
      }
      await source.storeDidWitnessFileByReference(witnessRef, witnessFile);
    }

    await source.storeDidLogByReference(documentRef, log);
  }

  /** Imports a log from `source`, with its `did-witness.json` from `witnessRef` when given. */
  public async restoreDidWebvhHistoryFromSource(
    documentRef: string,
    source: DIDDocumentSource,
    witnessRef?: string
  ): Promise<AgentDIDDocument> {
    if (!source.getDidLogByReference) {
      throw new Error('DIDDocumentSource does not support did:webvh log retrieval');
    }

    const didLog = await source.getDidLogByReference(documentRef);
    if (!didLog) {
      throw new Error(`did:webvh DID log not found for reference: ${documentRef}`);
    }
    let witnessFile: string | undefined;
    if (witnessRef !== undefined) {
      if (!source.getDidWitnessFileByReference) {
        throw new Error('DIDDocumentSource does not support did:webvh witness file retrieval');
      }
      witnessFile = (await source.getDidWitnessFileByReference(witnessRef)) ?? undefined;
      if (witnessFile === undefined) {
        throw new Error(`did:webvh witness file not found for reference: ${witnessRef}`);
      }
    }

    return this.importDidWebvhHistory(didLog, witnessFile);
  }

  public setResolver(resolver: DIDResolver): void {
    this.resolver = resolver;
  }

  public setRegistry(registry: AgentRegistry): void {
    this.registry = registry;
  }

  public useProductionResolver(config: ProductionResolverProfileConfig): void {
    this.resolver = new UniversalResolverClient({
      registry: config.registry,
      documentSource: config.documentSource,
      wbaDocumentSource: config.wbaDocumentSource,
      webvhDocumentSource: config.webvhDocumentSource,
      fallbackResolver: this.resolver,
      didWebvhLocalLog: (did) => this.didWebvhLogStore.get(did),
      didWebvhLocalWitnessFile: (did) => this.didWebvhWitnessStore.get(did),
      cacheTtlMs: config.cacheTtlMs,
      maxCacheEntries: config.maxCacheEntries,
      onResolutionEvent: config.onResolutionEvent,
      unverifiedDocumentRefSchemes: config.unverifiedDocumentRefSchemes,
      resolutionLimits: config.resolutionLimits
    });
  }

  public useProductionResolverFromHttp(config: ProductionHttpResolverProfileConfig): void {
    const httpSource = new HttpDIDDocumentSource({
      referenceToUrl: config.referenceToUrl,
      referenceToUrls: config.referenceToUrls,
      fetchFn: config.fetchFn,
      ipfsGateways: config.ipfsGateways,
      httpSecurity: config.httpSecurity
    });
    const webvhSource = new WebvhDIDDocumentSource({
      referenceToUrl: config.referenceToUrl,
      referenceToUrls: config.referenceToUrls,
      fetchFn: config.fetchFn,
      httpSecurity: config.httpSecurity
    });

    this.useProductionResolver({
      registry: config.registry,
      documentSource: httpSource,
      wbaDocumentSource: httpSource,
      webvhDocumentSource: webvhSource,
      cacheTtlMs: config.cacheTtlMs,
      maxCacheEntries: config.maxCacheEntries,
      onResolutionEvent: config.onResolutionEvent,
      unverifiedDocumentRefSchemes: config.unverifiedDocumentRefSchemes,
      resolutionLimits: config.resolutionLimits
    });
  }

  public useProductionResolverFromJsonRpc(config: ProductionJsonRpcResolverProfileConfig): void {
    const rpcSource = new JsonRpcDIDDocumentSource({
      endpoint: config.endpoint,
      endpoints: config.endpoints,
      method: config.method,
      buildParams: config.buildParams,
      headers: config.headers,
      transport: config.transport,
      httpSecurity: config.httpSecurity
    });

    this.useProductionResolver({
      registry: config.registry,
      documentSource: rpcSource,
      cacheTtlMs: config.cacheTtlMs,
      maxCacheEntries: config.maxCacheEntries,
      onResolutionEvent: config.onResolutionEvent,
      resolutionLimits: config.resolutionLimits
    });
  }

  private nextTimestamp(previousTimestamp?: string): string {
    return nextDocumentTimestamp(this.clock(), previousTimestamp);
  }

  private appendHistory(document: AgentDIDDocument, action: AgentDocumentHistoryAction): void {
    const did = document.id;
    const currentHistory = this.documentHistoryStore.get(did) || [];
    const nextRevision = currentHistory.length + 1;

    const entry: AgentDocumentHistoryEntry = {
      did,
      revision: nextRevision,
      action,
      timestamp: this.nowIsoTimestamp(),
      version: document.agentMetadata.version,
      documentRef: computeDocumentReference(document)
    };

    this.documentHistoryStore.set(did, [...currentHistory, entry]);
  }
}

/** The raw public key of `keyId` when it is an active Ed25519 `assertionMethod` key of `document`. */
function activeAssertionKey(document: DidDocument, keyId: string): Uint8Array | undefined {
  return activeKeyUnder(document, keyId, 'assertionMethod');
}

/** The public key of `keyId` when it is an active Ed25519 key listed under `relationship` of `document`. */
function activeKeyUnder(document: DidDocument, keyId: string, relationship: VerificationRelationship): Uint8Array | undefined {
  const method = relationshipMethods(document, relationship).find((candidate) => candidate.id === keyId);
  return method === undefined ? undefined : activeEd25519PublicKey(method);
}
