import {
  AddVerificationMethodOptions,
  AddVerificationMethodResult,
  AgentDocumentHistoryAction,
  AgentDocumentHistoryEntry,
  AgentDIDDocument,
  CreateAgentParams,
  CreateAgentResult,
  DidWebvhControllerKeys,
  DidWebvhLifecycleOptions,
  RotateControllerKeyOptions,
  RotateVerificationMethodOptions,
  RotateVerificationMethodResult,
  UpdateAgentDocumentParams,
  VerifyHttpRequestSignatureParams,
  VerifyHttpRequestSignatureResult,
  VerifySignatureAtTimeOptions,
  VerifySignatureAtTimeResult,
  VerificationRelationship
} from './types';
import { createMetadataCommitment, generateCommitmentSalt } from '../crypto/hash';
import { didKeyFromPublicKey } from '../crypto/multibase';
import { AgentSigner, LocalKeySigner } from './signer';
import { InMemoryNonceStore, NonceStore } from './nonce-store';
import { DIDDocumentSource, DIDResolver, DidWebvhState, ResolverResolutionEvent } from '../resolver/types';
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
  buildRotatedDocument,
  buildUpdatedDocument,
  nextDocumentTimestamp
} from '../lifecycle/documents';
import { verifyWithActiveKeys } from '../verification/signature';
import { checkDidWebvhKeyAtTime, signatureResultForKey } from '../verification/key-at-time';
import { SignatureCheckOutcome, verifyAgentDidHttpRequest } from '../http-signatures/verify-request';
import { IdentityCompositionError, REQUIRED_RELATIONSHIP_BY_ARTIFACT } from './identity-composition';
import { InMemoryAgentRegistry } from '../registry/InMemoryAgentRegistry';
import { normalizeTimestampToIso } from './time';
import { messageSigningInput } from './message-signing';
import { assertBoundToController, ControllerBindingError } from './controller-binding';

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
  /**
   * Deactivation state derived from the verified log, keyed by DID and tied to the exact
   * log text it was computed from. It is recomputed whenever the stored log changes.
   */
  private readonly didWebvhStateCache: Map<string, { log: string; deactivated: boolean; document: AgentDIDDocument }> = new Map();
  /** Controller signers (did:webvh `updateKeys`) retained for DIDs created in this process. */
  private readonly didWebvhSignerStore: Map<string, AgentSigner> = new Map();
  /** Local bootstrap controllers, keyed by the creator's did:key. */
  private readonly bootstrapControllers: Map<string, { did: string; signer: AgentSigner }> = new Map();
  /** Serializes the creation of a bootstrap controller per creator key. */
  private readonly bootstrapControllerLocks: Map<string, Promise<void>> = new Map();

  constructor(options: AgentDidClientOptions = {}) {
    this.resolver = options.resolver ?? new InMemoryDIDResolver();
    this.registry = options.registry ?? new InMemoryAgentRegistry();
    this.nonceStore = options.nonceStore ?? new InMemoryNonceStore();
    this.clock = options.clock ?? (() => new Date());
    this.defaultWebvhDomain = options.webvhDomain ?? 'agents.local';
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

    // Commit to the sensitive metadata with salted HMACs so it cannot be guessed by dictionary
    const metadataCommitmentSalts = {
      coreModel: params.coreModelSalt ?? generateCommitmentSalt(),
      systemPrompt: params.systemPromptSalt ?? generateCommitmentSalt()
    };
    const agentMetadata = {
      name: params.name,
      description: params.description,
      version: params.version || '1.0.0',
      coreModelHash: createMetadataCommitment(params.coreModel, metadataCommitmentSalts.coreModel),
      systemPromptHash: createMetadataCommitment(params.systemPrompt, metadataCommitmentSalts.systemPrompt),
      capabilities: params.capabilities || [],
      memberOf: params.memberOf
    };

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

    if (params.webvh?.domain?.trim()) {
      const options = this.requireWebvhCreateOptions(params);
      domain = options.domain.trim();
      pathSegments = options.pathSegments ?? [];
      controllerDid = options.controllerDid.trim();
      controllerSigner = options.controllerSigner;
      nextUpdateKeys = options.nextUpdateKeys;
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
      ...(nextUpdateKeys !== undefined ? { nextUpdateKeys } : {})
    });
    const document = cloneDocument(created.state as unknown as AgentDIDDocument);
    this.didWebvhLogStore.set(document.id, created.log);
    this.didWebvhSignerStore.set(document.id, controllerSigner);

    this.resolver.registerDocument(document);
    await this.registry.register(document.id, document.controller, computeDocumentReference(document));
    this.appendHistory(document, 'created');

    return {
      document,
      agentPrivateKey: agent.privateKeyHex,
      ...(controllerPrivateKey ? { controllerPrivateKey } : {}),
      metadataCommitmentSalts: agent.metadataCommitmentSalts
    };
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
    this.didWebvhLogStore.set(document.id, created.log);
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
    const updated = await updateDidWebvhLog({ log, signer, document: document as unknown as Record<string, unknown> });
    this.didWebvhLogStore.set(did, updated.log);
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

  private async resolveActiveVerificationChain(did: string): Promise<AgentDIDDocument[]> {
    const chain = did.startsWith('did:webvh:')
      ? await this.resolveControllerChain(did)
      : [await this.resolve(did)];

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
  private async assertControllerChainBound(chain: AgentDIDDocument[]): Promise<void> {
    for (let index = 0; index + 1 < chain.length; index += 1) {
      const agent = chain[index];
      const controller = chain[index + 1];
      const state = agent.id.startsWith('did:webvh:') ? await this.resolveDidWebvhState(agent.id) : undefined;
      if (!state) {
        throw new ControllerBindingError(agent.id, controller.id, 'no did:webvh log is available to check the binding');
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
    const resolved = await resolveDidWebvhLog(log, { did });
    return {
      document: cloneDocument(resolved.state as unknown as AgentDIDDocument),
      log: resolved.log,
      versionId: resolved.metadata.versionId,
      updateKeys: [...resolved.metadata.updateKeys],
      lastEntrySignerKeys: didWebvhLastEntrySigners(resolved.log),
      provenance
    };
  }

  private hasActiveVerificationMethod(document: AgentDIDDocument): boolean {
    return document.verificationMethod.some((method) => Boolean(method.publicKeyMultibase) && !method.deactivated);
  }

  /**
   * Verifies an Agent-DID RFC 9421 HTTP Message Signature.
   *
   * Requires the Agent-DID profile (covered components, `tag="agent-did"`, `alg="ed25519"`,
   * `created`, `expires`, `nonce`, a `keyid` under the `Signature-Agent` DID), a matching
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

  /** `verifySignature` that tells apart the ways a verification can fail. */
  private async checkSignature(
    did: string,
    payload: string,
    signature: string,
    keyId: string,
    requiredPurpose: VerificationRelationship
  ): Promise<SignatureCheckOutcome> {
    let verificationChain: AgentDIDDocument[];
    try {
      verificationChain = await this.resolveActiveVerificationChain(did);
    } catch (error) {
      return error instanceof ControllerBindingError ? 'controller_not_bound' : 'did_resolution_failed';
    }
    try {
      return verifyWithActiveKeys(verificationChain[0], payload, signature, keyId, requiredPurpose) ? 'valid' : 'invalid';
    } catch (error) {
      if (error instanceof IdentityCompositionError) {
        return 'key_not_authorized';
      }
      throw error;
    }
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
    let verificationChain: AgentDIDDocument[];
    try {
      verificationChain = await this.resolveActiveVerificationChain(did);
    } catch {
      return false;
    }

    return verifyWithActiveKeys(verificationChain[0], messageSigningInput(payload), signature, keyId, requiredPurpose);
  }

  /**
   * Verifies a signature made with `keyId` at the time the signed artifact states (RFC-001 §6.2.2), using the
   * DID's did:webvh log as created or imported in this client (`importDidWebvhHistory`).
   *
   * - `valid`: the signature verifies and the key was authorized for `requiredPurpose` at `statedTime`, with no
   *   later change that retires it, or with `trustedTimeNotAfter` earlier than that change.
   * - `invalid`: the signature does not verify, the key was not authorized at `statedTime`, or the log fails
   *   verification.
   * - `indeterminate`: the key was retired or the DID deactivated after `statedTime` and there is no trusted
   *   time evidence, or this client has no did:webvh log for the DID. Do not accept it.
   *
   * The stated time is asserted by the signer, so a retired key is never accepted on the signer's word alone.
   */
  public async verifySignatureAtTime(
    did: string,
    payload: string,
    signature: string,
    keyId: string,
    options: VerifySignatureAtTimeOptions
  ): Promise<VerifySignatureAtTimeResult> {
    const log = did.startsWith('did:webvh:') ? this.didWebvhLogStore.get(did) : undefined;
    if (log === undefined) {
      return { status: 'indeterminate', key: { status: 'indeterminate', keyId, reason: 'history_unavailable' } };
    }
    let key;
    try {
      key = await checkDidWebvhKeyAtTime(log, { ...options, did, keyId });
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
        await this.assertDidWebvhBoundNow(did);
      } catch (error) {
        if (error instanceof ControllerBindingError) {
          return { status: 'invalid', reason: 'controller_not_bound', key: result.key };
        }
        throw error;
      }
    }
    return result;
  }

  /** The binding of `did` (and of its controllers) to its controller chain as it is now, from the client's own log. */
  private async assertDidWebvhBoundNow(did: string): Promise<void> {
    const state = await this.resolveDidWebvhState(did);
    const document = state?.document;
    if (!document || !document.controller?.trim() || document.controller === did) {
      return;
    }
    let controllers: AgentDIDDocument[];
    try {
      controllers = await this.resolveControllerChain(document.controller);
    } catch (error) {
      throw new ControllerBindingError(did, document.controller, `the controller does not resolve (${String(error)})`);
    }
    await this.assertControllerChainBound([document, ...controllers]);
  }

  /**
   * Resolves a DID into its corresponding Agent-DID Document.
   * Uses the configured resolver (in-memory or production) to retrieve the document.
   */
  public async resolve(did: string): Promise<AgentDIDDocument> {
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
      return this.resolver.resolve(did);
    }

    const isRevoked = await this.registry.isRevoked(did);

    if (isRevoked) {
      throw new Error(`DID is revoked: ${did}`);
    }

    return this.resolver.resolve(did);
  }

  /**
   * State of the locally stored did:webvh log: whether it ends in a deactivation entry and its
   * latest document. The log is verified (SCID, hash chain, controller proofs) before its state is
   * trusted; a log that fails verification is an error, never "not revoked". Returns undefined when
   * no log is stored for the DID.
   */
  private async didWebvhState(did: string): Promise<{ deactivated: boolean; document: AgentDIDDocument } | undefined> {
    const log = this.didWebvhLogStore.get(did);
    if (log === undefined) {
      return undefined;
    }
    const cached = this.didWebvhStateCache.get(did);
    if (cached?.log === log) {
      return cached;
    }
    const resolved = await resolveDidWebvhLog(log, { did });
    const state = {
      log,
      deactivated: resolved.metadata.deactivated,
      document: cloneDocument(resolved.state as unknown as AgentDIDDocument)
    };
    this.didWebvhStateCache.set(did, state);
    return state;
  }

  public async resolveControllerChain(did: string, maxDepth = 8): Promise<AgentDIDDocument[]> {
    if (!Number.isInteger(maxDepth) || maxDepth < 1) {
      throw new Error('maxDepth must be a positive integer');
    }

    const chain: AgentDIDDocument[] = [];
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
      const current = await this.resolve(currentDid);
      chain.push(current);

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
    const existing = await this.resolve(did);
    if (did.startsWith('did:webvh:')) {
      const { log, signer } = this.requireDidWebvhLifecycle(did, options.controllerSigner);
      const deactivated = await deactivateDidWebvhLog({ log, signer });
      this.didWebvhLogStore.set(did, deactivated.log);
    }
    await this.registry.revoke(did);
    this.appendHistory(existing, 'revoked');
  }

  public async updateDidDocument(
    did: string,
    patch: UpdateAgentDocumentParams,
    options: DidWebvhLifecycleOptions = {}
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
    const existing = await this.resolve(did);
    const rotated = buildRotatedDocument(
      did,
      existing,
      this.nextTimestamp(existing.updated),
      options.signer ? await options.signer.getPublicKey() : undefined
    );
    let updatedDocument = rotated.document;

    if (did.startsWith('did:webvh:')) {
      updatedDocument = await this.appendDidWebvhEntry(did, updatedDocument, options.controllerSigner);
    }

    this.resolver.registerDocument(updatedDocument);
    await this.registry.setDocumentReference(did, computeDocumentReference(updatedDocument));
    this.appendHistory(updatedDocument, 'rotated-key');

    return {
      document: updatedDocument,
      verificationMethodId: rotated.verificationMethodId,
      agentPrivateKey: rotated.agentPrivateKey
    };
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

    return {
      document: updatedDocument,
      verificationMethodId: added.verificationMethodId,
      agentPrivateKey: added.agentPrivateKey
    };
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
    if (!did.startsWith('did:webvh:')) {
      throw new Error(`did:webvh DID is required to rotate the controller key: ${did}`);
    }
    const log = this.didWebvhLogStore.get(did);
    if (!log) {
      throw new Error(`No did:webvh log for ${did} in this process; import it with importDidWebvhHistory first`);
    }
    const current = await resolveDidWebvhLog(log, { did });
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
      ...(options.nextUpdateKeys !== undefined ? { nextUpdateKeys: options.nextUpdateKeys } : {})
    });
    this.didWebvhLogStore.set(did, updated.log);
    this.didWebvhSignerStore.set(did, options.newControllerSigner);
    return { updateKeys: [...updated.metadata.updateKeys], nextKeyHashes: [...updated.metadata.nextKeyHashes] };
  }

  /** The controller keys of a did:webvh DID, from its verified log (including pre-rotation commitments). */
  public async getDidWebvhControllerKeys(did: string): Promise<DidWebvhControllerKeys> {
    const log = this.didWebvhLogStore.get(did);
    if (!did.startsWith('did:webvh:') || !log) {
      throw new Error(`No did:webvh log for ${did} in this process; import it with importDidWebvhHistory first`);
    }
    const { metadata } = await resolveDidWebvhLog(log, { did });
    return { updateKeys: [...metadata.updateKeys], nextKeyHashes: [...metadata.nextKeyHashes] };
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
   */
  public async importDidWebvhHistory(didLog: string): Promise<AgentDIDDocument> {
    const resolved = await resolveDidWebvhLog(didLog);
    const did = resolved.did;
    const latestDocument = cloneDocument(resolved.state as unknown as AgentDIDDocument);
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
      this.didWebvhLogStore.set(did, resolved.log);
      // The retained controller signer stays only while its key is still one of the log's updateKeys.
      const signer = this.didWebvhSignerStore.get(did);
      if (signer && !resolved.metadata.updateKeys.includes(await didWebvhUpdateKeyFor(signer))) {
        this.didWebvhSignerStore.delete(did);
      }
    }

    this.resolver.registerDocument(latestDocument);
    await this.registry.register(latestDocument.id, latestDocument.controller, documentRef);
    await this.registry.setDocumentReference(latestDocument.id, documentRef);
    if (resolved.metadata.deactivated) {
      await this.registry.revoke(did);
    }

    return latestDocument;
  }

  public async saveDidWebvhHistoryToFile(did: string, filePath: string): Promise<void> {
    const fs = await import('node:fs/promises');
    await fs.writeFile(filePath, this.exportDidWebvhHistory(did), 'utf8');
  }

  public async loadDidWebvhHistoryFromFile(filePath: string): Promise<AgentDIDDocument> {
    const fs = await import('node:fs/promises');
    const didLog = await fs.readFile(filePath, 'utf8');
    return this.importDidWebvhHistory(didLog);
  }

  public async persistDidWebvhHistoryToSource(
    did: string,
    documentRef: string,
    source: DIDDocumentSource
  ): Promise<void> {
    if (!source.storeDidLogByReference) {
      throw new Error('DIDDocumentSource does not support did:webvh log persistence');
    }

    await source.storeDidLogByReference(documentRef, this.exportDidWebvhHistory(did));
  }

  public async restoreDidWebvhHistoryFromSource(
    documentRef: string,
    source: DIDDocumentSource
  ): Promise<AgentDIDDocument> {
    if (!source.getDidLogByReference) {
      throw new Error('DIDDocumentSource does not support did:webvh log retrieval');
    }

    const didLog = await source.getDidLogByReference(documentRef);
    if (!didLog) {
      throw new Error(`did:webvh DID log not found for reference: ${documentRef}`);
    }

    return this.importDidWebvhHistory(didLog);
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
      cacheTtlMs: config.cacheTtlMs,
      maxCacheEntries: config.maxCacheEntries,
      onResolutionEvent: config.onResolutionEvent,
      unverifiedDocumentRefSchemes: config.unverifiedDocumentRefSchemes
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
      unverifiedDocumentRefSchemes: config.unverifiedDocumentRefSchemes
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
      onResolutionEvent: config.onResolutionEvent
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
