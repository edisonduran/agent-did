import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import {
  AgentDocumentHistoryAction,
  AgentDocumentHistoryEntry,
  AgentDIDDocument,
  CreateAgentParams,
  CreateAgentResult,
  DidWebvhLifecycleOptions,
  RotateVerificationMethodResult,
  SignHttpRequestParams,
  UpdateAgentDocumentParams,
  VerifyHttpRequestSignatureParams,
  VerificationRelationship,
  VerificationMethod
} from './types';
import {
  createMetadataCommitment,
  generateAgentMetadataHash,
  generateCanonicalDocumentHash,
  generateCommitmentSalt
} from '../crypto/hash';
import { encodePublicKeyMultibase, decodePublicKeyMultibase, didKeyFromPublicKey } from '../crypto/multibase';
import { AgentSigner, LocalKeySigner } from './signer';
import { sha256 } from '@noble/hashes/sha256';
import {
  buildSignatureBase,
  getSignatureParam,
  parseSignatureHeader,
  parseSignatureInputHeader,
  serializeSignature,
  serializeSignatureInput,
  SignatureInput
} from './http-signatures';
import { InMemoryNonceStore, NonceStore } from './nonce-store';
import { validateHttpTarget } from './http-security';
import { DIDDocumentSource, DIDResolver, ResolverResolutionEvent } from '../resolver/types';
import { InMemoryDIDResolver } from '../resolver/InMemoryDIDResolver';
import { UniversalResolverClient } from '../resolver/UniversalResolverClient';
import { HttpDIDDocumentSource } from '../resolver/HttpDIDDocumentSource';
import { JsonRpcDIDDocumentSource } from '../resolver/JsonRpcDIDDocumentSource';
import { WebvhDIDDocumentSource } from '../resolver/WebvhDIDDocumentSource';
import { AgentRegistry } from '../registry/types';
import {
  createDidWebvhLog,
  deactivateDidWebvhLog,
  DID_WEBVH_PLACEHOLDER,
  resolveDidWebvhLog,
  updateDidWebvhLog
} from '../webvh/adapter';
import { InMemoryAgentRegistry } from '../registry/InMemoryAgentRegistry';
import { normalizeTimestampToIso } from './time';
import { assertKeyPurpose, assertSigningPurpose, getRelationshipKeyIds } from './identity-composition';
import { AGENT_DID_HTTP_SIGNATURE_COMPONENTS, AGENT_DID_HTTP_SIGNATURE_TAG, computeContentDigest } from './http-profile';

export interface ProductionResolverProfileConfig {
  registry: AgentRegistry;
  documentSource: DIDDocumentSource;
  wbaDocumentSource?: DIDDocumentSource;
  webvhDocumentSource?: DIDDocumentSource;
  cacheTtlMs?: number;
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
  httpSecurity?: import('./http-security').HttpTargetValidationOptions;
}

export interface ProductionJsonRpcResolverProfileConfig {
  registry: AgentRegistry;
  cacheTtlMs?: number;
  endpoint?: string;
  endpoints?: string[];
  method?: string;
  buildParams?: (documentRef: string) => unknown[];
  headers?: Record<string, string>;
  transport?: (url: string, body: string, headers: Record<string, string>) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;
  onResolutionEvent?: (event: ResolverResolutionEvent) => void;
  httpSecurity?: import('./http-security').HttpTargetValidationOptions;
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
  private readonly didWebvhStateCache: Map<string, { log: string; deactivated: boolean }> = new Map();
  /** Controller signers (did:webvh `updateKeys`) retained for DIDs created in this process. */
  private readonly didWebvhSignerStore: Map<string, AgentSigner> = new Map();
  /** Local bootstrap controllers, keyed by the creator's did:key. */
  private readonly bootstrapControllers: Map<string, { did: string; signer: AgentSigner }> = new Map();

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
  public async createAgent(
    controllerSigner: AgentSigner,
    network: string,
    params: CreateAgentParams
  ): Promise<CreateAgentResult> {
    const didMethod = params.didMethod || 'webvh';
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

    if (didMethod === 'webvh') {
      return this.createDidWebvhAgent(params, controllerKeyDid, {
        timestamp,
        agentMetadata,
        publicKeyBytes,
        privateKeyHex,
        metadataCommitmentSalts
      });
    }

    // Legacy did:agent profile
    const nonce = bytesToHex(randomBytes(16));
    const rawAgentId = bytesToHex(sha256(new TextEncoder().encode(`${controllerKeyDid}-${timestamp}-${nonce}`)));
    const agentDid = `did:agent:${network}:${rawAgentId}`;
    const controllerDid = controllerKeyDid;
    const verificationMethodId = `${agentDid}#key-1`;
    const document: AgentDIDDocument = {
      "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
      id: agentDid,
      controller: controllerDid,
      created: timestamp,
      updated: timestamp,
      agentMetadata,
      verificationMethod: [{
        id: verificationMethodId,
        type: "Ed25519VerificationKey2020",
        controller: controllerDid,
        publicKeyMultibase: encodePublicKeyMultibase(publicKeyBytes)
      }],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId]
    };

    this.resolver.registerDocument(document);
    await this.registry.register(document.id, document.controller, this.computeDocumentReference(document));
    this.appendHistory(document, 'created');

    return { document, agentPrivateKey: privateKeyHex, metadataCommitmentSalts };
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

    if (params.webvh?.domain?.trim()) {
      const options = this.requireWebvhCreateOptions(params);
      domain = options.domain.trim();
      pathSegments = options.pathSegments ?? [];
      controllerDid = options.controllerDid.trim();
      controllerSigner = options.controllerSigner;
    } else {
      // Only the implicit local profile bootstraps a controller. An explicitly supplied
      // controller DID must be published by its owner; the SDK never fabricates it.
      const bootstrap = await this.ensureBootstrapController(controllerKeyDid);
      domain = this.defaultWebvhDomain;
      pathSegments = ['agents', this.normalizeDidPathSegment(params.name)];
      controllerDid = bootstrap.did;
      controllerSigner = bootstrap.signer;
      controllerPrivateKey = bootstrap.privateKey;
    }

    const verificationMethodId = `${DID_WEBVH_PLACEHOLDER}#key-1`;
    const template = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
      id: DID_WEBVH_PLACEHOLDER,
      controller: controllerDid,
      created: agent.timestamp,
      updated: agent.timestamp,
      agentMetadata: agent.agentMetadata,
      verificationMethod: [{
        id: verificationMethodId,
        type: 'Ed25519VerificationKey2020',
        controller: controllerDid,
        publicKeyMultibase: encodePublicKeyMultibase(agent.publicKeyBytes)
      }],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId]
    };

    const created = await createDidWebvhLog({ domain, pathSegments, document: template, signer: controllerSigner });
    const document = this.cloneDocument(created.state as unknown as AgentDIDDocument);
    this.didWebvhLogStore.set(document.id, created.log);
    this.didWebvhSignerStore.set(document.id, controllerSigner);

    this.resolver.registerDocument(document);
    await this.registry.register(document.id, document.controller, this.computeDocumentReference(document));
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
      throw new Error('webvh.domain is required when didMethod is webvh');
    }
    if (!options.controllerDid?.trim()) {
      throw new Error('webvh.controllerDid is required when didMethod is webvh');
    }
    if (!options.controllerSigner) {
      throw new Error('webvh.controllerSigner is required: the controller key signs the did:webvh log (updateKeys)');
    }
    if ('scid' in (options as unknown as Record<string, unknown>)) {
      throw new Error('webvh.scid is no longer supported: did:webvh v1.0 derives the SCID from the genesis log entry');
    }
    return options;
  }

  private normalizeDidPathSegment(value: string): string {
    const normalized = value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    return normalized || 'agent';
  }

  /**
   * Returns the local bootstrap controller for a creator's `did:key`, creating it on first use.
   * Its did:webvh log is signed by a controller key generated with a CSPRNG; the key is
   * returned to the caller exactly once (`privateKey`) and never derived from public data.
   */
  private async ensureBootstrapController(
    controllerKeyDid: string
  ): Promise<{ did: string; signer: AgentSigner; privateKey?: string }> {
    const address = controllerKeyDid.trim();
    const keyId = address.replace(/^did:key:/u, '');
    const existing = this.bootstrapControllers.get(address);
    if (existing && await this.registry.getRecord(existing.did)) {
      return existing;
    }

    const [signer, privateKey] = LocalKeySigner.generate();
    const timestamp = this.nowIsoTimestamp();
    const verificationMethodId = `${DID_WEBVH_PLACEHOLDER}#key-1`;
    const template = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
      id: DID_WEBVH_PLACEHOLDER,
      controller: DID_WEBVH_PLACEHOLDER,
      created: timestamp,
      updated: timestamp,
      agentMetadata: {
        name: `controller-${this.normalizeDidPathSegment(keyId)}`,
        description: 'Local bootstrap controller root for canonical did:webvh flows.',
        version: '1.0.0',
        coreModelHash: generateAgentMetadataHash(`controller:${address}`),
        systemPromptHash: generateAgentMetadataHash('controller-bootstrap-root')
      },
      verificationMethod: [{
        id: verificationMethodId,
        type: 'Ed25519VerificationKey2020',
        controller: DID_WEBVH_PLACEHOLDER,
        publicKeyMultibase: encodePublicKeyMultibase(await signer.getPublicKey())
      }],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId]
    };

    const created = await createDidWebvhLog({
      domain: this.defaultWebvhDomain,
      pathSegments: ['controllers', this.normalizeDidPathSegment(keyId)],
      document: template,
      signer
    });
    const document = this.cloneDocument(created.state as unknown as AgentDIDDocument);
    this.didWebvhLogStore.set(document.id, created.log);
    this.didWebvhSignerStore.set(document.id, signer);
    this.bootstrapControllers.set(address, { did: document.id, signer });

    this.resolver.registerDocument(document);
    await this.registry.register(document.id, document.controller, this.computeDocumentReference(document));
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
    return this.cloneDocument(updated.state as unknown as AgentDIDDocument);
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

    return chain;
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
   * request is rejected. Returns `false` on any failure.
   */
  public async verifyHttpRequestSignature(params: VerifyHttpRequestSignatureParams): Promise<boolean> {
    const headers = Object.fromEntries(
      Object.entries(params.headers).map(([key, value]) => [key.toLowerCase(), value])
    );
    const signatureAgent = headers['signature-agent'];
    if (!headers['signature'] || !headers['signature-input'] || !signatureAgent) {
      return false;
    }
    if (headers['content-digest'] !== computeContentDigest(params.body)) {
      return false;
    }

    let inputs: Map<string, SignatureInput>;
    let signatures: Map<string, Uint8Array>;
    try {
      inputs = parseSignatureInputHeader(headers['signature-input']);
      signatures = parseSignatureHeader(headers['signature']);
    } catch {
      return false;
    }

    const now = Math.floor(this.clock().getTime() / 1000);
    const maxSkew = params.maxCreatedSkewSeconds ?? 300;
    const nonceStore = params.nonceStore ?? this.nonceStore;
    const request = { method: params.method.toUpperCase(), url: params.url, headers };

    for (const [label, input] of inputs) {
      const signature = signatures.get(label);
      if (!signature) {
        continue;
      }

      const created = getSignatureParam(input, 'created');
      const expires = getSignatureParam(input, 'expires');
      const nonce = getSignatureParam(input, 'nonce');
      const keyId = getSignatureParam(input, 'keyid');
      if (
        getSignatureParam(input, 'tag') !== AGENT_DID_HTTP_SIGNATURE_TAG ||
        getSignatureParam(input, 'alg') !== 'ed25519' ||
        typeof created !== 'number' ||
        typeof expires !== 'number' ||
        typeof nonce !== 'string' || nonce.length === 0 ||
        typeof keyId !== 'string' ||
        !keyId.startsWith(`${signatureAgent}#`) ||
        !AGENT_DID_HTTP_SIGNATURE_COMPONENTS.every((component) => input.components.includes(component)) ||
        Math.abs(now - created) > maxSkew ||
        expires < created ||
        now > expires
      ) {
        continue;
      }

      let signatureBase: string;
      try {
        signatureBase = buildSignatureBase(request, input);
      } catch {
        continue;
      }

      const isValid = await this.verifySignature(
        signatureAgent,
        signatureBase,
        bytesToHex(signature),
        keyId,
        'assertionMethod'
      );
      if (!isValid) {
        continue;
      }

      // Record the nonce only for a valid signature, so forged requests cannot burn nonces.
      return nonceStore.checkAndStore(`${keyId} ${nonce}`, expires);
    }

    return false;
  }

  /**
   * Verifies that a signature was produced by a specific Agent-DID.
   * Uses the configured resolver and registry to validate against active verification methods.
   */
  public async verifySignature(
    did: string,
    payload: string,
    signature: string,
    keyId?: string,
    requiredPurpose: VerificationRelationship = 'assertionMethod'
  ): Promise<boolean> {
    let verificationChain: AgentDIDDocument[];
    try {
      verificationChain = await this.resolveActiveVerificationChain(did);
    } catch {
      return false;
    }

    const didDoc = verificationChain[0];
    assertSigningPurpose(requiredPurpose, didDoc, keyId || '');
    if (keyId) {
      assertKeyPurpose(keyId, didDoc, requiredPurpose);
    }

    const messageBytes = new TextEncoder().encode(payload);
    const signatureBytes = hexToBytes(signature);

    const activeKeyIds = new Set(getRelationshipKeyIds(didDoc, requiredPurpose));
    const candidateMethods = didDoc.verificationMethod.filter((method) => {
      if (!method.publicKeyMultibase || method.deactivated) {
        return false;
      }

      if (keyId) {
        return method.id === keyId && activeKeyIds.has(method.id);
      }

      return activeKeyIds.has(method.id);
    });

    for (const verificationMethod of candidateMethods) {
      const keyValue = verificationMethod.publicKeyMultibase;
      if (!keyValue) continue;

      try {
        const publicKeyBytes = decodePublicKeyMultibase(keyValue);
        const valid = ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);

        if (valid) {
          return true;
        }
      } catch {
        continue;
      }
    }

    return false;
  }

  /**
   * Verifies a historical signature against deactivated (rotated-out) keys.
   * Unlike verifySignature(), this searches ALL verification methods including
   * those with a `deactivated` timestamp, enabling audit trail verification
   * for signatures created before a key rotation.
   */
  public async verifyHistoricalSignature(
    did: string,
    payload: string,
    signature: string,
    keyId: string,
    requiredPurpose: VerificationRelationship = 'assertionMethod'
  ): Promise<boolean> {
    let verificationChain: AgentDIDDocument[];
    try {
      verificationChain = await this.resolveActiveVerificationChain(did);
    } catch {
      return false;
    }

    const didDoc = verificationChain[0];
    assertSigningPurpose(requiredPurpose, didDoc, keyId);
    assertKeyPurpose(keyId, didDoc, requiredPurpose);

    const messageBytes = new TextEncoder().encode(payload);
    const signatureBytes = hexToBytes(signature);

    const candidate = didDoc.verificationMethod.find(
      (method) => method.id === keyId && method.publicKeyMultibase
    );

    if (!candidate?.publicKeyMultibase) {
      return false;
    }

    try {
      const publicKeyBytes = decodePublicKeyMultibase(candidate.publicKeyMultibase);
      return ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
    } catch {
      return false;
    }
  }

  /**
   * Resolves a DID into its corresponding Agent-DID Document.
   * Uses the configured resolver (in-memory or production) to retrieve the document.
   */
  public async resolve(did: string): Promise<AgentDIDDocument> {
    if (did.startsWith('did:webvh:')) {
      // For did:webvh the verified log is the only source of revocation state: a DID is
      // revoked only by a controller-signed deactivation entry. The registry record is a
      // derived index and is not consulted. DIDs without a local log are resolved (and their
      // logs verified) by the configured resolver.
      if (await this.isDidWebvhDeactivated(did)) {
        throw new Error(`DID is revoked: ${did}`);
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
   * Whether the locally stored did:webvh log ends in a deactivation entry. The log is
   * verified (SCID, hash chain, controller proofs) before its state is trusted; a log that
   * fails verification is an error, never "not revoked". Returns false when no log is
   * stored for the DID.
   */
  private async isDidWebvhDeactivated(did: string): Promise<boolean> {
    const log = this.didWebvhLogStore.get(did);
    if (log === undefined) {
      return false;
    }
    const cached = this.didWebvhStateCache.get(did);
    if (cached?.log === log) {
      return cached.deactivated;
    }
    const resolved = await resolveDidWebvhLog(log, { did });
    this.didWebvhStateCache.set(did, { log, deactivated: resolved.metadata.deactivated });
    return resolved.metadata.deactivated;
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
    if (!did?.trim()) {
      throw new Error('DID is required');
    }

    if (patch.coreModel && !patch.coreModelSalt) {
      throw new Error('coreModelSalt is required when updating coreModel (use generateCommitmentSalt() and keep it private)');
    }
    if (patch.systemPrompt && !patch.systemPromptSalt) {
      throw new Error('systemPromptSalt is required when updating systemPrompt (use generateCommitmentSalt() and keep it private)');
    }

    const existing = await this.resolve(did);
    const now = this.nextDocumentTimestamp(existing.updated);

    let updatedDocument: AgentDIDDocument = {
      ...existing,
      updated: now,
      agentMetadata: {
        ...existing.agentMetadata,
        description: patch.description ?? existing.agentMetadata.description,
        version: patch.version ?? existing.agentMetadata.version,
        coreModelHash: patch.coreModel
          ? createMetadataCommitment(patch.coreModel, patch.coreModelSalt as string)
          : existing.agentMetadata.coreModelHash,
        systemPromptHash: patch.systemPrompt
          ? createMetadataCommitment(patch.systemPrompt, patch.systemPromptSalt as string)
          : existing.agentMetadata.systemPromptHash,
        capabilities: patch.capabilities ?? existing.agentMetadata.capabilities,
        memberOf: patch.memberOf ?? existing.agentMetadata.memberOf
      },
      complianceCertifications: patch.complianceCertifications ?? existing.complianceCertifications
    };

    if (did.startsWith('did:webvh:')) {
      updatedDocument = await this.appendDidWebvhEntry(did, updatedDocument, options.controllerSigner);
    }

    this.resolver.registerDocument(updatedDocument);
    await this.registry.setDocumentReference(did, this.computeDocumentReference(updatedDocument));
    this.appendHistory(updatedDocument, 'updated');
    return updatedDocument;
  }

  public async rotateVerificationMethod(
    did: string,
    options: DidWebvhLifecycleOptions = {}
  ): Promise<RotateVerificationMethodResult> {
    const existing = await this.resolve(did);
    const keyIndexes = existing.verificationMethod
      .map((method) => {
        const match = method.id.match(/#key-(\d+)$/);
        return match ? Number(match[1]) : 0;
      });

    const nextIndex = (keyIndexes.length ? Math.max(...keyIndexes) : 0) + 1;
    const verificationMethodId = `${did}#key-${nextIndex}`;

    const privateKeyBytes = ed25519.utils.randomPrivateKey();
    const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);
    const privateKeyHex = bytesToHex(privateKeyBytes);

    const newVerificationMethod: VerificationMethod = {
      id: verificationMethodId,
      type: 'Ed25519VerificationKey2020',
      controller: existing.controller,
      publicKeyMultibase: encodePublicKeyMultibase(publicKeyBytes)
    };

    const deactivatedTimestamp = this.nextDocumentTimestamp(existing.updated);
    const deactivatedMethods = existing.verificationMethod.map((method) => ({
      ...method,
      deactivated: method.deactivated || deactivatedTimestamp
    }));

    let updatedDocument: AgentDIDDocument = {
      ...existing,
      updated: deactivatedTimestamp,
      verificationMethod: [...deactivatedMethods, newVerificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: Array.from(new Set([...(existing.assertionMethod || []), verificationMethodId]))
    };

    if (did.startsWith('did:webvh:')) {
      updatedDocument = await this.appendDidWebvhEntry(did, updatedDocument, options.controllerSigner);
    }

    this.resolver.registerDocument(updatedDocument);
    await this.registry.setDocumentReference(did, this.computeDocumentReference(updatedDocument));
    this.appendHistory(updatedDocument, 'rotated-key');

    return {
      document: updatedDocument,
      verificationMethodId,
      agentPrivateKey: privateKeyHex
    };
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
    const latestDocument = this.cloneDocument(resolved.state as unknown as AgentDIDDocument);
    const documentRef = this.computeDocumentReference(latestDocument);

    this.documentHistoryStore.set(did, this.historyFromDidWebvhLog(resolved.log));
    this.didWebvhLogStore.set(did, resolved.log);
    this.didWebvhSignerStore.delete(did);

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
      cacheTtlMs: config.cacheTtlMs,
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
      onResolutionEvent: config.onResolutionEvent
    });
  }

  private computeDocumentReference(document: AgentDIDDocument): string {
    return generateCanonicalDocumentHash(document);
  }

  /** History entries for a verified did:webvh log, one per log entry. */
  private historyFromDidWebvhLog(log: string): AgentDocumentHistoryEntry[] {
    let previous: AgentDIDDocument | undefined;
    return log
      .split(/\r?\n/u)
      .filter((line) => line.trim().length > 0)
      .map((line, index) => {
        const entry = JSON.parse(line) as {
          versionTime: string;
          parameters?: { deactivated?: boolean };
          state: AgentDIDDocument;
        };
        const document = this.cloneDocument(entry.state);
        let action: AgentDocumentHistoryAction = 'updated';
        if (index === 0 || !previous) {
          action = 'created';
        } else if (entry.parameters?.deactivated === true) {
          action = 'revoked';
        } else if (document.verificationMethod.length !== previous.verificationMethod.length) {
          action = 'rotated-key';
        }
        previous = document;
        return {
          did: document.id,
          revision: index + 1,
          action,
          timestamp: entry.versionTime,
          version: document.agentMetadata?.version,
          documentRef: this.computeDocumentReference(document)
        };
      });
  }

  private cloneDocument(document: AgentDIDDocument): AgentDIDDocument {
    return JSON.parse(JSON.stringify(document)) as AgentDIDDocument;
  }

  private nextDocumentTimestamp(previousTimestamp?: string): string {
    const now = this.clock().getTime();
    const previous = previousTimestamp ? Date.parse(previousTimestamp) : Number.NaN;

    if (!Number.isNaN(previous) && now <= previous) {
      return normalizeTimestampToIso(new Date(previous + 1).toISOString()) as string;
    }

    return this.nowIsoTimestamp();
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
      documentRef: this.computeDocumentReference(document)
    };

    this.documentHistoryStore.set(did, [...currentHistory, entry]);
  }
}
