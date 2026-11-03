import { ethers } from 'ethers';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
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
import { encodePublicKeyMultibase, decodePublicKeyMultibase } from '../crypto/multibase';
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

export interface AgentIdentityConfig {
  signer: ethers.Signer; // The Creator's Wallet (Controller)
  network?: string; // e.g., 'polygon', 'base', 'ethereum'
}

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

/** Components every Agent-DID HTTP Message Signature covers (RFC 9421). */
export const AGENT_DID_HTTP_SIGNATURE_COMPONENTS: readonly string[] = [
  '@method',
  '@authority',
  '@path',
  '@query',
  'content-digest',
  'date',
  'signature-agent'
];

/** RFC 9421 `tag` parameter of Agent-DID HTTP Message Signatures. */
export const AGENT_DID_HTTP_SIGNATURE_TAG = 'agent-did';

export class AgentIdentity {
  /** Default replay store for `verifyHttpRequestSignature` (process-local). */
  private static readonly defaultNonceStore: NonceStore = new InMemoryNonceStore();
  private static readonly defaultWebvhDomain = 'agents.local';
  private static resolver: DIDResolver = new InMemoryDIDResolver();
  private static registry: AgentRegistry = new InMemoryAgentRegistry();
  private static readonly documentHistoryStore: Map<string, AgentDocumentHistoryEntry[]> = new Map();
  /** did:webvh v1.0 logs (`did.jsonl`) of the DIDs created or imported in this process. */
  private static readonly didWebvhLogStore: Map<string, string> = new Map();
  /** Controller signers (did:webvh `updateKeys`) retained for DIDs created in this process. */
  private static readonly didWebvhSignerStore: Map<string, AgentSigner> = new Map();
  /** Local bootstrap controllers, keyed by lowercase controller wallet address. */
  private static readonly bootstrapControllers: Map<string, { did: string; signer: AgentSigner }> = new Map();
  private readonly signer: ethers.Signer;
  private readonly network: string;

  constructor(config: AgentIdentityConfig) {
    this.signer = config.signer;
    this.network = config.network || 'polygon';
  }

  private static nowIsoTimestamp(): string {
    return normalizeTimestampToIso(new Date().toISOString()) as string;
  }

  /**
   * Creates a new Agent-DID Document (Passport) from raw parameters.
   * Automatically hashes sensitive IP (coreModel, systemPrompt) and generates the DID.
   * 
   * @param params The raw agent configuration (name, prompt, capabilities, etc.)
   * @returns A fully formed AgentDIDDocument compliant with RFC-001 and the Agent's private key
   */
  public async create(params: CreateAgentParams): Promise<CreateAgentResult> {
    const controllerAddress = await this.signer.getAddress();
    const didMethod = params.didMethod || 'webvh';
    const timestamp = AgentIdentity.nowIsoTimestamp();

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
      return this.createDidWebvhAgent(params, controllerAddress, {
        timestamp,
        agentMetadata,
        publicKeyBytes,
        privateKeyHex,
        metadataCommitmentSalts
      });
    }

    // Legacy did:agent profile
    const nonce = ethers.hexlify(ethers.randomBytes(16));
    const rawAgentId = ethers.keccak256(ethers.toUtf8Bytes(`${controllerAddress}-${timestamp}-${nonce}`));
    const agentDid = `did:agent:${this.network}:${rawAgentId}`;
    const controllerDid = `did:ethr:${controllerAddress}`;
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
        publicKeyMultibase: encodePublicKeyMultibase(publicKeyBytes),
        blockchainAccountId: `eip155:1:${ethers.Wallet.createRandom().address}`
      }],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId]
    };

    AgentIdentity.resolver.registerDocument(document);
    await AgentIdentity.registry.register(document.id, document.controller, AgentIdentity.computeDocumentReference(document));
    AgentIdentity.appendHistory(document, 'created');

    return { document, agentPrivateKey: privateKeyHex, metadataCommitmentSalts };
  }

  /**
   * Canonical did:webvh v1.0 profile: the agent document is the genesis entry of a
   * `did.jsonl` log signed by the controller key (the log's only `updateKeys` entry).
   */
  private async createDidWebvhAgent(
    params: CreateAgentParams,
    controllerAddress: string,
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
      const options = AgentIdentity.requireWebvhCreateOptions(params);
      domain = options.domain.trim();
      pathSegments = options.pathSegments ?? [];
      controllerDid = options.controllerDid.trim();
      controllerSigner = options.controllerSigner;
    } else {
      // Only the implicit local profile bootstraps a controller. An explicitly supplied
      // controller DID must be published by its owner; the SDK never fabricates it.
      const bootstrap = await AgentIdentity.ensureBootstrapController(controllerAddress);
      domain = AgentIdentity.defaultWebvhDomain;
      pathSegments = ['agents', AgentIdentity.normalizeDidPathSegment(params.name)];
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
    const document = AgentIdentity.cloneDocument(created.state as unknown as AgentDIDDocument);
    AgentIdentity.didWebvhLogStore.set(document.id, created.log);
    AgentIdentity.didWebvhSignerStore.set(document.id, controllerSigner);

    AgentIdentity.resolver.registerDocument(document);
    await AgentIdentity.registry.register(document.id, document.controller, AgentIdentity.computeDocumentReference(document));
    AgentIdentity.appendHistory(document, 'created');

    return {
      document,
      agentPrivateKey: agent.privateKeyHex,
      ...(controllerPrivateKey ? { controllerPrivateKey } : {}),
      metadataCommitmentSalts: agent.metadataCommitmentSalts
    };
  }

  private static requireWebvhCreateOptions(params: CreateAgentParams): NonNullable<CreateAgentParams['webvh']> {
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

  private static normalizeDidPathSegment(value: string): string {
    const normalized = value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    return normalized || 'agent';
  }

  /**
   * Returns the local bootstrap controller for a wallet address, creating it on first use.
   * Its did:webvh log is signed by a controller key generated with a CSPRNG; the key is
   * returned to the caller exactly once (`privateKey`) and never derived from public data.
   */
  private static async ensureBootstrapController(
    controllerAddress: string
  ): Promise<{ did: string; signer: AgentSigner; privateKey?: string }> {
    const address = controllerAddress.trim().toLowerCase();
    const existing = AgentIdentity.bootstrapControllers.get(address);
    if (existing && await AgentIdentity.registry.getRecord(existing.did)) {
      return existing;
    }

    const [signer, privateKey] = LocalKeySigner.generate();
    const timestamp = AgentIdentity.nowIsoTimestamp();
    const verificationMethodId = `${DID_WEBVH_PLACEHOLDER}#key-1`;
    const template = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
      id: DID_WEBVH_PLACEHOLDER,
      controller: DID_WEBVH_PLACEHOLDER,
      created: timestamp,
      updated: timestamp,
      agentMetadata: {
        name: `controller-${AgentIdentity.normalizeDidPathSegment(address)}`,
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
      domain: AgentIdentity.defaultWebvhDomain,
      pathSegments: ['controllers', AgentIdentity.normalizeDidPathSegment(address)],
      document: template,
      signer
    });
    const document = AgentIdentity.cloneDocument(created.state as unknown as AgentDIDDocument);
    AgentIdentity.didWebvhLogStore.set(document.id, created.log);
    AgentIdentity.didWebvhSignerStore.set(document.id, signer);
    AgentIdentity.bootstrapControllers.set(address, { did: document.id, signer });

    AgentIdentity.resolver.registerDocument(document);
    await AgentIdentity.registry.register(document.id, document.controller, AgentIdentity.computeDocumentReference(document));
    AgentIdentity.appendHistory(document, 'created');
    return { did: document.id, signer, privateKey };
  }

  /**
   * Appends a controller-signed entry with `document` to the DID's did:webvh log and
   * returns the state as signed. The signer is `controllerSigner` when given, otherwise
   * the controller signer retained when the DID was created in this process.
   */
  private static async appendDidWebvhEntry(
    did: string,
    document: AgentDIDDocument,
    controllerSigner?: AgentSigner
  ): Promise<AgentDIDDocument> {
    const { log, signer } = AgentIdentity.requireDidWebvhLifecycle(did, controllerSigner);
    const updated = await updateDidWebvhLog({ log, signer, document: document as unknown as Record<string, unknown> });
    AgentIdentity.didWebvhLogStore.set(did, updated.log);
    return AgentIdentity.cloneDocument(updated.state as unknown as AgentDIDDocument);
  }

  private static requireDidWebvhLifecycle(did: string, controllerSigner?: AgentSigner): { log: string; signer: AgentSigner } {
    const log = AgentIdentity.didWebvhLogStore.get(did);
    if (!log) {
      throw new Error(`No did:webvh log for ${did} in this process; import it with importDidWebvhHistory first`);
    }
    const signer = controllerSigner ?? AgentIdentity.didWebvhSignerStore.get(did);
    if (!signer) {
      throw new Error(`A controller signer is required to change ${did}: pass options.controllerSigner`);
    }
    return { log, signer };
  }

  private static async resolveActiveVerificationChain(did: string): Promise<AgentDIDDocument[]> {
    const chain = did.startsWith('did:webvh:')
      ? await AgentIdentity.resolveControllerChain(did)
      : [await AgentIdentity.resolve(did)];

    if (chain.some((document) => !AgentIdentity.hasActiveVerificationMethod(document))) {
      throw new Error(`DID is not active: ${did}`);
    }

    return chain;
  }

  private static hasActiveVerificationMethod(document: AgentDIDDocument): boolean {
    return document.verificationMethod.some((method) => Boolean(method.publicKeyMultibase) && !method.deactivated);
  }

  /**
   * Signs a payload using an Ed25519 private key or an AgentSigner.
   */
  public async signMessage(payload: string, keyOrSigner: string | AgentSigner): Promise<string> {
    const messageBytes = new TextEncoder().encode(payload);
    if (typeof keyOrSigner === 'string') {
      const privateKeyBytes = hexToBytes(keyOrSigner);
      const signatureBytes = ed25519.sign(messageBytes, privateKeyBytes);
      return bytesToHex(signatureBytes);
    }
    return keyOrSigner.sign(messageBytes);
  }

  /**
   * Signs an HTTP request (Web Bot Auth) for secure API consumption.
   * Implements a simplified version of IETF HTTP Message Signatures.
   */
  /**
   * Signs an HTTP request with an RFC 9421 HTTP Message Signature (Agent-DID profile).
   *
   * Covered components: `"@method" "@authority" "@path" "@query" "content-digest" "date"
   * "signature-agent"`; parameters: `created`, `expires`, `nonce`, `keyid`, `alg="ed25519"`
   * and `tag="agent-did"`. Returns the header fields to add to the request.
   */
  public async signHttpRequest(params: SignHttpRequestParams): Promise<Record<string, string>> {
    if (!params.method?.trim()) {
      throw new Error("HTTP method is required");
    }

    if (!params.url?.trim()) {
      throw new Error("HTTP URL is required");
    }

    validateHttpTarget(params.url, params.httpSecurity);

    if (!params.agentDid?.trim()) {
      throw new Error("Agent DID is required");
    }

    const keyOrSigner = params.signer || params.agentPrivateKey;
    if (!keyOrSigner) {
      throw new Error("Either agentPrivateKey or signer must be provided");
    }

    const created = Math.floor(Date.now() / 1000);
    const headers: Record<string, string> = {
      'Signature-Agent': params.agentDid,
      'Date': new Date(created * 1000).toUTCString(),
      'Content-Digest': AgentIdentity.computeContentDigest(params.body)
    };
    const input: SignatureInput = {
      components: [...AGENT_DID_HTTP_SIGNATURE_COMPONENTS],
      params: [
        ['created', created],
        ['expires', created + (params.expiresInSeconds ?? 30)],
        ['nonce', AgentIdentity.generateNonce()],
        ['keyid', params.verificationMethodId || `${params.agentDid}#key-1`],
        ['alg', 'ed25519'],
        ['tag', AGENT_DID_HTTP_SIGNATURE_TAG]
      ]
    };
    const signatureBase = buildSignatureBase(
      { method: params.method.toUpperCase(), url: params.url, headers },
      input
    );

    const signatureHex = await this.signMessage(signatureBase, keyOrSigner);
    return {
      ...headers,
      'Signature-Input': `sig1=${serializeSignatureInput(input)}`,
      'Signature': serializeSignature('sig1', hexToBytes(signatureHex))
    };
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
  public static async verifyHttpRequestSignature(params: VerifyHttpRequestSignatureParams): Promise<boolean> {
    const headers = Object.fromEntries(
      Object.entries(params.headers).map(([key, value]) => [key.toLowerCase(), value])
    );
    const signatureAgent = headers['signature-agent'];
    if (!headers['signature'] || !headers['signature-input'] || !signatureAgent) {
      return false;
    }
    if (headers['content-digest'] !== AgentIdentity.computeContentDigest(params.body)) {
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

    const now = Math.floor(Date.now() / 1000);
    const maxSkew = params.maxCreatedSkewSeconds ?? 300;
    const nonceStore = params.nonceStore ?? AgentIdentity.defaultNonceStore;
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

      const isValid = await AgentIdentity.verifySignature(
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
  public static async verifySignature(
    did: string,
    payload: string,
    signature: string,
    keyId?: string,
    requiredPurpose: VerificationRelationship = 'assertionMethod'
  ): Promise<boolean> {
    let verificationChain: AgentDIDDocument[];
    try {
      verificationChain = await AgentIdentity.resolveActiveVerificationChain(did);
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
  public static async verifyHistoricalSignature(
    did: string,
    payload: string,
    signature: string,
    keyId: string,
    requiredPurpose: VerificationRelationship = 'assertionMethod'
  ): Promise<boolean> {
    let verificationChain: AgentDIDDocument[];
    try {
      verificationChain = await AgentIdentity.resolveActiveVerificationChain(did);
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
  public static async resolve(did: string): Promise<AgentDIDDocument> {
    const isRevoked = await AgentIdentity.registry.isRevoked(did);

    if (isRevoked) {
      throw new Error(`DID is revoked: ${did}`);
    }

    return AgentIdentity.resolver.resolve(did);
  }

  public static async resolveControllerChain(did: string, maxDepth = 8): Promise<AgentDIDDocument[]> {
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
      const current = await AgentIdentity.resolve(currentDid);
      chain.push(current);

      const controllerDid = current.controller?.trim();
      if (!controllerDid || controllerDid === currentDid || !controllerDid.startsWith('did:')) {
        return chain;
      }

      currentDid = controllerDid;
    }
  }

  /**
   * Revokes a DID in the registry. For did:webvh DIDs it first appends a controller-signed
   * deactivation entry (`deactivated: true`) to the DID's log.
   */
  public static async revokeDid(did: string, options: DidWebvhLifecycleOptions = {}): Promise<void> {
    const existing = await AgentIdentity.resolve(did);
    if (did.startsWith('did:webvh:')) {
      const { log, signer } = AgentIdentity.requireDidWebvhLifecycle(did, options.controllerSigner);
      const deactivated = await deactivateDidWebvhLog({ log, signer });
      AgentIdentity.didWebvhLogStore.set(did, deactivated.log);
    }
    await AgentIdentity.registry.revoke(did);
    AgentIdentity.appendHistory(existing, 'revoked');
  }

  public static async updateDidDocument(
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

    const existing = await AgentIdentity.resolve(did);
    const now = AgentIdentity.nextDocumentTimestamp(existing.updated);

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
      updatedDocument = await AgentIdentity.appendDidWebvhEntry(did, updatedDocument, options.controllerSigner);
    }

    AgentIdentity.resolver.registerDocument(updatedDocument);
    await AgentIdentity.registry.setDocumentReference(did, AgentIdentity.computeDocumentReference(updatedDocument));
    AgentIdentity.appendHistory(updatedDocument, 'updated');
    return updatedDocument;
  }

  public static async rotateVerificationMethod(
    did: string,
    options: DidWebvhLifecycleOptions = {}
  ): Promise<RotateVerificationMethodResult> {
    const existing = await AgentIdentity.resolve(did);
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

    const deactivatedTimestamp = AgentIdentity.nextDocumentTimestamp(existing.updated);
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
      updatedDocument = await AgentIdentity.appendDidWebvhEntry(did, updatedDocument, options.controllerSigner);
    }

    AgentIdentity.resolver.registerDocument(updatedDocument);
    await AgentIdentity.registry.setDocumentReference(did, AgentIdentity.computeDocumentReference(updatedDocument));
    AgentIdentity.appendHistory(updatedDocument, 'rotated-key');

    return {
      document: updatedDocument,
      verificationMethodId,
      agentPrivateKey: privateKeyHex
    };
  }

  public static getDocumentHistory(did: string): AgentDocumentHistoryEntry[] {
    const history = AgentIdentity.documentHistoryStore.get(did) || [];
    return JSON.parse(JSON.stringify(history)) as AgentDocumentHistoryEntry[];
  }

  /** Returns the DID's did:webvh v1.0 log (`did.jsonl`) as created or imported in this process. */
  public static exportDidWebvhHistory(did: string): string {
    if (!did.startsWith('did:webvh:')) {
      throw new Error(`did:webvh DID is required for history export: ${did}`);
    }
    const log = AgentIdentity.didWebvhLogStore.get(did);
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
  public static async importDidWebvhHistory(didLog: string): Promise<AgentDIDDocument> {
    const resolved = await resolveDidWebvhLog(didLog);
    const did = resolved.did;
    const latestDocument = AgentIdentity.cloneDocument(resolved.state as unknown as AgentDIDDocument);
    const documentRef = AgentIdentity.computeDocumentReference(latestDocument);

    AgentIdentity.documentHistoryStore.set(did, AgentIdentity.historyFromDidWebvhLog(resolved.log));
    AgentIdentity.didWebvhLogStore.set(did, resolved.log);
    AgentIdentity.didWebvhSignerStore.delete(did);

    AgentIdentity.resolver.registerDocument(latestDocument);
    await AgentIdentity.registry.register(latestDocument.id, latestDocument.controller, documentRef);
    await AgentIdentity.registry.setDocumentReference(latestDocument.id, documentRef);
    if (resolved.metadata.deactivated) {
      await AgentIdentity.registry.revoke(did);
    }

    return latestDocument;
  }

  public static async saveDidWebvhHistoryToFile(did: string, filePath: string): Promise<void> {
    const fs = await import('node:fs/promises');
    await fs.writeFile(filePath, AgentIdentity.exportDidWebvhHistory(did), 'utf8');
  }

  public static async loadDidWebvhHistoryFromFile(filePath: string): Promise<AgentDIDDocument> {
    const fs = await import('node:fs/promises');
    const didLog = await fs.readFile(filePath, 'utf8');
    return AgentIdentity.importDidWebvhHistory(didLog);
  }

  public static async persistDidWebvhHistoryToSource(
    did: string,
    documentRef: string,
    source: DIDDocumentSource
  ): Promise<void> {
    if (!source.storeDidLogByReference) {
      throw new Error('DIDDocumentSource does not support did:webvh log persistence');
    }

    await source.storeDidLogByReference(documentRef, AgentIdentity.exportDidWebvhHistory(did));
  }

  public static async restoreDidWebvhHistoryFromSource(
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

    return AgentIdentity.importDidWebvhHistory(didLog);
  }

  public static setResolver(resolver: DIDResolver): void {
    AgentIdentity.resolver = resolver;
  }

  public static setRegistry(registry: AgentRegistry): void {
    AgentIdentity.registry = registry;
  }

  public static useProductionResolver(config: ProductionResolverProfileConfig): void {
    AgentIdentity.resolver = new UniversalResolverClient({
      registry: config.registry,
      documentSource: config.documentSource,
      wbaDocumentSource: config.wbaDocumentSource,
      webvhDocumentSource: config.webvhDocumentSource,
      fallbackResolver: AgentIdentity.resolver,
      cacheTtlMs: config.cacheTtlMs,
      onResolutionEvent: config.onResolutionEvent,
      unverifiedDocumentRefSchemes: config.unverifiedDocumentRefSchemes
    });
  }

  public static useProductionResolverFromHttp(config: ProductionHttpResolverProfileConfig): void {
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

    AgentIdentity.useProductionResolver({
      registry: config.registry,
      documentSource: httpSource,
      wbaDocumentSource: httpSource,
      webvhDocumentSource: webvhSource,
      cacheTtlMs: config.cacheTtlMs,
      onResolutionEvent: config.onResolutionEvent,
      unverifiedDocumentRefSchemes: config.unverifiedDocumentRefSchemes
    });
  }

  public static useProductionResolverFromJsonRpc(config: ProductionJsonRpcResolverProfileConfig): void {
    const rpcSource = new JsonRpcDIDDocumentSource({
      endpoint: config.endpoint,
      endpoints: config.endpoints,
      method: config.method,
      buildParams: config.buildParams,
      headers: config.headers,
      transport: config.transport,
      httpSecurity: config.httpSecurity
    });

    AgentIdentity.useProductionResolver({
      registry: config.registry,
      documentSource: rpcSource,
      cacheTtlMs: config.cacheTtlMs,
      onResolutionEvent: config.onResolutionEvent
    });
  }

  private static computeDocumentReference(document: AgentDIDDocument): string {
    return generateCanonicalDocumentHash(document);
  }

  /** RFC 9530 `Content-Digest` with SHA-256. */
  private static computeContentDigest(body?: string): string {
    const digest = sha256(new TextEncoder().encode(body || ''));
    return `sha-256=:${Buffer.from(digest).toString('base64')}:`;
  }

  private static generateNonce(): string {
    return bytesToHex(ethers.randomBytes(16));
  }

  /** History entries for a verified did:webvh log, one per log entry. */
  private static historyFromDidWebvhLog(log: string): AgentDocumentHistoryEntry[] {
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
        const document = AgentIdentity.cloneDocument(entry.state);
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
          documentRef: AgentIdentity.computeDocumentReference(document)
        };
      });
  }

  private static cloneDocument(document: AgentDIDDocument): AgentDIDDocument {
    return JSON.parse(JSON.stringify(document)) as AgentDIDDocument;
  }

  private static nextDocumentTimestamp(previousTimestamp?: string): string {
    const now = Date.now();
    const previous = previousTimestamp ? Date.parse(previousTimestamp) : Number.NaN;

    if (!Number.isNaN(previous) && now <= previous) {
      return normalizeTimestampToIso(new Date(previous + 1).toISOString()) as string;
    }

    return AgentIdentity.nowIsoTimestamp();
  }

  private static appendHistory(document: AgentDIDDocument, action: AgentDocumentHistoryAction): void {
    const did = document.id;
    const currentHistory = AgentIdentity.documentHistoryStore.get(did) || [];
    const nextRevision = currentHistory.length + 1;

    const entry: AgentDocumentHistoryEntry = {
      did,
      revision: nextRevision,
      action,
      timestamp: AgentIdentity.nowIsoTimestamp(),
      version: document.agentMetadata.version,
      documentRef: AgentIdentity.computeDocumentReference(document)
    };

    AgentIdentity.documentHistoryStore.set(did, [...currentHistory, entry]);
  }
}
