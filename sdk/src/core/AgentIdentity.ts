import { ethers } from 'ethers';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import {
  AgentDocumentHistoryAction,
  AgentDocumentHistoryEntry,
  AgentDIDDocument,
  CreateAgentParams,
  CreateAgentResult,
  RotateVerificationMethodResult,
  SignHttpRequestParams,
  UpdateAgentDocumentParams,
  VerifyHttpRequestSignatureParams,
  VerificationRelationship,
  VerificationMethod
} from './types';
import { generateAgentMetadataHash, generateCanonicalDocumentHash } from '../crypto/hash';
import { encodePublicKeyMultibase, decodePublicKeyMultibase } from '../crypto/multibase';
import { AgentSigner, LocalKeySigner } from './signer';
import { validateHttpTarget } from './http-security';
import { DIDDocumentSource, DIDResolver, ResolverResolutionEvent } from '../resolver/types';
import { InMemoryDIDResolver } from '../resolver/InMemoryDIDResolver';
import { UniversalResolverClient } from '../resolver/UniversalResolverClient';
import { HttpDIDDocumentSource } from '../resolver/HttpDIDDocumentSource';
import { JsonRpcDIDDocumentSource } from '../resolver/JsonRpcDIDDocumentSource';
import { WebvhDIDDocumentSource } from '../resolver/WebvhDIDDocumentSource';
import { AgentRegistry } from '../registry/types';
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
}

export interface ProductionHttpResolverProfileConfig {
  registry: AgentRegistry;
  cacheTtlMs?: number;
  referenceToUrl?: (documentRef: string) => string;
  referenceToUrls?: (documentRef: string) => string[];
  fetchFn?: (url: string) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text?: () => Promise<string> }>;
  ipfsGateways?: string[];
  onResolutionEvent?: (event: ResolverResolutionEvent) => void;
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

interface StoredDocumentRevision {
  entry: AgentDocumentHistoryEntry;
  document: AgentDIDDocument;
}

export class AgentIdentity {
  private static readonly defaultWebvhDomain = 'agents.local';
  private static resolver: DIDResolver = new InMemoryDIDResolver();
  private static registry: AgentRegistry = new InMemoryAgentRegistry();
  private static readonly documentHistoryStore: Map<string, AgentDocumentHistoryEntry[]> = new Map();
  private static readonly documentRevisionStore: Map<string, StoredDocumentRevision[]> = new Map();
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
    const webvhOptions = didMethod === 'webvh'
      ? AgentIdentity.resolveWebvhCreateOptions(params, controllerAddress)
      : undefined;

    // 1. Get the Controller's address (The Creator)
    const controllerDid = webvhOptions?.controllerDid || `did:ethr:${controllerAddress}`;
    if (didMethod === 'webvh') {
      await AgentIdentity.ensureBootstrapControllerDocument(controllerDid);
    }

    // 2. Generate a unique Agent ID (Hash of controller + timestamp + random nonce)
    const timestamp = AgentIdentity.nowIsoTimestamp();
    const nonce = ethers.hexlify(ethers.randomBytes(16));
    const identitySeed = webvhOptions?.controllerDid || controllerAddress;
    const rawAgentId = ethers.keccak256(ethers.toUtf8Bytes(`${identitySeed}-${timestamp}-${nonce}`));
    const agentDid = didMethod === 'webvh'
      ? AgentIdentity.buildDidWebvh(rawAgentId, webvhOptions as NonNullable<CreateAgentParams['webvh']>)
      : `did:agent:${this.network}:${rawAgentId}`;

    // 3. Hash the sensitive Intellectual Property (IP)
    const coreModelHashUri = generateAgentMetadataHash(params.coreModel);
    const systemPromptHashUri = generateAgentMetadataHash(params.systemPrompt);

    // 4. Construct the Verification Method (The Agent's own keypair for signing actions)
    // We use Ed25519 for high-speed, deterministic agent signatures as per RFC-001
    let privateKeyHex = '';
    let publicKeyBytes: Uint8Array;

    if (params.signer) {
      publicKeyBytes = await params.signer.getPublicKey();
    } else {
      const [localSigner, localKeyHex] = LocalKeySigner.generate();
      privateKeyHex = localKeyHex;
      publicKeyBytes = await localSigner.getPublicKey();
    }
    
    const verificationMethodId = `${agentDid}#key-1`;

    const blockchainAccountId = didMethod === 'webvh'
      ? undefined
      : `eip155:1:${ethers.Wallet.createRandom().address}`;

    const verificationMethod: VerificationMethod = {
      id: verificationMethodId,
      type: "Ed25519VerificationKey2020",
      controller: controllerDid,
      publicKeyMultibase: encodePublicKeyMultibase(publicKeyBytes),
      blockchainAccountId
    };

    // 5. Assemble the final JSON-LD Document (RFC-001 Compliant)
    const document: AgentDIDDocument = {
      "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
      id: agentDid,
      controller: controllerDid,
      created: timestamp,
      updated: timestamp,
      agentMetadata: {
        name: params.name,
        description: params.description,
        version: params.version || "1.0.0",
        coreModelHash: coreModelHashUri,
        systemPromptHash: systemPromptHashUri,
        capabilities: params.capabilities || [],
        memberOf: params.memberOf
      },
      verificationMethod: [verificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId]
    };

    AgentIdentity.resolver.registerDocument(document);
    await AgentIdentity.registry.register(document.id, document.controller, AgentIdentity.computeDocumentReference(document));
    AgentIdentity.appendHistory(document, 'created');

    return {
      document,
      agentPrivateKey: privateKeyHex
    };
  }

  private static resolveWebvhCreateOptions(
    params: CreateAgentParams,
    controllerAddress: string
  ): NonNullable<CreateAgentParams['webvh']> {
    if (params.webvh?.domain?.trim()) {
      return AgentIdentity.requireWebvhCreateOptions(params);
    }

    const normalizedControllerAddress = controllerAddress.trim().toLowerCase();
    const controllerScid = ethers.keccak256(
      ethers.toUtf8Bytes(`${normalizedControllerAddress}:controller`)
    ).replace(/^0x/, '');
    const controllerDid = AgentIdentity.composeDidWebvh(
      controllerScid,
      AgentIdentity.defaultWebvhDomain,
      ['controllers', AgentIdentity.normalizeDidPathSegment(normalizedControllerAddress)]
    );

    return {
      domain: AgentIdentity.defaultWebvhDomain,
      controllerDid,
      pathSegments: ['agents', AgentIdentity.normalizeDidPathSegment(params.name)]
    };
  }

  private static requireWebvhCreateOptions(params: CreateAgentParams): NonNullable<CreateAgentParams['webvh']> {
    if (!params.webvh?.domain?.trim()) {
      throw new Error('webvh.domain is required when didMethod is webvh');
    }

    if (!params.webvh.controllerDid?.trim()) {
      throw new Error('webvh.controllerDid is required when didMethod is webvh');
    }

    return params.webvh;
  }

  private static buildDidWebvh(rawAgentId: string, options: NonNullable<CreateAgentParams['webvh']>): string {
    const scid = (options.scid?.trim() || rawAgentId.replace(/^0x/, ''));
    return AgentIdentity.composeDidWebvh(scid, options.domain, options.pathSegments);
  }

  private static composeDidWebvh(scid: string, domain: string, pathSegments?: string[]): string {
    const encodedDomain = encodeURIComponent(domain.trim());
    const encodedPathSegments = (pathSegments || [])
      .map((segment) => segment.trim())
      .filter((segment) => segment.length > 0)
      .map((segment) => encodeURIComponent(segment));

    return ['did:webvh', scid.replace(/^0x/, ''), encodedDomain, ...encodedPathSegments].join(':');
  }

  private static normalizeDidPathSegment(value: string): string {
    const normalized = value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    return normalized || 'agent';
  }

  private static async ensureBootstrapControllerDocument(controllerDid: string): Promise<void> {
    const existing = await AgentIdentity.registry.getRecord(controllerDid);
    if (existing) {
      return;
    }

    const controllerKeySeed = ethers.keccak256(
      ethers.toUtf8Bytes(`${controllerDid}:bootstrap-key`)
    ).replace(/^0x/, '');
    const controllerPublicKey = ed25519.getPublicKey(hexToBytes(controllerKeySeed));
    const controllerVerificationMethodId = `${controllerDid}#key-1`;
    const timestamp = AgentIdentity.nowIsoTimestamp();
    const controllerDocument: AgentDIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
      id: controllerDid,
      controller: controllerDid,
      created: timestamp,
      updated: timestamp,
      agentMetadata: {
        name: `controller-${AgentIdentity.normalizeDidPathSegment(controllerDid.split(':').at(-1) || 'root')}`,
        description: 'Local bootstrap controller root for canonical did:webvh flows.',
        version: '1.0.0',
        coreModelHash: generateAgentMetadataHash(`controller:${controllerDid}`),
        systemPromptHash: generateAgentMetadataHash('controller-bootstrap-root')
      },
      verificationMethod: [{
        id: controllerVerificationMethodId,
        type: 'Ed25519VerificationKey2020',
        controller: controllerDid,
        publicKeyMultibase: encodePublicKeyMultibase(controllerPublicKey)
      }],
      authentication: [controllerVerificationMethodId],
      assertionMethod: [controllerVerificationMethodId]
    };

    AgentIdentity.resolver.registerDocument(controllerDocument);
    await AgentIdentity.registry.register(
      controllerDocument.id,
      controllerDocument.controller,
      AgentIdentity.computeDocumentReference(controllerDocument)
    );
    AgentIdentity.appendHistory(controllerDocument, 'created');
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

    const timestamp = Math.floor(Date.now() / 1000);
    const expiresAt = timestamp + (params.expiresInSeconds ?? 30);
    const nonce = AgentIdentity.generateNonce();
    const dateHeader = new Date().toUTCString();
    const verificationMethodId = params.verificationMethodId || `${params.agentDid}#key-1`;
    const contentDigest = AgentIdentity.computeContentDigest(params.body);
    const stringToSign = AgentIdentity.buildHttpSignatureBase({
      method: params.method,
      url: params.url,
      dateHeader,
      contentDigest,
      nonce
    });

    // 2. Sign the string with Ed25519
    const keyOrSigner = params.signer || params.agentPrivateKey;
    if (!keyOrSigner) {
      throw new Error("Either agentPrivateKey or signer must be provided");
    }
    const signatureHex = await this.signMessage(stringToSign, keyOrSigner);
    const signatureBase64 = Buffer.from(hexToBytes(signatureHex)).toString('base64');

    // 3. Return the headers to be injected into the HTTP request
    return {
      'Signature': `sig1=:${signatureBase64}:`,
      'Signature-Input': `sig1=("@request-target" "host" "date" "content-digest" "x-request-nonce");created=${timestamp};expires=${expiresAt};keyid="${verificationMethodId}";alg="ed25519"`,
      'Signature-Agent': params.agentDid,
      'Date': dateHeader,
      'Content-Digest': contentDigest,
      'X-Request-Nonce': nonce
    };
  }

  public static async verifyHttpRequestSignature(params: VerifyHttpRequestSignatureParams): Promise<boolean> {
    const normalizedHeaders = Object.fromEntries(
      Object.entries(params.headers).map(([key, value]) => [key.toLowerCase(), value])
    );

    const signatureHeader = normalizedHeaders['signature'];
    const signatureInputHeader = normalizedHeaders['signature-input'];
    const signatureAgent = normalizedHeaders['signature-agent'];
    const dateHeader = normalizedHeaders['date'];
    const contentDigestHeader = normalizedHeaders['content-digest'];
    const nonceHeader = normalizedHeaders['x-request-nonce'];

    if (!signatureHeader || !signatureInputHeader || !signatureAgent || !dateHeader || !contentDigestHeader) {
      return false;
    }

    const expectedDigest = AgentIdentity.computeContentDigest(params.body);
    if (expectedDigest !== contentDigestHeader) {
      return false;
    }

    const parsedSignatureInputs = AgentIdentity.parseHttpSignatureInputDictionary(signatureInputHeader);
    const parsedSignatures = AgentIdentity.parseHttpSignatureDictionary(signatureHeader);

    const requiredComponents = new Set(['@request-target', 'host', 'date', 'content-digest', 'x-request-nonce']);
    const now = Math.floor(Date.now() / 1000);
    const maxSkew = params.maxCreatedSkewSeconds ?? 300;

    for (const parsedSignatureInput of parsedSignatureInputs) {
      if (!parsedSignatureInput.params.keyid || !parsedSignatureInput.params.created) {
        continue;
      }

      const signatureBase64 = parsedSignatures.get(parsedSignatureInput.label);
      if (!signatureBase64) {
        continue;
      }

      const coveredComponents = new Set(parsedSignatureInput.components.map((component) => component.toLowerCase()));
      const hasRequiredComponents = Array.from(requiredComponents).every((component) => coveredComponents.has(component));
      if (!hasRequiredComponents) {
        continue;
      }

      // Nonce header must be present when x-request-nonce is a covered component
      if (!nonceHeader) {
        continue;
      }

      const keyId = parsedSignatureInput.params.keyid;
      const createdRaw = parsedSignatureInput.params.created;
      const algorithm = parsedSignatureInput.params.alg;

      if (algorithm && algorithm.toLowerCase() !== 'ed25519') {
        continue;
      }

      const created = Number(createdRaw);
      if (Number.isNaN(created) || Math.abs(now - created) > maxSkew) {
        continue;
      }

      // Check expiration if present
      const expiresRaw = parsedSignatureInput.params.expires;
      if (expiresRaw) {
        const expires = Number(expiresRaw);
        if (Number.isNaN(expires) || now > expires) {
          continue;
        }
      }

      if (!keyId.startsWith(`${signatureAgent}#`)) {
        continue;
      }

      // Rebuild signature base including nonce
      const signatureBase = AgentIdentity.buildHttpSignatureBase({
        method: params.method,
        url: params.url,
        dateHeader,
        contentDigest: contentDigestHeader,
        nonce: nonceHeader
      });

      const signatureHex = Buffer.from(signatureBase64, 'base64').toString('hex');
      const isValid = await AgentIdentity.verifySignature(
        signatureAgent,
        signatureBase,
        signatureHex,
        keyId,
        'assertionMethod'
      );
      if (isValid) {
        return true;
      }
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

  public static async revokeDid(did: string): Promise<void> {
    const existing = await AgentIdentity.resolve(did);
    await AgentIdentity.registry.revoke(did);
    AgentIdentity.appendHistory(existing, 'revoked');
  }

  public static async updateDidDocument(did: string, patch: UpdateAgentDocumentParams): Promise<AgentDIDDocument> {
    if (!did?.trim()) {
      throw new Error('DID is required');
    }

    const existing = await AgentIdentity.resolve(did);
    const now = AgentIdentity.nextDocumentTimestamp(existing.updated);

    const updatedDocument: AgentDIDDocument = {
      ...existing,
      updated: now,
      agentMetadata: {
        ...existing.agentMetadata,
        description: patch.description ?? existing.agentMetadata.description,
        version: patch.version ?? existing.agentMetadata.version,
        coreModelHash: patch.coreModel
          ? generateAgentMetadataHash(patch.coreModel)
          : existing.agentMetadata.coreModelHash,
        systemPromptHash: patch.systemPrompt
          ? generateAgentMetadataHash(patch.systemPrompt)
          : existing.agentMetadata.systemPromptHash,
        capabilities: patch.capabilities ?? existing.agentMetadata.capabilities,
        memberOf: patch.memberOf ?? existing.agentMetadata.memberOf
      },
      complianceCertifications: patch.complianceCertifications ?? existing.complianceCertifications
    };

    AgentIdentity.resolver.registerDocument(updatedDocument);
    await AgentIdentity.registry.setDocumentReference(did, AgentIdentity.computeDocumentReference(updatedDocument));
    AgentIdentity.appendHistory(updatedDocument, 'updated');
    return updatedDocument;
  }

  public static async rotateVerificationMethod(did: string): Promise<RotateVerificationMethodResult> {
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

    const updatedDocument: AgentDIDDocument = {
      ...existing,
      updated: deactivatedTimestamp,
      verificationMethod: [...deactivatedMethods, newVerificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: Array.from(new Set([...(existing.assertionMethod || []), verificationMethodId]))
    };

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

  public static exportDidWebvhHistory(did: string): string {
    const scid = AgentIdentity.extractDidWebvhScid(did);
    const revisions = AgentIdentity.documentRevisionStore.get(did) || [];

    if (revisions.length === 0) {
      throw new Error(`No document history found for DID: ${did}`);
    }

    const stateRevisions = revisions.filter(({ entry }) => entry.action !== 'revoked');

    if (stateRevisions.length === 0) {
      throw new Error(`No did:webvh state revisions available for DID: ${did}`);
    }

    return stateRevisions.map(({ document }, index) => JSON.stringify({
      versionId: `${index + 1}-${scid}`,
      versionTime: document.updated,
      state: AgentIdentity.cloneDocument(document)
    })).join('\n');
  }

  public static async importDidWebvhHistory(didLog: string): Promise<AgentDIDDocument> {
    const revisions = AgentIdentity.parseDidWebvhHistory(didLog);
    const latestRevision = revisions[revisions.length - 1];
    const did = latestRevision.document.id;
    const latestDocument = AgentIdentity.cloneDocument(latestRevision.document);
    const documentRef = AgentIdentity.computeDocumentReference(latestDocument);

    AgentIdentity.documentHistoryStore.set(did, revisions.map(({ entry }) => JSON.parse(JSON.stringify(entry)) as AgentDocumentHistoryEntry));
    AgentIdentity.documentRevisionStore.set(did, revisions.map(({ entry, document }) => ({
      entry: JSON.parse(JSON.stringify(entry)) as AgentDocumentHistoryEntry,
      document: AgentIdentity.cloneDocument(document)
    })));

    AgentIdentity.resolver.registerDocument(latestDocument);
    await AgentIdentity.registry.register(latestDocument.id, latestDocument.controller, documentRef);
    await AgentIdentity.registry.setDocumentReference(latestDocument.id, documentRef);

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
      onResolutionEvent: config.onResolutionEvent
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
      onResolutionEvent: config.onResolutionEvent
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

  private static computeContentDigest(body?: string): string {
    const bodyHashHex = ethers.sha256(ethers.toUtf8Bytes(body || ""));
    const cleanBodyHashHex = bodyHashHex.startsWith('0x') ? bodyHashHex.slice(2) : bodyHashHex;
    const bodyHashBase64 = Buffer.from(hexToBytes(cleanBodyHashHex)).toString('base64');
    return `sha-256=:${bodyHashBase64}:`;
  }

  private static buildHttpSignatureBase(params: {
    method: string;
    url: string;
    dateHeader: string;
    contentDigest: string;
    nonce?: string;
  }): string {
    const urlObj = new URL(params.url);

    const lines = [
      `(request-target): ${params.method.toLowerCase()} ${urlObj.pathname}${urlObj.search}`,
      `host: ${urlObj.host}`,
      `date: ${params.dateHeader}`,
      `content-digest: ${params.contentDigest}`
    ];

    if (params.nonce) {
      lines.push(`x-request-nonce: ${params.nonce}`);
    }

    return lines.join('\n');
  }

  private static generateNonce(): string {
    return bytesToHex(ethers.randomBytes(16));
  }

  private static parseHttpSignatureInputDictionary(value: string): Array<{
    label: string;
    components: string[];
    params: Record<string, string>;
  }> {
    const entries = value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);

    const parsed: Array<{
      label: string;
      components: string[];
      params: Record<string, string>;
    }> = [];

    for (const entry of entries) {
      const match = entry.match(/^([a-zA-Z0-9_-]+)=\(([^)]*)\)(.*)$/);
      if (!match) {
        continue;
      }

      const [, label, componentSection, paramsSection] = match;
      const componentMatches = componentSection.match(/"([^"]+)"/g) || [];
      const components = componentMatches.map((component) => component.slice(1, -1));

      const params: Record<string, string> = {};
      const rawSegments = paramsSection
        .split(';')
        .map((segment) => segment.trim())
        .filter(Boolean);

      for (const segment of rawSegments) {
        const equalsIndex = segment.indexOf('=');
        if (equalsIndex === -1) {
          continue;
        }

        const key = segment.slice(0, equalsIndex).trim().toLowerCase();
        const rawValue = segment.slice(equalsIndex + 1).trim();
        params[key] = rawValue.startsWith('"') && rawValue.endsWith('"')
          ? rawValue.slice(1, -1)
          : rawValue;
      }

      parsed.push({
        label,
        components,
        params
      });
    }

    return parsed;
  }

  private static parseHttpSignatureDictionary(value: string): Map<string, string> {
    const entries = value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);

    const parsed = new Map<string, string>();

    for (const entry of entries) {
      const match = entry.match(/^([a-zA-Z0-9_-]+)=:([A-Za-z0-9+/=]+):$/);
      if (!match) {
        continue;
      }

      const [, label, base64Value] = match;
      parsed.set(label, base64Value);
    }

    return parsed;
  }

  private static extractDidWebvhScid(did: string): string {
    if (!did.startsWith('did:webvh:')) {
      throw new Error(`did:webvh DID is required for history export: ${did}`);
    }

    const suffix = did.slice('did:webvh:'.length);
    const [scid] = suffix.split(':');

    if (!scid) {
      throw new Error(`Invalid did:webvh DID: ${did}`);
    }

    return scid;
  }

  private static parseDidWebvhHistory(didLog: string): StoredDocumentRevision[] {
    const lines = didLog
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    if (lines.length === 0) {
      throw new Error('did:webvh DID log is empty');
    }

    let currentDid: string | undefined;
    let previousDocument: AgentDIDDocument | undefined;

    return lines.map((line, index) => {
      const parsed = JSON.parse(line) as { versionId?: string; versionTime?: string; state?: AgentDIDDocument };
      if (!parsed.state || typeof parsed.state.id !== 'string') {
        throw new Error('did:webvh DID log does not contain a resolvable state entry');
      }

      const document = AgentIdentity.cloneDocument(parsed.state);
      const scid = AgentIdentity.extractDidWebvhScid(document.id);
      if (parsed.versionId && !parsed.versionId.endsWith(`-${scid}`)) {
        throw new Error(`did:webvh DID log versionId does not match DID SCID: ${parsed.versionId}`);
      }

      if (currentDid && document.id !== currentDid) {
        throw new Error(`did:webvh DID log mixes multiple DIDs: ${currentDid} and ${document.id}`);
      }
      currentDid = document.id;

      const action = AgentIdentity.inferImportedHistoryAction(previousDocument, document, index);
      const entry: AgentDocumentHistoryEntry = {
        did: document.id,
        revision: index + 1,
        action,
        timestamp: typeof parsed.versionTime === 'string' && parsed.versionTime.trim().length > 0
          ? parsed.versionTime
          : document.updated,
        version: document.agentMetadata.version,
        documentRef: AgentIdentity.computeDocumentReference(document)
      };

      previousDocument = AgentIdentity.cloneDocument(document);
      return { entry, document };
    });
  }

  private static inferImportedHistoryAction(
    previousDocument: AgentDIDDocument | undefined,
    currentDocument: AgentDIDDocument,
    index: number
  ): AgentDocumentHistoryAction {
    if (index === 0 || !previousDocument) {
      return 'created';
    }

    if (currentDocument.verificationMethod.length !== previousDocument.verificationMethod.length) {
      return 'rotated-key';
    }

    return 'updated';
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
    const currentRevisions = AgentIdentity.documentRevisionStore.get(did) || [];
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
    AgentIdentity.documentRevisionStore.set(did, [...currentRevisions, {
      entry: JSON.parse(JSON.stringify(entry)) as AgentDocumentHistoryEntry,
      document: AgentIdentity.cloneDocument(document)
    }]);
  }
}
