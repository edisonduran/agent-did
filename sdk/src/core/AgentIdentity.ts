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
import { AgentRegistry } from '../registry/types';
import { InMemoryAgentRegistry } from '../registry/InMemoryAgentRegistry';
import { normalizeTimestampToIso } from './time';

export interface AgentIdentityConfig {
  signer: ethers.Signer; // The Creator's Wallet (Controller)
  network?: string; // e.g., 'polygon', 'base', 'ethereum'
}

export interface ProductionResolverProfileConfig {
  registry: AgentRegistry;
  documentSource: DIDDocumentSource;
  wbaDocumentSource?: DIDDocumentSource;
  cacheTtlMs?: number;
  onResolutionEvent?: (event: ResolverResolutionEvent) => void;
}

export interface ProductionHttpResolverProfileConfig {
  registry: AgentRegistry;
  cacheTtlMs?: number;
  referenceToUrl?: (documentRef: string) => string;
  referenceToUrls?: (documentRef: string) => string[];
  fetchFn?: (url: string) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;
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

export class AgentIdentity {
  private static resolver: DIDResolver = new InMemoryDIDResolver();
  private static registry: AgentRegistry = new InMemoryAgentRegistry();
  private static readonly documentHistoryStore: Map<string, AgentDocumentHistoryEntry[]> = new Map();
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
    // 1. Get the Controller's address (The Creator)
    const controllerAddress = await this.signer.getAddress();
    const controllerDid = `did:ethr:${controllerAddress}`;

    // 2. Generate a unique Agent ID (Hash of controller + timestamp + random nonce)
    const timestamp = AgentIdentity.nowIsoTimestamp();
    const nonce = ethers.hexlify(ethers.randomBytes(16));
    const rawAgentId = ethers.keccak256(ethers.toUtf8Bytes(`${controllerAddress}-${timestamp}-${nonce}`));
    const agentDid = `did:agent:${this.network}:${rawAgentId}`;

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
    
    // We also generate an EVM wallet for Account Abstraction (ERC-4337)
    const agentWallet = ethers.Wallet.createRandom();
    const verificationMethodId = `${agentDid}#key-1`;
    
    const verificationMethod: VerificationMethod = {
      id: verificationMethodId,
      type: "Ed25519VerificationKey2020",
      controller: controllerDid,
      publicKeyMultibase: encodePublicKeyMultibase(publicKeyBytes),
      blockchainAccountId: `eip155:1:${agentWallet.address}` // Assuming Ethereum Mainnet format for the account ID
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
      authentication: [verificationMethodId]
    };

    AgentIdentity.resolver.registerDocument(document);
    await AgentIdentity.registry.register(document.id, document.controller, AgentIdentity.computeDocumentReference(document));
    AgentIdentity.appendHistory(document, 'created');

    return {
      document,
      agentPrivateKey: privateKeyHex
    };
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
      const isValid = await AgentIdentity.verifySignature(signatureAgent, signatureBase, signatureHex, keyId);
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
  public static async verifySignature(did: string, payload: string, signature: string, keyId?: string): Promise<boolean> {
    const isRevoked = await AgentIdentity.registry.isRevoked(did);

    if (isRevoked) {
      return false;
    }

    const didDoc = await AgentIdentity.resolve(did);
    const messageBytes = new TextEncoder().encode(payload);
    const signatureBytes = hexToBytes(signature);

    const activeKeyIds = new Set(didDoc.authentication || []);
    const candidateMethods = didDoc.verificationMethod.filter((method) => {
      if (!method.publicKeyMultibase) {
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
    keyId: string
  ): Promise<boolean> {
    const isRevoked = await AgentIdentity.registry.isRevoked(did);
    if (isRevoked) {
      return false;
    }

    const didDoc = await AgentIdentity.resolve(did);
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
    const now = AgentIdentity.nowIsoTimestamp();

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

    const deactivatedTimestamp = AgentIdentity.nowIsoTimestamp();
    const deactivatedMethods = existing.verificationMethod.map((method) => ({
      ...method,
      deactivated: method.deactivated || deactivatedTimestamp
    }));

    const updatedDocument: AgentDIDDocument = {
      ...existing,
      updated: deactivatedTimestamp,
      verificationMethod: [...deactivatedMethods, newVerificationMethod],
      authentication: [verificationMethodId]
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

    AgentIdentity.useProductionResolver({
      registry: config.registry,
      documentSource: httpSource,
      wbaDocumentSource: httpSource,
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
