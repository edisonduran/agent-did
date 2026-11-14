import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import {
  AgentDocumentHistoryEntry,
  AgentDIDDocument,
  CreateAgentParams,
  CreateAgentResult,
  DidWebvhLifecycleOptions,
  RotateVerificationMethodOptions,
  RotateVerificationMethodResult,
  SignHttpRequestParams,
  UpdateAgentDocumentParams,
  VerifyHttpRequestSignatureParams,
  VerificationRelationship
} from './types';
import { AgentSigner } from './signer';
import { REQUIRED_RELATIONSHIP_BY_ARTIFACT } from './identity-composition';
import {
  buildSignatureBase,
  HttpSignatureError,
  requestUrlFormProblem,
  serializeSignature,
  serializeSignatureInput,
  SignatureInput
} from './http-signatures';
import { validateHttpTarget } from './http-security';
import { messageSigningInput } from './message-signing';
import {
  AGENT_DID_HTTP_SIGNATURE_COMPONENTS,
  AGENT_DID_HTTP_SIGNATURE_TAG,
  computeContentDigest,
  generateNonce
} from './http-profile';
import { DIDDocumentSource, DIDResolver } from '../resolver/types';
import { AgentRegistry } from '../registry/types';
import {
  AgentDidClient,
  ProductionHttpResolverProfileConfig,
  ProductionJsonRpcResolverProfileConfig,
  ProductionResolverProfileConfig
} from './AgentDidClient';

export type {
  ProductionHttpResolverProfileConfig,
  ProductionJsonRpcResolverProfileConfig,
  ProductionResolverProfileConfig
} from './AgentDidClient';
export { AGENT_DID_HTTP_SIGNATURE_COMPONENTS, AGENT_DID_HTTP_SIGNATURE_TAG } from './http-profile';

export interface AgentIdentityConfig {
  /**
   * The controller's Ed25519 signer (the creator). Its public key identifies the controller
   * (`did:key`) and, for did:webvh, authorizes the log. Use a KMS/HSM-backed `AgentSigner` in production.
   */
  controllerSigner: AgentSigner;
  /**
   * Client that owns the identity state (resolver, registry, did:webvh logs...) this
   * identity creates documents in. Defaults to the process-wide default client.
   */
  client?: AgentDidClient;
}

export class AgentIdentity {
  private static defaultClient: AgentDidClient = new AgentDidClient();
  private readonly controllerSigner: AgentSigner;
  private readonly explicitClient?: AgentDidClient;

  constructor(config: AgentIdentityConfig) {
    this.controllerSigner = config.controllerSigner;
    this.explicitClient = config.client;
  }

  /** The client this identity creates documents in. */
  public get client(): AgentDidClient {
    return this.explicitClient ?? AgentIdentity.defaultClient;
  }

  /** The client behind the deprecated static API. */
  public static getDefaultClient(): AgentDidClient {
    return AgentIdentity.defaultClient;
  }

  /** Replaces the client behind the deprecated static API (and identities without an explicit client). */
  public static setDefaultClient(client: AgentDidClient): void {
    AgentIdentity.defaultClient = client;
  }

  /**
   * Creates a new Agent-DID Document (Passport) from raw parameters.
   * Automatically hashes sensitive IP (coreModel, systemPrompt) and generates the DID.
   *
   * @param params The raw agent configuration (name, prompt, capabilities, etc.)
   * @returns A fully formed AgentDIDDocument compliant with RFC-001 and the Agent's private key
   */
  public async create(params: CreateAgentParams): Promise<CreateAgentResult> {
    return this.client.createAgent(this.controllerSigner, params);
  }

  /**
   * Signs a payload using an Ed25519 private key or an AgentSigner (hex signature).
   *
   * The signature covers `AGENT_DID_MESSAGE_SIGNING_PREFIX + payload`, so it is a payload signature and cannot
   * be reused as an HTTP request signature or any other signature of the same key. Verify it with
   * `verifySignature` / `verifySignatureAtTime`, which apply the same prefix.
   */
  public async signMessage(payload: string, keyOrSigner: string | AgentSigner): Promise<string> {
    return this.signBytes(messageSigningInput(payload), keyOrSigner);
  }

  /** Signs exactly `messageBytes`, with no domain prefix: for protocols that define their own signature input. */
  private async signBytes(messageBytes: Uint8Array, keyOrSigner: string | AgentSigner): Promise<string> {
    if (typeof keyOrSigner === 'string') {
      const privateKeyBytes = hexToBytes(keyOrSigner);
      const signatureBytes = ed25519.sign(messageBytes, privateKeyBytes);
      return bytesToHex(signatureBytes);
    }
    return keyOrSigner.sign(messageBytes);
  }

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

    // Only a URL in normalized form is signed: a verifier with another URL parser must derive the same components
    const urlProblem = requestUrlFormProblem(params.url);
    if (urlProblem !== undefined) {
      throw new HttpSignatureError(`The request URL is not in normalized form: ${urlProblem}`);
    }

    validateHttpTarget(params.url, params.httpSecurity);

    if (!params.agentDid?.trim()) {
      throw new Error("Agent DID is required");
    }

    if (!params.verificationMethodId?.trim()) {
      throw new Error("verificationMethodId is required: pass the verification method that matches the signing key");
    }

    const keyOrSigner = params.signer || params.agentPrivateKey;
    if (!keyOrSigner) {
      throw new Error("Either agentPrivateKey or signer must be provided");
    }

    const created = Math.floor(Date.now() / 1000);
    const headers: Record<string, string> = {
      'Signature-Agent': params.agentDid,
      'Date': new Date(created * 1000).toUTCString(),
      'Content-Digest': computeContentDigest(params.body)
    };
    const input: SignatureInput = {
      components: [...AGENT_DID_HTTP_SIGNATURE_COMPONENTS],
      params: [
        ['created', created],
        ['expires', created + (params.expiresInSeconds ?? 30)],
        ['nonce', generateNonce()],
        ['keyid', params.verificationMethodId],
        ['alg', 'ed25519'],
        ['tag', AGENT_DID_HTTP_SIGNATURE_TAG]
      ]
    };
    const signatureBase = buildSignatureBase(
      { method: params.method.toUpperCase(), url: params.url, headers },
      input
    );

    // The RFC 9421 signature base is signed as is: the "agent-did/v1/message" prefix of signMessage is not applied
    const signatureHex = await this.signBytes(new TextEncoder().encode(signatureBase), keyOrSigner);
    return {
      ...headers,
      'Signature-Input': `sig1=${serializeSignatureInput(input)}`,
      'Signature': serializeSignature('sig1', hexToBytes(signatureHex))
    };
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async verifyHttpRequestSignature(params: VerifyHttpRequestSignatureParams): Promise<boolean> {
    return AgentIdentity.defaultClient.verifyHttpRequestSignature(params);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async verifySignature(did: string, payload: string, signature: string, keyId?: string, requiredPurpose: VerificationRelationship = REQUIRED_RELATIONSHIP_BY_ARTIFACT.assertion): Promise<boolean> {
    return AgentIdentity.defaultClient.verifySignature(did, payload, signature, keyId, requiredPurpose);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async resolve(did: string): Promise<AgentDIDDocument> {
    return AgentIdentity.defaultClient.resolve(did);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async resolveControllerChain(did: string, maxDepth = 8): Promise<AgentDIDDocument[]> {
    return AgentIdentity.defaultClient.resolveControllerChain(did, maxDepth);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async revokeDid(did: string, options: DidWebvhLifecycleOptions = {}): Promise<void> {
    return AgentIdentity.defaultClient.revokeDid(did, options);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async updateDidDocument(did: string, patch: UpdateAgentDocumentParams, options: DidWebvhLifecycleOptions = {}): Promise<AgentDIDDocument> {
    return AgentIdentity.defaultClient.updateDidDocument(did, patch, options);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async rotateVerificationMethod(did: string, options: RotateVerificationMethodOptions = {}): Promise<RotateVerificationMethodResult> {
    return AgentIdentity.defaultClient.rotateVerificationMethod(did, options);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static getDocumentHistory(did: string): AgentDocumentHistoryEntry[] {
    return AgentIdentity.defaultClient.getDocumentHistory(did);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static exportDidWebvhHistory(did: string): string {
    return AgentIdentity.defaultClient.exportDidWebvhHistory(did);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async importDidWebvhHistory(didLog: string): Promise<AgentDIDDocument> {
    return AgentIdentity.defaultClient.importDidWebvhHistory(didLog);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async saveDidWebvhHistoryToFile(did: string, filePath: string): Promise<void> {
    return AgentIdentity.defaultClient.saveDidWebvhHistoryToFile(did, filePath);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async loadDidWebvhHistoryFromFile(filePath: string): Promise<AgentDIDDocument> {
    return AgentIdentity.defaultClient.loadDidWebvhHistoryFromFile(filePath);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async persistDidWebvhHistoryToSource(did: string, documentRef: string, source: DIDDocumentSource): Promise<void> {
    return AgentIdentity.defaultClient.persistDidWebvhHistoryToSource(did, documentRef, source);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static async restoreDidWebvhHistoryFromSource(documentRef: string, source: DIDDocumentSource): Promise<AgentDIDDocument> {
    return AgentIdentity.defaultClient.restoreDidWebvhHistoryFromSource(documentRef, source);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static setResolver(resolver: DIDResolver): void {
    return AgentIdentity.defaultClient.setResolver(resolver);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static setRegistry(registry: AgentRegistry): void {
    return AgentIdentity.defaultClient.setRegistry(registry);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static useProductionResolver(config: ProductionResolverProfileConfig): void {
    return AgentIdentity.defaultClient.useProductionResolver(config);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static useProductionResolverFromHttp(config: ProductionHttpResolverProfileConfig): void {
    return AgentIdentity.defaultClient.useProductionResolverFromHttp(config);
  }

  /** @deprecated Use the same method on an `AgentDidClient`; removed in 2.0. */
  public static useProductionResolverFromJsonRpc(config: ProductionJsonRpcResolverProfileConfig): void {
    return AgentIdentity.defaultClient.useProductionResolverFromJsonRpc(config);
  }
}
