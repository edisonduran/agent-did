import { sha256 } from '@noble/hashes/sha256';
import { AgentIdentity, AGENT_DID_HTTP_SIGNATURE_COMPONENTS, AGENT_DID_HTTP_SIGNATURE_TAG } from '../src/core/AgentIdentity';
import { buildSignatureBase, parseSignatureInputHeader, serializeSignatureInput } from '../src/core/http-signatures';
import { InMemoryNonceStore } from '../src/core/nonce-store';
import { CreateAgentParams } from '../src/core/types';
import { assertKeyPurpose, assertSigningPurpose, IdentityCompositionError } from '../src/core/identity-composition';
import { LocalKeySigner } from '../src/core/signer';
import { DidWebvhError, didWebvhUpdateKeyFor, resolveDidWebvhLog } from '../src/webvh/adapter';
import { InMemoryAgentRegistry } from '../src/registry/InMemoryAgentRegistry';
import { InMemoryDIDResolver } from '../src/resolver/InMemoryDIDResolver';
import { DIDDocumentSource } from '../src/resolver/types';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { encodePublicKeyMultibase, didKeyFromPublicKey } from '../src/crypto/multibase';
import { generateCommitmentSalt, verifyMetadataCommitment } from '../src/crypto/hash';


/** Simulates a fresh process: drops the in-process did:webvh logs, controller signers and bootstrap controllers. */
function resetDidWebvhState(): void {
  const stores = AgentIdentity.getDefaultClient() as unknown as Record<
    'didWebvhLogStore' | 'didWebvhStateCache' | 'didWebvhSignerStore' | 'bootstrapControllers',
    Map<string, unknown>
  >;
  stores.didWebvhLogStore.clear();
  stores.didWebvhStateCache.clear();
  stores.didWebvhSignerStore.clear();
  stores.bootstrapControllers.clear();
}

describe('AgentIdentity Core Module', () => {
  // Create a random wallet to act as the "Creator" (Controller)
  const [creatorSigner] = LocalKeySigner.generate();
  let agentIdentity: AgentIdentity;

  beforeAll(() => {
    // Initialize the SDK with the creator's wallet
    agentIdentity = new AgentIdentity({
      controllerSigner: creatorSigner,
      network: 'polygon'
    });

  });

  beforeEach(() => {
    AgentIdentity.setResolver(new InMemoryDIDResolver());
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
    (AgentIdentity.getDefaultClient() as unknown as { documentHistoryStore: Map<string, unknown> }).documentHistoryStore.clear();
    resetDidWebvhState();
  });

  it('should successfully create a valid Agent-DID Document (RFC-001 Compliant)', async () => {
    const params: CreateAgentParams = {
      name: "TestBot-Alpha",
      description: "A test agent for unit testing",
      coreModel: "gpt-4o-mini",
      systemPrompt: "You are a helpful test assistant.",
      capabilities: ["read:test", "write:log"],
      memberOf: "did:fleet:test-fleet-1"
    };

    const result = await agentIdentity.create(params);
    const document = result.document;

    // 1. Verify Core DID Structure
    expect(document).toBeDefined();
    expect(document["@context"]).toContain("https://www.w3.org/ns/did/v1");
    expect(document.id.startsWith('did:webvh:')).toBe(true);
    
    // 2. Verify Controller (Creator)
    expect(document.controller.startsWith('did:webvh:')).toBe(true);

    // 3. Verify Metadata & Hashing
    expect(document.agentMetadata.name).toEqual("TestBot-Alpha");
    expect(document.agentMetadata.description).toEqual("A test agent for unit testing");
    expect(document.agentMetadata.version).toEqual("1.0.0"); // Default value
    expect(document.agentMetadata.capabilities).toEqual(["read:test", "write:log"]);
    expect(document.agentMetadata.memberOf).toEqual("did:fleet:test-fleet-1");

    // Ensure sensitive data was hashed into URIs
    expect(document.agentMetadata.coreModelHash.startsWith("hash://hmac-sha256/")).toBe(true);
    expect(document.agentMetadata.systemPromptHash.startsWith("hash://hmac-sha256/")).toBe(true);
    
    // The raw prompt should NOT be in the document
    expect(JSON.stringify(document)).not.toContain("You are a helpful test assistant.");

    // 4. Verify Verification Method (The Agent's Key)
    expect(document.verificationMethod).toBeDefined();
    expect(document.verificationMethod.length).toBe(1);
    
    const vm = document.verificationMethod[0];
    expect(vm.id).toEqual(`${document.id}#key-1`);
    expect(vm.controller).toEqual(document.controller);
    expect(vm.type).toEqual("Ed25519VerificationKey2020");
    expect(vm.blockchainAccountId).toBeUndefined();

    // 5. Verify verification relationship bindings
    expect(document.authentication).toContain(vm.id);
    expect(document.assertionMethod).toContain(vm.id);

    const chain = await AgentIdentity.resolveControllerChain(document.id);
    expect(chain.map((entry) => entry.id)).toEqual([document.id, document.controller]);
    
    // 6. Verify Private Key
    expect(result.agentPrivateKey).toBeDefined();
    expect(typeof result.agentPrivateKey).toBe('string');
  });

  it('should handle minimal parameters correctly', async () => {
    const minimalParams: CreateAgentParams = {
      name: "MinimalBot",
      coreModel: "llama-3",
      systemPrompt: "Minimal prompt"
    };

    const result = await agentIdentity.create(minimalParams);
    const document = result.document;

    expect(document.agentMetadata.name).toEqual("MinimalBot");
    expect(document.agentMetadata.description).toBeUndefined();
    expect(document.agentMetadata.capabilities).toEqual([]); // Should default to empty array
    expect(document.agentMetadata.memberOf).toBeUndefined();
    expect(document.id.startsWith('did:webvh:')).toBe(true);
  });

  it('should preserve the legacy did:agent profile when explicitly requested', async () => {
    const result = await agentIdentity.create({
      name: 'LegacyBot',
      coreModel: 'gpt-4.1-mini',
      systemPrompt: 'You are a legacy compatibility agent.',
      didMethod: 'agent'
    });

    expect(result.document.id).toMatch(/^did:agent:polygon:[0-9a-f]{64}$/);
    expect(result.document.controller).toEqual(didKeyFromPublicKey(await creatorSigner.getPublicKey()));
    expect(result.document.verificationMethod[0].blockchainAccountId).toBeUndefined();
  });

  it('should create a did:webvh document when the web-native profile is requested', async () => {
    const result = await agentIdentity.create({
      name: 'WebvhBot',
      description: 'A web-native agent identity',
      coreModel: 'gpt-4.1-mini',
      systemPrompt: 'You are a web-native agent.',
      didMethod: 'webvh',
      webvh: {
        domain: 'agents.example',
        pathSegments: ['agents', 'webvh-bot'],
        controllerDid: 'did:webvh:QmControllerScid:agents.example:organizations:acme-support',
        controllerSigner: new LocalKeySigner('7c'.repeat(32))
      }
    });

    const document = result.document;
    const expectedDid = document.id;

    // did:webvh v1.0: the SCID is derived from the genesis log entry.
    expect(expectedDid).toMatch(/^did:webvh:Qm[1-9A-HJ-NP-Za-km-z]{44}:agents\.example:agents:webvh-bot$/u);
    expect(document.controller).toEqual('did:webvh:QmControllerScid:agents.example:organizations:acme-support');
    expect(document.verificationMethod[0].id).toEqual(`${expectedDid}#key-1`);
    expect(document.verificationMethod[0].controller).toEqual(document.controller);
    expect(document.verificationMethod[0].blockchainAccountId).toBeUndefined();
    expect(document.authentication).toEqual([`${expectedDid}#key-1`]);
    expect(document.assertionMethod).toEqual([`${expectedDid}#key-1`]);

    await expect(AgentIdentity.resolve(expectedDid)).resolves.toMatchObject({
      id: expectedDid,
      controller: document.controller
    });
  });
  
  it('should sign HTTP requests (Web Bot Auth)', async () => {
    const params: CreateAgentParams = {
      name: "SignerBot",
      coreModel: "test",
      systemPrompt: "test"
    };

    const { document, agentPrivateKey } = await agentIdentity.create(params);
    
    const requestParams = {
      method: 'POST',
      url: 'https://api.example.com/v1/data',
      body: '{"test": true}',
      agentPrivateKey,
      agentDid: document.id
    };
    
    const headers = await agentIdentity.signHttpRequest(requestParams);
    
    expect(headers['Signature']).toBeDefined();
    expect(headers['Signature-Input']).toBeDefined();
    expect(headers['Signature-Agent']).toEqual(document.id);
    expect(headers['Date']).toContain('GMT');
    expect(headers['Content-Digest']).toMatch(/^sha-256=:.+:$/);

    const isHttpValid = await AgentIdentity.verifyHttpRequestSignature({
      method: requestParams.method,
      url: requestParams.url,
      body: requestParams.body,
      headers
    });

    expect(isHttpValid).toBe(true);
  });

  it('should reject tampered HTTP request bodies during signature verification', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'TamperCheckBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const requestParams = {
      method: 'POST',
      url: 'https://api.example.com/v1/transfer',
      body: '{"amount":100}',
      agentPrivateKey,
      agentDid: document.id
    };

    const headers = await agentIdentity.signHttpRequest(requestParams);

    const tamperedValid = await AgentIdentity.verifyHttpRequestSignature({
      method: requestParams.method,
      url: requestParams.url,
      body: '{"amount":999}',
      headers
    });

    expect(tamperedValid).toBe(false);
  });

  it('should reject HTTP signatures missing required signed components', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'MissingComponentBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const requestParams = {
      method: 'POST',
      url: 'https://api.example.com/v1/claims',
      body: '{"claim": true}',
      agentPrivateKey,
      agentDid: document.id
    };

    const headers = await agentIdentity.signHttpRequest(requestParams);
    const signatureInput = headers['Signature-Input'];
    headers['Signature-Input'] = signatureInput.replace('"content-digest"', '');

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: requestParams.method,
      url: requestParams.url,
      body: requestParams.body,
      headers
    });

    expect(valid).toBe(false);
  });

  it('should reject HTTP signatures with unsupported algorithm', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'UnsupportedAlgBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const requestParams = {
      method: 'POST',
      url: 'https://api.example.com/v1/claims',
      body: '{"claim": true}',
      agentPrivateKey,
      agentDid: document.id
    };

    const headers = await agentIdentity.signHttpRequest(requestParams);
    headers['Signature-Input'] = headers['Signature-Input'].replace('alg="ed25519"', 'alg="rsa-pss-sha512"');

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: requestParams.method,
      url: requestParams.url,
      body: requestParams.body,
      headers
    });

    expect(valid).toBe(false);
  });

  it('should verify HTTP signatures with alternate signature labels and additional covered components', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'InteropLabelBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const url = 'https://api.example.com/v1/interop?view=full';
    const body = '{"interop": true}';
    const signed = await agentIdentity.signHttpRequest({ method: 'POST', url, body, agentPrivateKey, agentDid: document.id });
    const created = Math.floor(Date.now() / 1000);
    const headers: Record<string, string> = {
      'Signature-Agent': document.id,
      'Date': signed['Date'],
      'Content-Digest': signed['Content-Digest'],
      'X-Extra': 'covered too'
    };
    // An extra covered component must really be signed: build the base with it.
    const input = {
      components: [...AGENT_DID_HTTP_SIGNATURE_COMPONENTS, 'x-extra'],
      params: [
        ['created', created],
        ['expires', created + 30],
        ['nonce', 'f'.repeat(32)],
        ['keyid', `${document.id}#key-1`],
        ['alg', 'ed25519'],
        ['tag', AGENT_DID_HTTP_SIGNATURE_TAG]
      ] as Array<[string, string | number]>
    };
    const base = buildSignatureBase({ method: 'POST', url, headers }, input);
    const signatureHex = await agentIdentity.signMessage(base, agentPrivateKey);
    headers['Signature-Input'] = `sig-a=${serializeSignatureInput(input)}`;
    headers['Signature'] = `sig-a=:${Buffer.from(hexToBytes(signatureHex)).toString('base64')}:`;

    await expect(AgentIdentity.verifyHttpRequestSignature({ method: 'POST', url, body, headers })).resolves.toBe(true);

    // Changing the extra covered header breaks the signature.
    const tampered: Record<string, string> = { ...headers, 'X-Extra': 'changed' };
    tampered['Signature-Input'] = tampered['Signature-Input'].replace('f'.repeat(32), 'e'.repeat(32));
    await expect(AgentIdentity.verifyHttpRequestSignature({ method: 'POST', url, body, headers: tampered })).resolves.toBe(false);
  });

  it('should verify HTTP signatures when signature dictionaries contain multiple labels', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'InteropMultiSigBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const requestParams = {
      method: 'POST',
      url: 'https://api.example.com/v1/interop',
      body: '{"multi": true}',
      agentPrivateKey,
      agentDid: document.id
    };

    const headers = await agentIdentity.signHttpRequest(requestParams);

    headers['Signature'] = `other=:ZmFrZVNpZw==:, ${headers['Signature']}`;
    headers['Signature-Input'] = `other=("@method");created=1;keyid="${document.id}#key-1";alg="ed25519", ${headers['Signature-Input']}`;

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: requestParams.method,
      url: requestParams.url,
      body: requestParams.body,
      headers
    });

    expect(valid).toBe(true);
  });

  it('should sign the RFC 9421 Agent-DID profile with nonce, expires and tag parameters', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'AntiReplayBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const headers = await agentIdentity.signHttpRequest({
      method: 'post',
      url: 'https://api.example.com/v1/data?x=1',
      body: '{"nonce": true}',
      agentPrivateKey,
      agentDid: document.id,
      expiresInSeconds: 60
    });

    expect(headers['X-Request-Nonce']).toBeUndefined();
    const input = parseSignatureInputHeader(headers['Signature-Input']).get('sig1')!;
    expect(input.components).toEqual([...AGENT_DID_HTTP_SIGNATURE_COMPONENTS]);
    expect(input.params.map(([name]) => name)).toEqual(['created', 'expires', 'nonce', 'keyid', 'alg', 'tag']);
    const params = Object.fromEntries(input.params);
    expect(params.expires).toEqual((params.created as number) + 60);
    expect(params.nonce).toMatch(/^[0-9a-f]{32}$/u);
    expect(params.keyid).toEqual(`${document.id}#key-1`);
    expect(params.alg).toEqual('ed25519');
    expect(params.tag).toEqual('agent-did');

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: 'POST',
      url: 'https://api.example.com/v1/data?x=1',
      body: '{"nonce": true}',
      headers
    });
    expect(valid).toBe(true);
  });

  it('should reject HTTP signatures with expired expires param', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'ExpiredBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const signedAtMs = Date.now() - 120_000;
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(signedAtMs);
    let headers: Record<string, string>;
    try {
      headers = await agentIdentity.signHttpRequest({
        method: 'POST',
        url: 'https://api.example.com/v1/data',
        body: '{"expired": true}',
        agentPrivateKey,
        agentDid: document.id,
        expiresInSeconds: 30
      });
    } finally {
      nowSpy.mockRestore();
    }

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: 'POST',
      url: 'https://api.example.com/v1/data',
      body: '{"expired": true}',
      headers
    });
    expect(valid).toBe(false);
  });

  it('should reject replayed HTTP requests whose created/expires params were rewritten', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'ParamTamperBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const request = { method: 'POST', url: 'https://api.example.com/v1/transfer', body: '{"amount":500}' };
    const headers = await agentIdentity.signHttpRequest({ ...request, agentPrivateKey, agentDid: document.id });
    const now = Math.floor(Date.now() / 1000);

    const rewritten = {
      ...headers,
      'Signature-Input': headers['Signature-Input']
        .replace(/created=\d+/, `created=${now}`)
        .replace(/expires=\d+/, `expires=${now + 86_400}`)
    };
    const withoutExpires = {
      ...headers,
      'Signature-Input': headers['Signature-Input'].replace(/;expires=\d+/, '')
    };

    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers })).resolves.toBe(true);
    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers: rewritten })).resolves.toBe(false);
    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers: withoutExpires })).resolves.toBe(false);
  });

  it('should enforce maxCreatedSkewSeconds within and beyond a 60 second window', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'SkewBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const signAt = async (secondsAgo: number) => {
      const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(Date.now() - secondsAgo * 1000);
      try {
        return await agentIdentity.signHttpRequest({
          method: 'POST',
          url: 'https://api.example.com/v1/data',
          body: '{"skew": true}',
          agentPrivateKey,
          agentDid: document.id,
          expiresInSeconds: 120
        });
      } finally {
        nowSpy.mockRestore();
      }
    };

    const withinSkewHeaders = await signAt(55);
    const outsideSkewHeaders = await signAt(65);

    await expect(AgentIdentity.verifyHttpRequestSignature({
      method: 'POST',
      url: 'https://api.example.com/v1/data',
      body: '{"skew": true}',
      headers: withinSkewHeaders,
      maxCreatedSkewSeconds: 60
    })).resolves.toBe(true);

    await expect(AgentIdentity.verifyHttpRequestSignature({
      method: 'POST',
      url: 'https://api.example.com/v1/data',
      body: '{"skew": true}',
      headers: outsideSkewHeaders,
      maxCreatedSkewSeconds: 60
    })).resolves.toBe(false);
  });

  it('should bound signature lifetime with maxSignatureLifetimeSeconds (default 300)', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'LifetimeBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });
    const sign = (expiresInSeconds: number) => agentIdentity.signHttpRequest({
      method: 'POST',
      url: 'https://api.example.com/v1/data',
      body: '{"lifetime": true}',
      agentPrivateKey,
      agentDid: document.id,
      expiresInSeconds
    });
    const verify = (headers: Record<string, string>, maxSignatureLifetimeSeconds?: number) =>
      AgentIdentity.verifyHttpRequestSignature({
        method: 'POST',
        url: 'https://api.example.com/v1/data',
        body: '{"lifetime": true}',
        headers,
        maxSignatureLifetimeSeconds,
        nonceStore: new InMemoryNonceStore()
      });

    await expect(verify(await sign(300))).resolves.toBe(true);
    await expect(verify(await sign(301))).resolves.toBe(false);
    await expect(verify(await sign(301), 400)).resolves.toBe(true);
    await expect(verify(await sign(61), 60)).resolves.toBe(false);
  });

  it('should reject a replayed request through the built-in nonce store', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'NonceCacheBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });
    const request = { method: 'POST', url: 'https://api.example.com/v1/data', body: '{"nonce-cache": true}' };
    const headers = await agentIdentity.signHttpRequest({ ...request, agentPrivateKey, agentDid: document.id, expiresInSeconds: 120 });

    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers })).resolves.toBe(true);
    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers })).resolves.toBe(false);

    // A caller-supplied store is used instead of the default one.
    const nonceStore = new InMemoryNonceStore();
    const second = await agentIdentity.signHttpRequest({ ...request, agentPrivateKey, agentDid: document.id });
    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers: second, nonceStore })).resolves.toBe(true);
    expect(nonceStore.size).toBe(1);
    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers: second, nonceStore })).resolves.toBe(false);
  });

  it('should not record nonces of requests whose signature is invalid', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'NonceBurnBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });
    const request = { method: 'POST', url: 'https://api.example.com/v1/data', body: '{"amount":1}' };
    const headers = await agentIdentity.signHttpRequest({ ...request, agentPrivateKey, agentDid: document.id });
    const nonceStore = new InMemoryNonceStore();

    await expect(
      AgentIdentity.verifyHttpRequestSignature({ ...request, body: '{"amount":2}', headers, nonceStore })
    ).resolves.toBe(false);
    const forged = { ...headers, 'Signature': `sig1=:${Buffer.alloc(64).toString('base64')}:` };
    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers: forged, nonceStore })).resolves.toBe(false);
    expect(nonceStore.size).toBe(0);
    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers, nonceStore })).resolves.toBe(true);
  });

  it.each([
    ['missing nonce', (input: string) => input.replace(/;nonce="[^"]*"/u, '')],
    ['missing tag', (input: string) => input.replace(';tag="agent-did"', '')],
    ['foreign tag', (input: string) => input.replace('tag="agent-did"', 'tag="web-bot-auth"')],
    ['missing alg', (input: string) => input.replace(';alg="ed25519"', '')],
    ['missing expires', (input: string) => input.replace(/;expires=\d+/u, '')],
    ['dropped signature-agent component', (input: string) => input.replace(' "signature-agent"', '')],
    ['dropped @query component', (input: string) => input.replace(' "@query"', '')],
    ['malformed dictionary', (input: string) => input.replace('sig1=(', 'sig1=[')]
  ])('should reject Agent-DID signatures with %s', async (_label, mutate) => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'ProfileBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });
    const request = { method: 'POST', url: 'https://api.example.com/v1/data', body: '{"profile": true}' };
    const headers = await agentIdentity.signHttpRequest({ ...request, agentPrivateKey, agentDid: document.id });
    headers['Signature-Input'] = mutate(headers['Signature-Input']);

    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers })).resolves.toBe(false);
  });

  it.each([
    ['method', { method: 'PUT' }],
    ['host', { url: 'https://evil.example.com/v1/data?x=1' }],
    ['path', { url: 'https://api.example.com/v1/admin?x=1' }],
    ['query', { url: 'https://api.example.com/v1/data?x=2' }]
  ])('should reject a request whose %s differs from the signed one', async (_label, change) => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'BindingBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });
    const request = { method: 'POST', url: 'https://api.example.com/v1/data?x=1', body: '{}' };
    const headers = await agentIdentity.signHttpRequest({ ...request, agentPrivateKey, agentDid: document.id });

    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, ...change, headers })).resolves.toBe(false);
  });

  it('should reject a Signature-Agent swapped to another DID', async () => {
    const victim = await agentIdentity.create({ name: 'VictimBot', coreModel: 'test', systemPrompt: 'test' });
    const attacker = await agentIdentity.create({ name: 'AttackerBot', coreModel: 'test', systemPrompt: 'test' });
    const request = { method: 'POST', url: 'https://api.example.com/v1/data', body: '{}' };
    const headers = await agentIdentity.signHttpRequest({
      ...request,
      agentPrivateKey: attacker.agentPrivateKey,
      agentDid: attacker.document.id
    });

    const swapped = { ...headers, 'Signature-Agent': victim.document.id };
    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers: swapped })).resolves.toBe(false);
  });

  it('should resolve a created DID document', async () => {
    const { document } = await agentIdentity.create({
      name: 'ResolverBot',
      coreModel: 'test-model',
      systemPrompt: 'test-prompt'
    });

    const resolved = await AgentIdentity.resolve(document.id);

    expect(resolved.id).toEqual(document.id);
    expect(resolved.controller).toEqual(document.controller);
  });

  it('should resolve a did:webvh controller chain for the canonical web-native profile', async () => {
    const rootSigner = new LocalKeySigner('3d'.repeat(32));
    const { document: controllerDocument } = await agentIdentity.create({
      name: 'ControllerRoot',
      coreModel: 'controller-model',
      systemPrompt: 'You are the controller root.',
      didMethod: 'webvh',
      webvh: {
        domain: 'agents.example',
        pathSegments: ['organizations', 'acme-support'],
        // `{DID}` is replaced with the generated DID: a self-controlled root.
        controllerDid: '{DID}',
        controllerSigner: rootSigner
      }
    });
    const { document: agentDocument } = await agentIdentity.create({
      name: 'SupportBot',
      coreModel: 'agent-model',
      systemPrompt: 'You are a support agent.',
      didMethod: 'webvh',
      webvh: {
        domain: 'agents.example',
        pathSegments: ['agents', 'supportbot-x'],
        controllerDid: controllerDocument.id,
        controllerSigner: rootSigner
      }
    });

    const chain = await AgentIdentity.resolveControllerChain(agentDocument.id);

    expect(controllerDocument.controller).toEqual(controllerDocument.id);
    expect(chain.map((doc) => doc.id)).toEqual([agentDocument.id, controllerDocument.id]);
  });

  it('should reject controller chain cycles', async () => {
    const makeChainDocument = (did: string, controller: string) => ({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
      id: did,
      controller,
      created: '2026-05-06T00:00:00.000Z',
      updated: '2026-05-06T00:00:00.000Z',
      agentMetadata: {
        name: 'CycleBot',
        version: '1.0.0',
        coreModelHash: 'hash://sha256/cycle-model',
        systemPromptHash: 'hash://sha256/cycle-prompt'
      },
      verificationMethod: [{
        id: `${did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller,
        publicKeyMultibase: 'z6MkjTsREfRXe13mbS7GZQ9DKcrTuexb5YYdpbSFkwtWdRva'
      }],
      authentication: [`${did}#key-1`],
      assertionMethod: [`${did}#key-1`]
    });

    const cycleADid = 'did:webvh:QmCycleA:agents.example:agents:cycle-a';
    const cycleBDid = 'did:webvh:QmCycleB:agents.example:agents:cycle-b';
    const resolver = new InMemoryDIDResolver();
    resolver.registerDocument(makeChainDocument(cycleADid, cycleBDid));
    resolver.registerDocument(makeChainDocument(cycleBDid, cycleADid));
    AgentIdentity.setResolver(resolver);
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());

    await expect(AgentIdentity.resolveControllerChain(cycleADid)).rejects.toThrow(
      `Controller chain cycle detected at DID: ${cycleADid}`
    );
  });

  it('should verify a valid signature and reject a tampered payload', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'VerifierBot',
      coreModel: 'test-model',
      systemPrompt: 'test-prompt'
    });

    const payload = 'approve:invoice:123';
    const signature = await agentIdentity.signMessage(payload, agentPrivateKey);

    const isValid = await AgentIdentity.verifySignature(document.id, payload, signature);
    const isTamperedValid = await AgentIdentity.verifySignature(document.id, `${payload}-tampered`, signature);

    expect(isValid).toBe(true);
    expect(isTamperedValid).toBe(false);
  });

  it('should reject verification when the canonical controller chain is no longer active', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'ChainVerifierBot',
      coreModel: 'test-model',
      systemPrompt: 'test-prompt'
    });

    const payload = 'approve:controller-chain:1';
    const signature = await agentIdentity.signMessage(payload, agentPrivateKey);
    const chain = await AgentIdentity.resolveControllerChain(document.id);

    await AgentIdentity.revokeDid(chain[1].id);

    await expect(AgentIdentity.verifySignature(document.id, payload, signature)).resolves.toBe(false);
  });

  it('should expose structured key purpose errors for direct helper calls', async () => {
    const { document } = await agentIdentity.create({
      name: 'PurposeHelperBot',
      coreModel: 'test-model',
      systemPrompt: 'test-prompt'
    });

    const keyId = document.verificationMethod[0].id;
    const misboundDocument = {
      ...document,
      authentication: [],
      assertionMethod: [],
      keyAgreement: [keyId]
    };

    expect(() => assertKeyPurpose(keyId, misboundDocument, 'assertionMethod')).toThrow(IdentityCompositionError);

    try {
      assertKeyPurpose(keyId, misboundDocument, 'assertionMethod');
      throw new Error('assertKeyPurpose should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(IdentityCompositionError);
      expect(error).toMatchObject({
        reason: 'key_purpose_violation',
        keyId,
        requiredPurpose: 'assertionMethod',
        foundIn: ['keyAgreement']
      });
    }
  });

  it('should reject signatures from keys outside the required assertionMethod purpose', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'PurposeVerifierBot',
      coreModel: 'test-model',
      systemPrompt: 'test-prompt'
    });

    const keyId = document.verificationMethod[0].id;
    const payload = 'approve:purpose:1';
    const signature = await agentIdentity.signMessage(payload, agentPrivateKey);
    const misboundDocument = {
      ...document,
      authentication: [],
      assertionMethod: [],
      keyAgreement: [keyId]
    };
    const controllerChain = await AgentIdentity.resolveControllerChain(document.id);

    const resolver = new InMemoryDIDResolver();
    resolver.registerDocument(misboundDocument);
    resolver.registerDocument(controllerChain[1]);
    AgentIdentity.setResolver(resolver);
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());

    await expect(
      AgentIdentity.verifySignature(document.id, payload, signature, keyId)
    ).rejects.toMatchObject({
      reason: 'key_purpose_violation',
      keyId,
      requiredPurpose: 'assertionMethod',
      foundIn: ['keyAgreement']
    });
  });

  it('should reject keyAgreement as a signing verification purpose', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'KeyAgreementBot',
      coreModel: 'test-model',
      systemPrompt: 'test-prompt'
    });

    const keyId = document.verificationMethod[0].id;
    const payload = 'approve:key-agreement:1';
    const signature = await agentIdentity.signMessage(payload, agentPrivateKey);

    await expect(
      AgentIdentity.verifySignature(document.id, payload, signature, keyId, 'keyAgreement')
    ).rejects.toMatchObject({
      reason: 'key_purpose_violation',
      requiredPurpose: 'keyAgreement'
    });
  });

  it('should reject unknown verification methods with key_purpose_violation', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'UnknownPurposeBot',
      coreModel: 'test-model',
      systemPrompt: 'test-prompt'
    });

    const payload = 'approve:unknown-key:1';
    const signature = await agentIdentity.signMessage(payload, agentPrivateKey);
    const unknownKeyId = `${document.id}#key-999`;

    await expect(
      AgentIdentity.verifySignature(document.id, payload, signature, unknownKeyId)
    ).rejects.toMatchObject({
      reason: 'key_purpose_violation',
      keyId: unknownKeyId,
      foundIn: []
    });
  });

  it('assertKeyPurpose accepts a key listed under keyAgreement when keyAgreement is the requested relationship', async () => {
    const { document } = await agentIdentity.create({
      name: 'MembershipBot',
      coreModel: 'test-model',
      systemPrompt: 'test-prompt'
    });

    const keyId = document.verificationMethod[0].id;
    const keyAgreementDoc = {
      ...document,
      keyAgreement: [keyId]
    };

    expect(() => assertKeyPurpose(keyId, keyAgreementDoc, 'keyAgreement')).not.toThrow();
    expect(() => assertSigningPurpose('keyAgreement', keyAgreementDoc, keyId)).toThrow(IdentityCompositionError);
  });

  it('should throw when resolving an unknown DID', async () => {
    await expect(AgentIdentity.resolve('did:agent:polygon:0xunknown')).rejects.toThrow('DID not found');
  });

  it('should mark a DID as invalid after revocation', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'RevokedBot',
      coreModel: 'test-model',
      systemPrompt: 'test-prompt'
    });

    const payload = 'approve:payment:789';
    const signature = await agentIdentity.signMessage(payload, agentPrivateKey);

    const isValidBefore = await AgentIdentity.verifySignature(document.id, payload, signature);
    expect(isValidBefore).toBe(true);

    await AgentIdentity.revokeDid(document.id);

    const isValidAfter = await AgentIdentity.verifySignature(document.id, payload, signature);
    expect(isValidAfter).toBe(false);

    await expect(AgentIdentity.resolve(document.id)).rejects.toThrow('DID is revoked');
  });

  it('should evolve an existing DID document while preserving DID', async () => {
    const { document } = await agentIdentity.create({
      name: 'EvolveBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'initial prompt',
      capabilities: ['read:kb']
    });

    const updated = await AgentIdentity.updateDidDocument(document.id, {
      version: '1.1.0',
      description: 'Updated description',
      coreModel: 'gpt-4.1-mini',
      coreModelSalt: generateCommitmentSalt(),
      systemPrompt: 'updated prompt',
      systemPromptSalt: generateCommitmentSalt(),
      capabilities: ['read:kb', 'write:ticket']
    });

    expect(updated.id).toEqual(document.id);
    expect(updated.updated).not.toEqual(document.updated);
    expect(updated.agentMetadata.version).toEqual('1.1.0');
    expect(updated.agentMetadata.description).toEqual('Updated description');
    expect(updated.agentMetadata.capabilities).toEqual(['read:kb', 'write:ticket']);
    expect(updated.agentMetadata.coreModelHash).not.toEqual(document.agentMetadata.coreModelHash);
    expect(updated.agentMetadata.systemPromptHash).not.toEqual(document.agentMetadata.systemPromptHash);

    const registry = new InMemoryAgentRegistry();
    AgentIdentity.setRegistry(registry);

    const created = await agentIdentity.create({
      name: 'RefBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'initial prompt'
    });

    const recordBefore = await registry.getRecord(created.document.id);
    expect(recordBefore?.documentRef).toBeDefined();

    await AgentIdentity.updateDidDocument(created.document.id, {
      systemPrompt: 'new prompt for ref change',
      systemPromptSalt: generateCommitmentSalt()
    });

    const recordAfter = await registry.getRecord(created.document.id);
    expect(recordAfter?.documentRef).toBeDefined();
    expect(recordAfter?.documentRef).not.toEqual(recordBefore?.documentRef);
  });

  it('should throw when updating with an empty DID', async () => {
    await expect(AgentIdentity.updateDidDocument('', { version: '2.0.0' })).rejects.toThrow('DID is required');
  });

  it('should rotate verification method and invalidate old key for active auth', async () => {
    const { document, agentPrivateKey: oldPrivateKey } = await agentIdentity.create({
      name: 'RotationBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'rotation test prompt'
    });

    const payload = 'approve:rotation:1';
    const oldSignature = await agentIdentity.signMessage(payload, oldPrivateKey);

    const validBeforeRotation = await AgentIdentity.verifySignature(document.id, payload, oldSignature);
    expect(validBeforeRotation).toBe(true);

    const rotation = await AgentIdentity.rotateVerificationMethod(document.id);
    const newSignature = await agentIdentity.signMessage(payload, rotation.agentPrivateKey);

    const oldValidAfterRotation = await AgentIdentity.verifySignature(document.id, payload, oldSignature);
    const newValidAfterRotation = await AgentIdentity.verifySignature(
      document.id,
      payload,
      newSignature,
      rotation.verificationMethodId
    );

    expect(oldValidAfterRotation).toBe(false);
    expect(newValidAfterRotation).toBe(true);
    expect(rotation.document.authentication).toEqual([rotation.verificationMethodId]);
    expect(rotation.document.assertionMethod).toEqual([
      `${document.id}#key-1`,
      rotation.verificationMethodId
    ]);
  });

  it('should mark old keys as deactivated after rotation', async () => {
    const { document } = await agentIdentity.create({
      name: 'DeactivationBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const rotation = await AgentIdentity.rotateVerificationMethod(document.id);
    const oldKey = rotation.document.verificationMethod.find(
      m => m.id === `${document.id}#key-1`
    );

    expect(oldKey).toBeDefined();
    if (!oldKey?.deactivated) {
      throw new Error('expected the prior key to be marked as deactivated');
    }
    expect(new Date(oldKey.deactivated).toISOString()).toEqual(oldKey.deactivated);

    const newKey = rotation.document.verificationMethod.find(
      m => m.id === rotation.verificationMethodId
    );
    expect(newKey).toBeDefined();
    expect(newKey?.deactivated).toBeUndefined();
  });

  const versionTimes = (did: string): string[] =>
    AgentIdentity.exportDidWebvhHistory(did)
      .split('\n')
      .filter((line) => line.trim())
      .map((line) => (JSON.parse(line) as { versionTime: string }).versionTime);

  it('treats a rotated-out key as indeterminate at a stated time before the rotation', async () => {
    const { document, agentPrivateKey: oldPrivateKey } = await agentIdentity.create({
      name: 'HistoryBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const payload = 'approve:historical:1';
    const oldKeyId = `${document.id}#key-1`;
    const oldSignature = await agentIdentity.signMessage(payload, oldPrivateKey);

    await AgentIdentity.rotateVerificationMethod(document.id);
    const [createdAt, rotatedAt] = versionTimes(document.id);

    // The old key is no longer active.
    expect(await AgentIdentity.verifySignature(document.id, payload, oldSignature, oldKeyId)).toBe(false);

    // The stated time is the signer's claim, so a key retired after it is not accepted on that claim alone.
    const client = AgentIdentity.getDefaultClient();
    const atCreation = await client.verifySignatureAtTime(document.id, payload, oldSignature, oldKeyId, { statedTime: createdAt });
    expect(atCreation.status).toBe('indeterminate');
    expect(atCreation.key).toMatchObject({ status: 'indeterminate', reason: 'key_retired_after_stated_time' });

    // Trusted evidence that the signature existed before the rotation entry makes it valid.
    const withEvidence = await client.verifySignatureAtTime(document.id, payload, oldSignature, oldKeyId, {
      statedTime: createdAt,
      trustedTimeNotAfter: createdAt
    });
    expect(withEvidence.status).toBe('valid');

    // At or after the rotation the old key is no longer authorized.
    const afterRotation = await client.verifySignatureAtTime(document.id, payload, oldSignature, oldKeyId, { statedTime: rotatedAt });
    expect(afterRotation).toMatchObject({ status: 'invalid', reason: 'key_not_authorized' });
  });

  it('checks the oldest key after three did:webvh rotation cycles', async () => {
    const { document, agentPrivateKey: oldestPrivateKey } = await agentIdentity.create({
      name: 'ThreeCycleBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });
    const payload = 'approve:historical:three-cycle';
    const oldestKeyId = `${document.id}#key-1`;
    const oldestSignature = await agentIdentity.signMessage(payload, oldestPrivateKey);

    expect(document.id.startsWith('did:webvh:')).toBe(true);

    await AgentIdentity.rotateVerificationMethod(document.id);
    await AgentIdentity.rotateVerificationMethod(document.id);
    const thirdRotation = await AgentIdentity.rotateVerificationMethod(document.id);

    expect(thirdRotation.verificationMethodId).toEqual(`${document.id}#key-4`);
    expect(thirdRotation.document.authentication).toEqual([`${document.id}#key-4`]);
    expect(thirdRotation.document.verificationMethod).toHaveLength(4);

    const [createdAt] = versionTimes(document.id);
    const client = AgentIdentity.getDefaultClient();
    expect(await AgentIdentity.verifySignature(document.id, payload, oldestSignature, oldestKeyId)).toBe(false);
    const atCreation = await client.verifySignatureAtTime(document.id, payload, oldestSignature, oldestKeyId, {
      statedTime: createdAt,
      trustedTimeNotAfter: createdAt
    });
    expect(atCreation.status).toBe('valid');
  });

  it('rejects a key check at a stated time with an unknown key id', async () => {
    const { document } = await agentIdentity.create({
      name: 'UnknownKeyBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });
    const [createdAt] = versionTimes(document.id);

    const result = await AgentIdentity.getDefaultClient().verifySignatureAtTime(
      document.id, 'test-payload', '00'.repeat(64), `${document.id}#key-999`, { statedTime: createdAt }
    );
    expect(result).toMatchObject({ status: 'invalid', reason: 'key_not_authorized' });
    expect(result.key).toMatchObject({ status: 'not_authorized', reason: 'key_not_found' });
  });

  it('should keep auditable history for create, update, rotate, revoke lifecycle', async () => {
    const { document } = await agentIdentity.create({
      name: 'AuditBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'audit trail baseline prompt'
    });

    await AgentIdentity.updateDidDocument(document.id, {
      version: '1.0.1',
      systemPrompt: 'audit trail updated prompt',
      systemPromptSalt: generateCommitmentSalt()
    });

    await AgentIdentity.rotateVerificationMethod(document.id);
    await AgentIdentity.revokeDid(document.id);

    const history = AgentIdentity.getDocumentHistory(document.id);

    expect(history.length).toBeGreaterThanOrEqual(4);
    expect(history[0].action).toEqual('created');
    expect(history[1].action).toEqual('updated');
    expect(history[2].action).toEqual('rotated-key');
    expect(history[3].action).toEqual('revoked');

    for (let index = 0; index < history.length; index += 1) {
      expect(history[index].revision).toEqual(index + 1);
      expect(history[index].documentRef).toBeDefined();
      expect(history[index].timestamp.endsWith('Z')).toBe(true);
    }
  });

  it('should export canonical did:webvh history as did.jsonl state revisions', async () => {
    const { document } = await agentIdentity.create({
      name: 'HistoryExportBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'export lifecycle prompt'
    });

    await AgentIdentity.updateDidDocument(document.id, {
      version: '1.0.1',
      systemPrompt: 'export lifecycle prompt v2',
      systemPromptSalt: generateCommitmentSalt()
    });

    await AgentIdentity.rotateVerificationMethod(document.id);
    await AgentIdentity.revokeDid(document.id);

    const exported = AgentIdentity.exportDidWebvhHistory(document.id);
    const lines = exported
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line) as {
        versionId: string;
        versionTime: string;
        parameters: { method?: string; updateKeys?: string[]; deactivated?: boolean };
        state: typeof document;
        proof: Array<{ cryptosuite: string }>;
      });

    // create, update, rotate-key, revoke (deactivation): one controller-signed entry each
    expect(lines).toHaveLength(4);
    expect(lines.map((line) => line.versionId.split('-')[0])).toEqual(['1', '2', '3', '4']);
    lines.forEach((line) => expect(line.proof[0].cryptosuite).toEqual('eddsa-jcs-2022'));
    expect(lines[0].parameters.method).toEqual('did:webvh:1.0');
    expect(lines[0].state.id).toEqual(document.id);
    expect(lines[1].state.agentMetadata.version).toEqual('1.0.1');
    expect(lines[2].state.authentication).toEqual([`${document.id}#key-2`]);
    expect(lines[2].state.verificationMethod.some((method) => method.id === `${document.id}#key-2`)).toBe(true);
    expect(lines[3].parameters.deactivated).toBe(true);

    const verified = await resolveDidWebvhLog(exported, { did: document.id });
    expect(verified.metadata.deactivated).toBe(true);
  });

  it('should restore did:webvh runtime state from an exported did.jsonl history', async () => {
    const { document } = await agentIdentity.create({
      name: 'HistoryImportBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'import lifecycle prompt'
    });

    await AgentIdentity.updateDidDocument(document.id, {
      version: '1.0.1',
      description: 'restored from did log'
    });
    await AgentIdentity.rotateVerificationMethod(document.id);

    const didLog = AgentIdentity.exportDidWebvhHistory(document.id);

    AgentIdentity.setResolver(new InMemoryDIDResolver());
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
    (AgentIdentity.getDefaultClient() as unknown as { documentHistoryStore: Map<string, unknown> }).documentHistoryStore.clear();
    resetDidWebvhState();

    const restored = await AgentIdentity.importDidWebvhHistory(didLog);
    const resolved = await AgentIdentity.resolve(document.id);
    const history = AgentIdentity.getDocumentHistory(document.id);

    expect(restored.id).toEqual(document.id);
    expect(resolved.authentication).toEqual([`${document.id}#key-2`]);
    expect(history.map((entry) => entry.action)).toEqual(['created', 'updated', 'rotated-key']);
    expect(AgentIdentity.exportDidWebvhHistory(document.id)).toEqual(didLog);
  });

  it('should persist and restore did:webvh history via filesystem roundtrip', async () => {
    const { document } = await agentIdentity.create({
      name: 'HistoryFileBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'file lifecycle prompt',
    });

    await AgentIdentity.updateDidDocument(document.id, {
      version: '1.0.1',
      description: 'saved to disk'
    });
    await AgentIdentity.rotateVerificationMethod(document.id);

    const fs = await import('node:fs/promises');
    const os = await import('node:os');
    const path = await import('node:path');
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'agentdid-history-'));
    const didLogPath = path.join(tempDir, 'history.did.jsonl');

    try {
      await AgentIdentity.saveDidWebvhHistoryToFile(document.id, didLogPath);
      const savedDidLog = await fs.readFile(didLogPath, 'utf8');

      AgentIdentity.setResolver(new InMemoryDIDResolver());
      AgentIdentity.setRegistry(new InMemoryAgentRegistry());
      (AgentIdentity.getDefaultClient() as unknown as { documentHistoryStore: Map<string, unknown> }).documentHistoryStore.clear();
      resetDidWebvhState();

      const restored = await AgentIdentity.loadDidWebvhHistoryFromFile(didLogPath);

      expect(savedDidLog).toEqual(AgentIdentity.exportDidWebvhHistory(document.id));
      expect(restored.authentication).toEqual([`${document.id}#key-2`]);
      expect((await AgentIdentity.resolve(document.id)).id).toEqual(document.id);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('should persist and restore did:webvh history via backend source contract', async () => {
    const { document } = await agentIdentity.create({
      name: 'HistorySourceBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'source lifecycle prompt',
    });

    await AgentIdentity.updateDidDocument(document.id, {
      version: '1.0.1',
      description: 'saved to source backend'
    });
    await AgentIdentity.rotateVerificationMethod(document.id);

    const sourceStore = new Map<string, string>();
    const source: DIDDocumentSource = {
      getByReference: jest.fn().mockResolvedValue(null),
      getDidLogByReference: jest.fn(async (documentRef: string) => sourceStore.get(documentRef) ?? null),
      storeDidLogByReference: jest.fn(async (documentRef: string, didLog: string) => {
        sourceStore.set(documentRef, didLog);
      })
    };
    const documentRef = 'history://agentdid/source-bot';

    await AgentIdentity.persistDidWebvhHistoryToSource(document.id, documentRef, source);

    AgentIdentity.setResolver(new InMemoryDIDResolver());
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
    (AgentIdentity.getDefaultClient() as unknown as { documentHistoryStore: Map<string, unknown> }).documentHistoryStore.clear();
    resetDidWebvhState();

    const restored = await AgentIdentity.restoreDidWebvhHistoryFromSource(documentRef, source);

    expect(restored.authentication).toEqual([`${document.id}#key-2`]);
    expect(source.storeDidLogByReference).toHaveBeenCalledWith(documentRef, expect.any(String));
    expect(source.getDidLogByReference).toHaveBeenCalledWith(documentRef);
    expect((await AgentIdentity.resolve(document.id)).id).toEqual(document.id);
  });

  it('should reject did.jsonl history export for legacy non-webvh identifiers', async () => {
    const { document } = await agentIdentity.create({
      name: 'LegacyHistoryBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'legacy export prompt',
      didMethod: 'agent'
    });

    expect(() => AgentIdentity.exportDidWebvhHistory(document.id)).toThrow(/did:webvh DID is required/i);
  });

  it('should create an agent with an external signer (production mode)', async () => {
    const [signer] = LocalKeySigner.generate();

    const result = await agentIdentity.create({
      name: 'ProductionBot',
      coreModel: 'gpt-4o',
      systemPrompt: 'production prompt',
      signer
    });

    expect(result.document).toBeDefined();
    expect(result.document.verificationMethod[0].publicKeyMultibase).toMatch(/^z6Mk/);
    // agentPrivateKey is empty string in production mode
    expect(result.agentPrivateKey).toEqual('');
  });

  it('should sign and verify messages using an external signer', async () => {
    const [signer, privateKeyHex] = LocalKeySigner.generate();

    const result = await agentIdentity.create({
      name: 'SignerTestBot',
      coreModel: 'test',
      systemPrompt: 'test',
      signer
    });

    const payload = 'signer-test-payload';
    const signatureViaSigner = await agentIdentity.signMessage(payload, signer);
    const signatureViaKey = await agentIdentity.signMessage(payload, privateKeyHex);

    // Both should produce the same signature
    expect(signatureViaSigner).toEqual(signatureViaKey);

    // Should verify correctly
    const valid = await AgentIdentity.verifySignature(result.document.id, payload, signatureViaSigner);
    expect(valid).toBe(true);
  });

  it('should sign HTTP requests using an external signer', async () => {
    const [signer] = LocalKeySigner.generate();

    const result = await agentIdentity.create({
      name: 'HttpSignerBot',
      coreModel: 'test',
      systemPrompt: 'test',
      signer
    });

    const headers = await agentIdentity.signHttpRequest({
      method: 'POST',
      url: 'https://api.example.com/v1/action',
      body: '{"action":"approve"}',
      signer,
      agentDid: result.document.id
    });

    expect(headers['Signature']).toBeDefined();
    expect(headers['X-Request-Nonce']).toBeUndefined();

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: 'POST',
      url: 'https://api.example.com/v1/action',
      body: '{"action":"approve"}',
      headers
    });
    expect(valid).toBe(true);
  });
});

describe('Bootstrap controller keys', () => {
  const [creatorSigner] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner: creatorSigner, network: 'polygon' });
  const minimalParams: CreateAgentParams = {
    name: 'BootstrapBot',
    coreModel: 'gpt-4.1-mini',
    systemPrompt: 'You are a bootstrap test agent.'
  };

  beforeEach(() => {
    AgentIdentity.setResolver(new InMemoryDIDResolver());
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
  });

  it('returns a random controller key that controls the bootstrap controller document', async () => {
    const result = await identity.create(minimalParams);
    const controllerPrivateKey = result.controllerPrivateKey as string;

    expect(controllerPrivateKey).toMatch(/^[0-9a-f]{64}$/);

    const controllerDocument = await AgentIdentity.resolve(result.document.controller);
    const expectedPublicKey = encodePublicKeyMultibase(ed25519.getPublicKey(hexToBytes(controllerPrivateKey)));
    expect(controllerDocument.verificationMethod[0].publicKeyMultibase).toEqual(expectedPublicKey);

    const signature = await identity.signMessage('controller-statement', controllerPrivateKey);
    await expect(
      AgentIdentity.verifySignature(result.document.controller, 'controller-statement', signature)
    ).resolves.toBe(true);
  });

  it('never derives the controller key from public data', async () => {
    const result = await identity.create(minimalParams);
    const controllerDid = result.document.controller;
    const publiclyDerivableSeed = bytesToHex(sha256(new TextEncoder().encode(`${controllerDid}:bootstrap-key`)));

    expect(result.controllerPrivateKey).not.toEqual(publiclyDerivableSeed);

    const forgedSignature = bytesToHex(
      ed25519.sign(new TextEncoder().encode('forged-statement'), hexToBytes(publiclyDerivableSeed))
    );
    await expect(
      AgentIdentity.verifySignature(controllerDid, 'forged-statement', forgedSignature)
    ).resolves.toBe(false);
  });

  it('generates a fresh controller key for each new bootstrap', async () => {
    const first = await identity.create(minimalParams);

    AgentIdentity.setResolver(new InMemoryDIDResolver());
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
    const second = await identity.create(minimalParams);

    // did:webvh v1.0 derives the SCID from the genesis entry, so a new bootstrap is a new controller DID.
    expect(second.document.controller).not.toEqual(first.document.controller);
    expect(second.controllerPrivateKey).toBeDefined();
    expect(second.controllerPrivateKey).not.toEqual(first.controllerPrivateKey);
  });

  it('returns the controller key only when the controller document is created', async () => {
    const first = await identity.create(minimalParams);
    const controllerBefore = await AgentIdentity.resolve(first.document.controller);

    const second = await identity.create({ ...minimalParams, name: 'BootstrapBot-2' });

    expect(second.document.controller).toEqual(first.document.controller);
    expect(second.controllerPrivateKey).toBeUndefined();
    expect('controllerPrivateKey' in second).toBe(false);
    await expect(AgentIdentity.resolve(first.document.controller)).resolves.toEqual(controllerBefore);
  });

  it('does not fabricate an explicitly supplied controller', async () => {
    const controllerDid = 'did:webvh:QmControllerScid:agents.example:organizations:acme-support';
    const result = await identity.create({
      ...minimalParams,
      webvh: {
        domain: 'agents.example',
        controllerDid,
        controllerSigner: new LocalKeySigner('7c'.repeat(32)),
        pathSegments: ['agents', 'bootstrap-bot']
      }
    });

    expect(result.document.controller).toEqual(controllerDid);
    expect(result.controllerPrivateKey).toBeUndefined();
    await expect(AgentIdentity.resolve(controllerDid)).rejects.toThrow();
    await expect(AgentIdentity.resolve(result.document.id)).resolves.toMatchObject({ id: result.document.id });
  });

  describe('Metadata commitments', () => {
    const baseParams = {
      name: 'CommitmentBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'You are a helpful assistant.'
    };

    it('commits to model and prompt with salted HMACs and returns the salts once', async () => {
      const { document, metadataCommitmentSalts: salts } = await identity.create(baseParams);
      const metadataCommitmentSalts = salts as NonNullable<typeof salts>;
      const { coreModelHash, systemPromptHash } = document.agentMetadata;

      expect(coreModelHash).toMatch(/^hash:\/\/hmac-sha256\/[0-9a-f]{64}$/);
      expect(systemPromptHash).toMatch(/^hash:\/\/hmac-sha256\/[0-9a-f]{64}$/);
      expect(metadataCommitmentSalts.coreModel).not.toEqual(metadataCommitmentSalts.systemPrompt);
      expect(verifyMetadataCommitment(systemPromptHash, baseParams.systemPrompt, metadataCommitmentSalts.systemPrompt)).toBe(true);
      expect(verifyMetadataCommitment(coreModelHash, baseParams.coreModel, metadataCommitmentSalts.coreModel)).toBe(true);
      expect(JSON.stringify(document)).not.toContain(metadataCommitmentSalts.systemPrompt);
    });

    it('does not let a verifier confirm a guessed prompt without the salt', async () => {
      const { document } = await identity.create(baseParams);
      expect(verifyMetadataCommitment(document.agentMetadata.systemPromptHash, baseParams.systemPrompt)).toBe(false);
      expect(document.agentMetadata.systemPromptHash).not.toContain(
        bytesToHex(sha256(new TextEncoder().encode(baseParams.systemPrompt)))
      );
    });

    it('produces different commitments for the same prompt across agents', async () => {
      const first = await identity.create(baseParams);
      const second = await identity.create(baseParams);
      expect(first.document.agentMetadata.systemPromptHash).not.toEqual(second.document.agentMetadata.systemPromptHash);
    });

    it('uses caller-supplied salts', async () => {
      const systemPromptSalt = generateCommitmentSalt();
      const coreModelSalt = generateCommitmentSalt();
      const { document, metadataCommitmentSalts } = await identity.create({ ...baseParams, systemPromptSalt, coreModelSalt });
      expect(metadataCommitmentSalts).toEqual({ coreModel: coreModelSalt, systemPrompt: systemPromptSalt });
      expect(verifyMetadataCommitment(document.agentMetadata.systemPromptHash, baseParams.systemPrompt, systemPromptSalt)).toBe(true);
    });

    it('rejects malformed caller-supplied salts', async () => {
      await expect(identity.create({ ...baseParams, systemPromptSalt: 'not-hex' })).rejects.toThrow('64 hex characters');
    });

    it('requires a salt when an update changes the prompt or model', async () => {
      const { document } = await identity.create(baseParams);
      await expect(AgentIdentity.updateDidDocument(document.id, { systemPrompt: 'new prompt' }))
        .rejects.toThrow('systemPromptSalt is required');
      await expect(AgentIdentity.updateDidDocument(document.id, { coreModel: 'gpt-4.1' }))
        .rejects.toThrow('coreModelSalt is required');

      const systemPromptSalt = generateCommitmentSalt();
      const updated = await AgentIdentity.updateDidDocument(document.id, { systemPrompt: 'new prompt', systemPromptSalt });
      expect(verifyMetadataCommitment(updated.agentMetadata.systemPromptHash, 'new prompt', systemPromptSalt)).toBe(true);
      expect(updated.agentMetadata.coreModelHash).toEqual(document.agentMetadata.coreModelHash);
    });
  });
});

describe('did:webvh v1.0 lifecycle authorization', () => {
  const [creatorSigner] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner: creatorSigner, network: 'polygon' });
  const controllerSigner = new LocalKeySigner('7c'.repeat(32));
  const params = {
    name: 'LifecycleBot',
    coreModel: 'gpt-4o-mini',
    systemPrompt: 'lifecycle prompt',
    webvh: {
      domain: 'agents.example',
      controllerDid: 'did:webvh:QmControllerScid:agents.example:organizations:acme-support',
      controllerSigner,
      pathSegments: ['agents', 'lifecycle-bot']
    }
  };

  beforeEach(() => {
    AgentIdentity.setResolver(new InMemoryDIDResolver());
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
    resetDidWebvhState();
  });

  /** Simulates another process: the log is known (imported), the controller signer is not. */
  async function importIntoFreshProcess(did: string): Promise<void> {
    const log = AgentIdentity.exportDidWebvhHistory(did);
    AgentIdentity.setResolver(new InMemoryDIDResolver());
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
    resetDidWebvhState();
    await AgentIdentity.importDidWebvhHistory(log);
  }

  it('makes the controller key, not the agent key, the only update key', async () => {
    const { document } = await identity.create(params);
    const resolved = await resolveDidWebvhLog(AgentIdentity.exportDidWebvhHistory(document.id));

    expect(resolved.metadata.updateKeys).toEqual([await didWebvhUpdateKeyFor(controllerSigner)]);
    expect(resolved.metadata.updateKeys).not.toContain(document.verificationMethod[0].publicKeyMultibase);
  });

  it('requires webvh.controllerSigner for the explicit profile', async () => {
    const { controllerSigner: _omitted, ...withoutSigner } = params.webvh;
    await expect(
      identity.create({ ...params, webvh: withoutSigner as unknown as typeof params.webvh })
    ).rejects.toThrow(/controllerSigner is required/u);
  });

  it('rejects webvh.scid, which v1.0 derives from the genesis entry', async () => {
    await expect(
      identity.create({ ...params, webvh: { ...params.webvh, scid: 'QmChosen' } as unknown as typeof params.webvh })
    ).rejects.toThrow(/webvh\.scid is no longer supported/u);
  });

  it('requires the controller signer to change an imported DID', async () => {
    const { document } = await identity.create(params);
    await importIntoFreshProcess(document.id);

    await expect(AgentIdentity.updateDidDocument(document.id, { version: '2.0.0' })).rejects.toThrow(
      /controller signer is required/u
    );
    await expect(AgentIdentity.rotateVerificationMethod(document.id)).rejects.toThrow(/controller signer is required/u);
    await expect(AgentIdentity.revokeDid(document.id)).rejects.toThrow(/controller signer is required/u);
    await expect(AgentIdentity.resolve(document.id)).resolves.toMatchObject({ id: document.id });
  });

  it('rejects a signer that is not the controller', async () => {
    const { document } = await identity.create(params);
    await importIntoFreshProcess(document.id);

    const notTheController = new LocalKeySigner('9e'.repeat(32));
    await expect(
      AgentIdentity.updateDidDocument(document.id, { version: '2.0.0' }, { controllerSigner: notTheController })
    ).rejects.toMatchObject({ code: 'unauthorized' });
    await expect(
      AgentIdentity.revokeDid(document.id, { controllerSigner: notTheController })
    ).rejects.toBeInstanceOf(DidWebvhError);
    await expect(AgentIdentity.resolve(document.id)).resolves.toMatchObject({ id: document.id });
  });

  it('accepts the controller signer for an imported DID', async () => {
    const { document } = await identity.create(params);
    await importIntoFreshProcess(document.id);

    const updated = await AgentIdentity.updateDidDocument(document.id, { version: '2.0.0' }, { controllerSigner });
    const rotated = await AgentIdentity.rotateVerificationMethod(document.id, { controllerSigner });
    await AgentIdentity.revokeDid(document.id, { controllerSigner });

    expect(updated.agentMetadata.version).toEqual('2.0.0');
    expect(rotated.verificationMethodId).toEqual(`${document.id}#key-2`);
    await expect(AgentIdentity.resolve(document.id)).rejects.toThrow(/revoked/u);
    const log = await resolveDidWebvhLog(AgentIdentity.exportDidWebvhHistory(document.id));
    expect(log.metadata.versionNumber).toEqual(4);
    expect(log.metadata.deactivated).toBe(true);
  });

  it('refuses to import a log that fails verification and registers nothing', async () => {
    const { document } = await identity.create(params);
    const lines = AgentIdentity.exportDidWebvhHistory(document.id).trimEnd().split('\n');
    const entry = JSON.parse(lines[0]);
    entry.state.controller = 'did:webvh:QmAttacker:attacker.example';
    const tampered = JSON.stringify(entry) + '\n';
    AgentIdentity.setResolver(new InMemoryDIDResolver());
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
    resetDidWebvhState();

    await expect(AgentIdentity.importDidWebvhHistory(tampered)).rejects.toBeInstanceOf(DidWebvhError);
    await expect(AgentIdentity.resolve(document.id)).rejects.toThrow();
  });

  it('imports a deactivated log as revoked', async () => {
    const { document } = await identity.create(params);
    await AgentIdentity.revokeDid(document.id);
    await importIntoFreshProcess(document.id);

    await expect(AgentIdentity.resolve(document.id)).rejects.toThrow(/revoked/u);
    expect(AgentIdentity.getDocumentHistory(document.id).map((entry) => entry.action)).toEqual(['created', 'revoked']);
  });

  it('does not revoke a did:webvh DID through the registry alone', async () => {
    const registry = new InMemoryAgentRegistry();
    AgentIdentity.setRegistry(registry);
    const { document } = await identity.create(params);

    await registry.revoke(document.id);

    await expect(AgentIdentity.resolve(document.id)).resolves.toMatchObject({ id: document.id });
  });

  it('keeps a deactivated did:webvh DID revoked when the registry record is lost', async () => {
    const { document } = await identity.create(params);
    await AgentIdentity.revokeDid(document.id);

    AgentIdentity.setRegistry(new InMemoryAgentRegistry());

    await expect(AgentIdentity.resolve(document.id)).rejects.toThrow(/revoked/u);
  });

  it('fails closed when the stored did:webvh log no longer verifies', async () => {
    const { document } = await identity.create(params);
    await AgentIdentity.resolve(document.id);
    const stores = AgentIdentity.getDefaultClient() as unknown as Record<'didWebvhLogStore', Map<string, string>>;
    const entry = JSON.parse(stores.didWebvhLogStore.get(document.id)!.trimEnd().split('\n')[0]);
    entry.state.controller = 'did:webvh:QmAttacker:attacker.example';
    stores.didWebvhLogStore.set(document.id, JSON.stringify(entry) + '\n');

    await expect(AgentIdentity.resolve(document.id)).rejects.toBeInstanceOf(DidWebvhError);
  });
});
