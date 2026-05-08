import { ethers } from 'ethers';
import { AgentIdentity } from '../src/core/AgentIdentity';
import { CreateAgentParams } from '../src/core/types';
import { assertKeyPurpose, assertSigningPurpose, IdentityCompositionError } from '../src/core/identity-composition';
import { LocalKeySigner } from '../src/core/signer';
import { InMemoryAgentRegistry } from '../src/registry/InMemoryAgentRegistry';
import { InMemoryDIDResolver } from '../src/resolver/InMemoryDIDResolver';
import { DIDDocumentSource } from '../src/resolver/types';

describe('AgentIdentity Core Module', () => {
  // Create a random wallet to act as the "Creator" (Controller)
  const creatorWallet = ethers.Wallet.createRandom();
  let agentIdentity: AgentIdentity;

  beforeAll(() => {
    // Initialize the SDK with the creator's wallet
    agentIdentity = new AgentIdentity({
      signer: creatorWallet,
      network: 'polygon'
    });

  });

  beforeEach(() => {
    AgentIdentity.setResolver(new InMemoryDIDResolver());
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
    (AgentIdentity as unknown as { documentHistoryStore: Map<string, unknown>; documentRevisionStore: Map<string, unknown> }).documentHistoryStore.clear();
    (AgentIdentity as unknown as { documentHistoryStore: Map<string, unknown>; documentRevisionStore: Map<string, unknown> }).documentRevisionStore.clear();
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
    expect(document.agentMetadata.coreModelHash.startsWith("hash://sha256/")).toBe(true);
    expect(document.agentMetadata.systemPromptHash.startsWith("hash://sha256/")).toBe(true);
    
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

    expect(result.document.id.startsWith('did:agent:polygon:0x')).toBe(true);
    expect(result.document.controller).toEqual(`did:ethr:${creatorWallet.address}`);
    expect(result.document.verificationMethod[0].blockchainAccountId?.startsWith('eip155:1:0x')).toBe(true);
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
        scid: 'QmAgentScid'
      }
    });

    const document = result.document;
    const expectedDid = 'did:webvh:QmAgentScid:agents.example:agents:webvh-bot';

    expect(document.id).toEqual(expectedDid);
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

    const requestParams = {
      method: 'POST',
      url: 'https://api.example.com/v1/interop',
      body: '{"interop": true}',
      agentPrivateKey,
      agentDid: document.id
    };

    const headers = await agentIdentity.signHttpRequest(requestParams);

    headers['Signature'] = headers['Signature'].replace(/^sig1/, 'sigA');
    headers['Signature-Input'] = headers['Signature-Input']
      .replace(/^sig1/, 'sigA')
      .replace('("@request-target" "host" "date" "content-digest")', '("@request-target" "host" "date" "content-digest" "x-extra")');

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: requestParams.method,
      url: requestParams.url,
      body: requestParams.body,
      headers
    });

    expect(valid).toBe(true);
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
    headers['Signature-Input'] = `other=("@request-target");created=1;keyid="${document.id}#key-1";alg="ed25519", ${headers['Signature-Input']}`;

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: requestParams.method,
      url: requestParams.url,
      body: requestParams.body,
      headers
    });

    expect(valid).toBe(true);
  });

  it('should include anti-replay headers (nonce + expires) in signed HTTP requests', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'AntiReplayBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const headers = await agentIdentity.signHttpRequest({
      method: 'POST',
      url: 'https://api.example.com/v1/data',
      body: '{"nonce": true}',
      agentPrivateKey,
      agentDid: document.id,
      expiresInSeconds: 60
    });

    expect(headers['X-Request-Nonce']).toBeDefined();
    expect(headers['X-Request-Nonce'].length).toBeGreaterThan(0);
    expect(headers['Signature-Input']).toContain('"x-request-nonce"');
    expect(headers['Signature-Input']).toContain('expires=');

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: 'POST',
      url: 'https://api.example.com/v1/data',
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

    const headers = await agentIdentity.signHttpRequest({
      method: 'POST',
      url: 'https://api.example.com/v1/data',
      body: '{"expired": true}',
      agentPrivateKey,
      agentDid: document.id,
      expiresInSeconds: 1
    });

    // Artificially expire: set expires far in the past
    headers['Signature-Input'] = headers['Signature-Input'].replace(
      /expires=\d+/,
      'expires=1000000000'
    );

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: 'POST',
      url: 'https://api.example.com/v1/data',
      body: '{"expired": true}',
      headers
    });
    expect(valid).toBe(false);
  });

  it('should reject HTTP signatures missing x-request-nonce header', async () => {
    const { document, agentPrivateKey } = await agentIdentity.create({
      name: 'NoNonceBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const headers = await agentIdentity.signHttpRequest({
      method: 'POST',
      url: 'https://api.example.com/v1/data',
      body: '{"no-nonce": true}',
      agentPrivateKey,
      agentDid: document.id
    });

    // Remove the nonce header
    delete headers['X-Request-Nonce'];

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: 'POST',
      url: 'https://api.example.com/v1/data',
      body: '{"no-nonce": true}',
      headers
    });
    expect(valid).toBe(false);
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
    const controllerDid = 'did:webvh:QmControllerScid:agents.example:organizations:acme-support';
    const { document: controllerDocument } = await agentIdentity.create({
      name: 'ControllerRoot',
      coreModel: 'controller-model',
      systemPrompt: 'You are the controller root.',
      didMethod: 'webvh',
      webvh: {
        domain: 'agents.example',
        pathSegments: ['organizations', 'acme-support'],
        controllerDid,
        scid: 'QmControllerScid'
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
        controllerDid,
        scid: 'QmAgentScid'
      }
    });

    const chain = await AgentIdentity.resolveControllerChain(agentDocument.id);

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
      systemPrompt: 'updated prompt',
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
      systemPrompt: 'new prompt for ref change'
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
    expect(oldKey!.deactivated).toBeDefined();
    expect(new Date(oldKey!.deactivated!).toISOString()).toEqual(oldKey!.deactivated);

    const newKey = rotation.document.verificationMethod.find(
      m => m.id === rotation.verificationMethodId
    );
    expect(newKey).toBeDefined();
    expect(newKey!.deactivated).toBeUndefined();
  });

  it('should verify historical signatures after key rotation', async () => {
    const { document, agentPrivateKey: oldPrivateKey } = await agentIdentity.create({
      name: 'HistoryBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const payload = 'approve:historical:1';
    const oldKeyId = `${document.id}#key-1`;
    const oldSignature = await agentIdentity.signMessage(payload, oldPrivateKey);

    await AgentIdentity.rotateVerificationMethod(document.id);

    // verifySignature should fail (old key no longer active)
    const activeValid = await AgentIdentity.verifySignature(document.id, payload, oldSignature, oldKeyId);
    expect(activeValid).toBe(false);

    // verifyHistoricalSignature should succeed (old key still in document)
    const historicalValid = await AgentIdentity.verifyHistoricalSignature(
      document.id, payload, oldSignature, oldKeyId
    );
    expect(historicalValid).toBe(true);
  });

  it('should reject historical verification with unknown key id', async () => {
    const { document } = await agentIdentity.create({
      name: 'UnknownKeyBot',
      coreModel: 'test',
      systemPrompt: 'test'
    });

    const payload = 'test-payload';
    const fakeSignature = '00'.repeat(64);

    await expect(AgentIdentity.verifyHistoricalSignature(
      document.id, payload, fakeSignature, `${document.id}#key-999`
    )).rejects.toMatchObject({
      reason: 'key_purpose_violation',
      foundIn: []
    });
  });

  it('should keep auditable history for create, update, rotate, revoke lifecycle', async () => {
    const { document } = await agentIdentity.create({
      name: 'AuditBot',
      coreModel: 'gpt-4o-mini',
      systemPrompt: 'audit trail baseline prompt'
    });

    await AgentIdentity.updateDidDocument(document.id, {
      version: '1.0.1',
      systemPrompt: 'audit trail updated prompt'
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
      systemPrompt: 'export lifecycle prompt v2'
    });

    await AgentIdentity.rotateVerificationMethod(document.id);
    await AgentIdentity.revokeDid(document.id);

    const scid = document.id.split(':')[2];
    const lines = AgentIdentity.exportDidWebvhHistory(document.id)
      .split('\n')
      .map((line) => JSON.parse(line) as { versionId: string; versionTime: string; state: typeof document });

    expect(lines).toHaveLength(3);
    expect(lines.map((line) => line.versionId)).toEqual([
      `1-${scid}`,
      `2-${scid}`,
      `3-${scid}`
    ]);
    expect(lines[0].state.id).toEqual(document.id);
    expect(lines[1].state.agentMetadata.version).toEqual('1.0.1');
    expect(lines[2].state.authentication).toEqual([`${document.id}#key-2`]);
    expect(lines[2].state.verificationMethod.some((method) => method.id === `${document.id}#key-2`)).toBe(true);
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
    (AgentIdentity as unknown as { documentHistoryStore: Map<string, unknown>; documentRevisionStore: Map<string, unknown> }).documentHistoryStore.clear();
    (AgentIdentity as unknown as { documentHistoryStore: Map<string, unknown>; documentRevisionStore: Map<string, unknown> }).documentRevisionStore.clear();

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
      systemPrompt: 'file lifecycle prompt'
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
      (AgentIdentity as unknown as { documentHistoryStore: Map<string, unknown>; documentRevisionStore: Map<string, unknown> }).documentHistoryStore.clear();
      (AgentIdentity as unknown as { documentHistoryStore: Map<string, unknown>; documentRevisionStore: Map<string, unknown> }).documentRevisionStore.clear();

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
      systemPrompt: 'source lifecycle prompt'
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
    (AgentIdentity as unknown as { documentHistoryStore: Map<string, unknown>; documentRevisionStore: Map<string, unknown> }).documentHistoryStore.clear();
    (AgentIdentity as unknown as { documentHistoryStore: Map<string, unknown>; documentRevisionStore: Map<string, unknown> }).documentRevisionStore.clear();

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
    expect(headers['X-Request-Nonce']).toBeDefined();

    const valid = await AgentIdentity.verifyHttpRequestSignature({
      method: 'POST',
      url: 'https://api.example.com/v1/action',
      body: '{"action":"approve"}',
      headers
    });
    expect(valid).toBe(true);
  });
});
