import { ethers } from 'ethers';
import { AgentIdentity } from '../src/core/AgentIdentity';
import { CreateAgentParams } from '../src/core/types';
import { LocalKeySigner } from '../src/core/signer';
import { InMemoryAgentRegistry } from '../src/registry/InMemoryAgentRegistry';

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

    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
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
    expect(document.id.startsWith("did:agent:polygon:0x")).toBe(true);
    
    // 2. Verify Controller (Creator)
    const expectedControllerDid = `did:ethr:${creatorWallet.address}`;
    expect(document.controller).toEqual(expectedControllerDid);

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
    expect(vm.controller).toEqual(expectedControllerDid);
    expect(vm.type).toEqual("Ed25519VerificationKey2020");
    expect(vm.blockchainAccountId?.startsWith("eip155:1:0x")).toBe(true);

    // 5. Verify Authentication Binding
    expect(document.authentication).toContain(vm.id);
    
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

    const valid = await AgentIdentity.verifyHistoricalSignature(
      document.id, payload, fakeSignature, `${document.id}#key-999`
    );
    expect(valid).toBe(false);
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
