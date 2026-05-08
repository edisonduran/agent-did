import fs from 'fs';
import path from 'path';
import { AgentIdentity } from '../src/core/AgentIdentity';
import { AgentDIDDocument } from '../src/core/types';
import { InMemoryAgentRegistry } from '../src/registry/InMemoryAgentRegistry';
import { InMemoryDIDResolver } from '../src/resolver/InMemoryDIDResolver';

describe('Interoperability Vectors', () => {
  const fixturePath = path.join(__dirname, '..', '..', 'fixtures', 'interop-vectors.json');
  const fixtureSet = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as {
    formatVersion: number;
    vectors: Record<string, {
      did: string;
      controller: string;
      verificationMethod: {
        id: string;
        type: string;
        controller: string;
        publicKeyMultibase: string;
      };
      messageVector: {
        payload: string;
        signatureHex: string;
      };
      httpVector: {
        method: string;
        url: string;
        body: string;
        headers: Record<string, string>;
        maxCreatedSkewSeconds: number;
      };
    }>;
  };

  const buildDidDocument = (fixture: (typeof fixtureSet.vectors)[string]): AgentDIDDocument => ({
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: fixture.did,
    controller: fixture.controller,
    created: '2026-01-01T00:00:00.000Z',
    updated: '2026-01-01T00:00:00.000Z',
    agentMetadata: {
      name: 'InteropFixtureBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [fixture.verificationMethod],
    authentication: [fixture.verificationMethod.id],
    assertionMethod: [fixture.verificationMethod.id]
  });

  const buildControllerDocument = (fixture: (typeof fixtureSet.vectors)[string]): AgentDIDDocument => ({
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: fixture.controller,
    controller: fixture.controller,
    created: '2026-01-01T00:00:00.000Z',
    updated: '2026-01-01T00:00:00.000Z',
    agentMetadata: {
      name: 'InteropFixtureController',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/controller-model',
      systemPromptHash: 'hash://sha256/controller-prompt'
    },
    verificationMethod: [{
      id: `${fixture.controller}#key-1`,
      type: 'Ed25519VerificationKey2020',
      controller: fixture.controller,
      publicKeyMultibase: fixture.verificationMethod.publicKeyMultibase
    }],
    authentication: [`${fixture.controller}#key-1`],
    assertionMethod: [`${fixture.controller}#key-1`]
  });

  describe.each(Object.entries(fixtureSet.vectors))('%s', (_name, fixture) => {
    const didDocument = buildDidDocument(fixture);
    const controllerDocument = buildControllerDocument(fixture);

    beforeEach(async () => {
      const resolver = new InMemoryDIDResolver();
      resolver.registerDocument(didDocument);
      resolver.registerDocument(controllerDocument);

      const registry = new InMemoryAgentRegistry();
      await registry.register(didDocument.id, didDocument.controller, 'hash://sha256/interop-fixture');

      AgentIdentity.setResolver(resolver);
      AgentIdentity.setRegistry(registry);
    });

    it('should verify shared message signature vector', async () => {
      const valid = await AgentIdentity.verifySignature(
        fixture.did,
        fixture.messageVector.payload,
        fixture.messageVector.signatureHex,
        fixture.verificationMethod.id
      );

      expect(valid).toBe(true);
    });

    it('should verify shared HTTP signature vector from fixture headers', async () => {
      const valid = await AgentIdentity.verifyHttpRequestSignature({
        method: fixture.httpVector.method,
        url: fixture.httpVector.url,
        body: fixture.httpVector.body,
        headers: fixture.httpVector.headers,
        maxCreatedSkewSeconds: fixture.httpVector.maxCreatedSkewSeconds
      });

      expect(valid).toBe(true);
    });
  });
});
