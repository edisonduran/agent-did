import fs from 'fs';
import path from 'path';
import { AgentDidClient } from '../src/core/AgentDidClient';
import { InMemoryNonceStore } from '../src/core/nonce-store';
import { AgentDIDDocument, VerificationRelationship } from '../src/core/types';
import { InMemoryAgentRegistry } from '../src/registry/InMemoryAgentRegistry';
import { InMemoryDIDResolver } from '../src/resolver/InMemoryDIDResolver';

interface HttpVector {
  id: string;
  rule: string;
  description: string;
  request: { method: string; url: string; body: string };
  headers: Record<string, string>;
  now?: number;
  maxCreatedSkewSeconds?: number;
  maxSignatureLifetimeSeconds?: number;
  expected?: boolean;
  reason?: string;
  expectedSequence?: boolean[];
  expectedReasons?: Array<string | null>;
}

interface HttpVectorSet {
  formatVersion: number;
  clock: number;
  did: string;
  otherDid: string;
  controller: string;
  keys: Record<string, { id: string; publicKeyMultibase: string; relationships: VerificationRelationship[] }>;
  vectors: HttpVector[];
}

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'http-verification-vectors.json'), 'utf8')
) as HttpVectorSet;

const context = ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'];
const meta = (name: string) => ({
  name,
  version: '1.0.0',
  coreModelHash: 'hash://sha256/model',
  systemPromptHash: 'hash://sha256/prompt'
});

function buildDocument(): AgentDIDDocument {
  const methods = Object.values(fixture.keys).map((key) => ({
    id: key.id,
    type: 'Ed25519VerificationKey2020',
    controller: fixture.controller,
    publicKeyMultibase: key.publicKeyMultibase
  }));
  const idsFor = (relationship: VerificationRelationship) =>
    Object.values(fixture.keys).filter((key) => key.relationships.includes(relationship)).map((key) => key.id);
  return {
    '@context': context,
    id: fixture.did,
    // Self-controlled: the vectors test the HTTP rules, and a document-only resolver cannot prove a controller binding
    controller: fixture.did,
    created: '2024-01-01T00:00:00.000Z',
    updated: '2024-01-01T00:00:00.000Z',
    agentMetadata: meta('HttpVerificationFixtureBot'),
    verificationMethod: methods,
    authentication: idsFor('authentication'),
    assertionMethod: idsFor('assertionMethod'),
    keyAgreement: idsFor('keyAgreement')
  };
}

function buildController(): AgentDIDDocument {
  const key = fixture.keys['key-1'];
  return {
    '@context': context,
    id: fixture.controller,
    controller: fixture.controller,
    created: '2024-01-01T00:00:00.000Z',
    updated: '2024-01-01T00:00:00.000Z',
    agentMetadata: meta('HttpVerificationFixtureController'),
    verificationMethod: [{
      id: `${fixture.controller}#key-1`,
      type: 'Ed25519VerificationKey2020',
      controller: fixture.controller,
      publicKeyMultibase: key.publicKeyMultibase
    }],
    authentication: [`${fixture.controller}#key-1`],
    assertionMethod: [`${fixture.controller}#key-1`]
  };
}

async function clientAt(now: number): Promise<{ client: AgentDidClient; nonceStore: InMemoryNonceStore }> {
  const document = buildDocument();
  const resolver = new InMemoryDIDResolver();
  resolver.registerDocument(document);
  resolver.registerDocument(buildController());
  const registry = new InMemoryAgentRegistry();
  await registry.register(document.id, document.controller, 'hash://sha256/http-verification-fixture');
  // The store's own clock must match the vector clock, or its entries expire at once.
  const nonceStore = new InMemoryNonceStore({ now: () => now });
  const client = new AgentDidClient({ resolver, registry, nonceStore, clock: () => new Date(now * 1000) });
  return { client, nonceStore };
}

describe('HTTP verification vectors (RFC-001 §6.5)', () => {
  it('uses the expected fixture format', () => {
    expect(fixture.formatVersion).toBe(1);
    expect(fixture.vectors.length).toBeGreaterThan(0);
    const ids = fixture.vectors.map((vector) => vector.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it.each(fixture.vectors.map((vector) => [vector.id, vector] as const))('%s', async (_id, vector) => {
    const now = vector.now ?? fixture.clock;
    const { client, nonceStore } = await clientAt(now);
    const verify = () =>
      client.verifyHttpRequestSignatureDetailed({
        ...vector.request,
        headers: vector.headers,
        maxCreatedSkewSeconds: vector.maxCreatedSkewSeconds,
        maxSignatureLifetimeSeconds: vector.maxSignatureLifetimeSeconds,
        nonceStore
      });

    if (vector.expectedSequence) {
      const results = [];
      for (let i = 0; i < vector.expectedSequence.length; i += 1) {
        results.push(await verify());
      }
      expect(results.map((result) => result.ok)).toEqual(vector.expectedSequence);
      expect(results.map((result) => (result.ok ? null : result.reason))).toEqual(vector.expectedReasons);
      return;
    }

    const result = await verify();
    expect(result.ok).toBe(vector.expected);
    expect(result.ok ? undefined : result.reason).toBe(vector.reason);

    // The boolean method gives the same verdict (fresh client: its nonce store is not shared).
    const fresh = await clientAt(now);
    await expect(
      fresh.client.verifyHttpRequestSignature({
        ...vector.request,
        headers: vector.headers,
        maxCreatedSkewSeconds: vector.maxCreatedSkewSeconds,
        maxSignatureLifetimeSeconds: vector.maxSignatureLifetimeSeconds,
        nonceStore: fresh.nonceStore
      })
    ).resolves.toBe(vector.expected);
  });
});
