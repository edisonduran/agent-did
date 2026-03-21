import fs from 'fs';
import path from 'path';
import {
  hashPayload,
  formatHashUri,
  generateAgentMetadataHash,
  canonicalizeJson,
  generateCanonicalDocumentHash
} from '../src/crypto/hash';

describe('Crypto Hash Module', () => {
  const samplePrompt = "You are a helpful customer support agent.";
  const canonicalFixturePath = path.join(__dirname, '..', '..', 'fixtures', 'canonical-document-reference.json');
  const canonicalFixture = JSON.parse(fs.readFileSync(canonicalFixturePath, 'utf8')) as {
    document: Record<string, unknown>;
    expectedDocumentRef: string;
  };

  it('should generate a deterministic hash for a given payload', () => {
    const hash1 = hashPayload(samplePrompt);
    const hash2 = hashPayload(samplePrompt);
    
    expect(hash1).toBeDefined();
    expect(hash1.startsWith('0x')).toBe(true);
    expect(hash1).toEqual(hash2); // Determinism check
  });

  it('should throw an error for empty payloads', () => {
    expect(() => hashPayload("")).toThrow("Payload cannot be empty");
  });

  it('should format a raw hex hash into a valid URI', () => {
    const rawHash = "0xabcdef123456";
    const uri = formatHashUri(rawHash);
    
    expect(uri).toEqual("hash://sha256/abcdef123456");
  });

  it('should generate a complete metadata hash URI in one step', () => {
    const uri = generateAgentMetadataHash(samplePrompt);
    
    expect(uri).toBeDefined();
    expect(uri.startsWith('hash://sha256/')).toBe(true);
  });

  it('should canonicalize object keys and timestamps before hashing', () => {
    const left = {
      updated: '2024-01-01T00:00:00+00:00',
      agentMetadata: {
        systemPromptHash: 'hash://sha256/prompt',
        coreModelHash: 'hash://sha256/model',
        version: '1.0.0',
        name: 'Fixture'
      },
      created: '2024-01-01T00:00:00Z'
    };
    const right = {
      created: '2024-01-01T00:00:00.000Z',
      agentMetadata: {
        name: 'Fixture',
        version: '1.0.0',
        coreModelHash: 'hash://sha256/model',
        systemPromptHash: 'hash://sha256/prompt'
      },
      updated: '2024-01-01T00:00:00.000Z'
    };

    expect(canonicalizeJson(left)).toEqual(canonicalizeJson(right));
    expect(generateCanonicalDocumentHash(left)).toEqual(generateCanonicalDocumentHash(right));
  });

  it('should match the shared canonical document reference fixture', () => {
    expect(generateCanonicalDocumentHash(canonicalFixture.document)).toEqual(canonicalFixture.expectedDocumentRef);
  });
});
