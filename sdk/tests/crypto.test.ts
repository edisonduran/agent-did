import fs from 'fs';
import path from 'path';
import {
  hashPayload,
  formatHashUri,
  generateAgentMetadataHash,
  canonicalizeJson,
  generateCanonicalDocumentHash,
  generateCommitmentSalt,
  createMetadataCommitment,
  verifyMetadataCommitment
} from '../src/crypto/hash';

describe('Crypto Hash Module', () => {
  const samplePrompt = "You are a helpful customer support agent.";
  const canonicalFixturePath = path.join(__dirname, '..', '..', 'fixtures', 'canonical-document-reference.json');
  const canonicalFixture = JSON.parse(fs.readFileSync(canonicalFixturePath, 'utf8')) as {
    document: Record<string, unknown>;
    expectedDocumentRef: string;
  };
  const jcsVectors = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'jcs-vectors.json'), 'utf8')
  ) as {
    documents: Array<{ name: string; input: string; expected: string }>;
    numbers: Array<{ ieee754: string; expected?: string; error?: boolean }>;
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

  it('should produce the same hash regardless of key order', () => {
    const left = {
      updated: '2024-01-01T00:00:00.000Z',
      agentMetadata: { systemPromptHash: 'hash://sha256/prompt', name: 'Fixture' },
      created: '2024-01-01T00:00:00.000Z'
    };
    const right = {
      created: '2024-01-01T00:00:00.000Z',
      agentMetadata: { name: 'Fixture', systemPromptHash: 'hash://sha256/prompt' },
      updated: '2024-01-01T00:00:00.000Z'
    };

    expect(canonicalizeJson(left)).toEqual(canonicalizeJson(right));
    expect(generateCanonicalDocumentHash(left)).toEqual(generateCanonicalDocumentHash(right));
  });

  it('should hash timestamps exactly as given (no normalization)', () => {
    expect(canonicalizeJson({ created: '2024-01-01T00:00:00Z' })).toEqual('{"created":"2024-01-01T00:00:00Z"}');
    expect(generateCanonicalDocumentHash({ created: '2024-01-01T00:00:00Z' }))
      .not.toEqual(generateCanonicalDocumentHash({ created: '2024-01-01T00:00:00.000Z' }));
  });

  it('should sort keys by UTF-16 code units, not locale', () => {
    expect(canonicalizeJson({ a: 1, B: 2, 'é': 3, '\u{1f602}': 4, 'דּ': 5 }))
      .toEqual('{"B":2,"a":1,"é":3,"\u{1f602}":4,"דּ":5}');
  });

  it('should keep null members and drop undefined ones', () => {
    expect(canonicalizeJson({ b: null, c: undefined, a: [null, undefined] })).toEqual('{"a":[null,null],"b":null}');
  });

  it('should reject values outside JCS', () => {
    expect(() => canonicalizeJson(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalizeJson(Number.POSITIVE_INFINITY)).toThrow(TypeError);
    expect(() => canonicalizeJson(10n)).toThrow(TypeError);
    expect(() => canonicalizeJson(undefined)).toThrow(TypeError);
  });

  it('should match the RFC 8785 reference documents', () => {
    for (const vector of jcsVectors.documents) {
      expect({ name: vector.name, out: canonicalizeJson(JSON.parse(vector.input)) })
        .toEqual({ name: vector.name, out: vector.expected });
    }
  });

  it('should match the RFC 8785 Appendix B number vectors', () => {
    for (const vector of jcsVectors.numbers) {
      const value = Buffer.from(vector.ieee754, 'hex').readDoubleBE(0);
      if (vector.error) {
        expect(() => canonicalizeJson(value)).toThrow(TypeError);
      } else {
        expect({ ieee754: vector.ieee754, out: canonicalizeJson(value) })
          .toEqual({ ieee754: vector.ieee754, out: vector.expected });
      }
    }
  });

  it('should compute standard SHA-256 digests', () => {
    // SHA-256("abc"), FIPS 180-2 test vector
    expect(hashPayload('abc')).toEqual('0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('should match the shared canonical document reference fixture', () => {
    expect(generateCanonicalDocumentHash(canonicalFixture.document)).toEqual(canonicalFixture.expectedDocumentRef);
  });

  describe('metadata commitments', () => {
    const vectors = JSON.parse(
      fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'metadata-commitment-vectors.json'), 'utf8')
    ) as {
      hmacSha256: Array<{ name: string; value: string; salt: string; expected: string }>;
      legacySha256: Array<{ name: string; value: string; expected: string }>;
    };

    it('matches the shared HMAC-SHA256 commitment vectors', () => {
      for (const vector of vectors.hmacSha256) {
        expect({ name: vector.name, out: createMetadataCommitment(vector.value, vector.salt) })
          .toEqual({ name: vector.name, out: vector.expected });
        expect(verifyMetadataCommitment(vector.expected, vector.value, vector.salt)).toBe(true);
        expect(verifyMetadataCommitment(vector.expected, vector.value, vector.salt.toUpperCase())).toBe(true);
      }
    });

    it('verifies legacy unsalted sha256 commitments without a salt', () => {
      for (const vector of vectors.legacySha256) {
        expect(verifyMetadataCommitment(vector.expected, vector.value)).toBe(true);
        expect(verifyMetadataCommitment(vector.expected, `${vector.value}!`)).toBe(false);
      }
    });

    it('rejects wrong values, wrong or missing salts, and unknown schemes', () => {
      const [vector] = vectors.hmacSha256;
      expect(verifyMetadataCommitment(vector.expected, `${vector.value} `, vector.salt)).toBe(false);
      expect(verifyMetadataCommitment(vector.expected, vector.value, generateCommitmentSalt())).toBe(false);
      expect(verifyMetadataCommitment(vector.expected, vector.value)).toBe(false);
      expect(verifyMetadataCommitment(vector.expected, vector.value, 'abcd')).toBe(false);
      expect(verifyMetadataCommitment(vector.expected.replace('hmac-sha256', 'sha512'), vector.value, vector.salt)).toBe(false);
      expect(verifyMetadataCommitment(vector.expected, '', vector.salt)).toBe(false);
    });

    it('generates distinct 32-byte salts and validates salt format', () => {
      const salts = new Set(Array.from({ length: 50 }, () => generateCommitmentSalt()));
      expect(salts.size).toBe(50);
      for (const salt of salts) {
        expect(salt).toMatch(/^[0-9a-f]{64}$/);
      }
      expect(() => createMetadataCommitment('value', 'zz'.repeat(32))).toThrow('64 hex characters');
      expect(() => createMetadataCommitment('value', 'ab'.repeat(16))).toThrow('64 hex characters');
      expect(() => createMetadataCommitment('', generateCommitmentSalt())).toThrow('cannot be empty');
    });
  });
});
