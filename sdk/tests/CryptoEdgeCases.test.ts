import { ed25519 } from '@noble/curves/ed25519';
import {
  createEddsaJcs2022Proof,
  decodeEddsaProofValue,
  encodeEddsaProofValue,
  verifyEddsaJcs2022Proof
} from '../src/crypto/data-integrity';
import { canonicalizeJson, generateAgentMetadataHash, verifyMetadataCommitment } from '../src/crypto/hash';

// Edge cases of the crypto modules that the protocol-level tests do not reach (C-QA-2).

describe('canonicalizeJson', () => {
  it('serializes a value through its toJSON, as JSON.stringify does', () => {
    expect(canonicalizeJson({ at: new Date(0) })).toBe('{"at":"1970-01-01T00:00:00.000Z"}');
  });
});

describe('verifyMetadataCommitment', () => {
  it('rejects a sha256 commitment URI of the wrong length', () => {
    const uri = generateAgentMetadataHash('value');
    expect(verifyMetadataCommitment(uri.slice(0, -2), 'value')).toBe(false);
    expect(verifyMetadataCommitment(uri, 'value')).toBe(true);
  });
});

describe('eddsa-jcs-2022 proofs', () => {
  const privateKey = new Uint8Array(32).fill(7);
  const publicKey = ed25519.getPublicKey(privateKey);
  const sign = async (data: Uint8Array) => ed25519.sign(data, privateKey);
  const options = { verificationMethod: 'did:example:a#key-1', proofPurpose: 'assertionMethod' };
  const unsecured = { '@context': ['https://www.w3.org/ns/credentials/v2'], id: 'urn:uuid:1', value: 1 };

  async function secured(): Promise<Record<string, unknown>> {
    return { ...unsecured, proof: await createEddsaJcs2022Proof(unsecured, options, sign) };
  }

  it('refuses to add a second proof', async () => {
    await expect(createEddsaJcs2022Proof(await secured(), options, sign)).rejects.toThrow('already carries a proof');
  });

  it('refuses a signer that returns something other than 64 bytes', async () => {
    await expect(createEddsaJcs2022Proof(unsecured, options, async () => new Uint8Array(63))).rejects.toThrow('64 bytes');
    expect(() => encodeEddsaProofValue(new Uint8Array(65))).toThrow('64 bytes');
  });

  it('decodes only z-prefixed base58btc of 64 bytes', () => {
    expect(decodeEddsaProofValue(42)).toBeUndefined();
    expect(decodeEddsaProofValue('u' + 'A'.repeat(86))).toBeUndefined();
    expect(decodeEddsaProofValue('z0OIl')).toBeUndefined(); // not base58
    expect(decodeEddsaProofValue('z' + 'A'.repeat(10))).toBeUndefined(); // wrong length
  });

  it('verifies a proof and rejects every malformed variant', async () => {
    const document = await secured();
    const proof = document.proof as Record<string, unknown>;
    expect(verifyEddsaJcs2022Proof(document, publicKey)).toBe(true);

    expect(verifyEddsaJcs2022Proof('not an object', publicKey)).toBe(false);
    expect(verifyEddsaJcs2022Proof({ ...unsecured }, publicKey)).toBe(false);
    expect(verifyEddsaJcs2022Proof({ ...document, proof: { ...proof, cryptosuite: 'eddsa-rdfc-2022' } }, publicKey)).toBe(false);
    expect(verifyEddsaJcs2022Proof({ ...document, proof: { ...proof, proofValue: 'z0' } }, publicKey)).toBe(false);
    // A value JCS cannot serialize makes the check fail instead of throwing
    expect(verifyEddsaJcs2022Proof({ ...document, value: Number.NaN }, publicKey)).toBe(false);
  });

  it('checks that a proof @context is a prefix of the document @context', async () => {
    const withContext = { ...unsecured, '@context': ['https://www.w3.org/ns/credentials/v2', 'https://example.org/v1'] };
    const proof = await createEddsaJcs2022Proof(
      withContext,
      options,
      sign
    );
    const contextProof = { ...proof, '@context': ['https://www.w3.org/ns/credentials/v2', 'https://example.org/v1', 'https://example.org/v2'] };
    expect(verifyEddsaJcs2022Proof({ ...withContext, proof: contextProof }, publicKey)).toBe(false);
    const mismatch = { ...proof, '@context': ['https://example.org/other'] };
    expect(verifyEddsaJcs2022Proof({ ...withContext, proof: mismatch }, publicKey)).toBe(false);
  });
});
