/**
 * W3C vc-di-eddsa `eddsa-jcs-2022` test vectors against the SDK's Data Integrity implementation (ADR-006 D-8d).
 *
 * Runs only when VC_DI_EDDSA_DIR points at a checkout of w3c/vc-di-eddsa at the commit pinned in
 * fixtures/vc-di-eddsa-test-vectors.json (the CI workflow `ci-vc-di-eddsa-vectors.yml` does this). Python parity:
 * sdk-python/tests/test_vc_di_eddsa_vectors.py.
 */
import fs from 'fs';
import path from 'path';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { canonicalizeJson } from '../src/crypto/hash';
import { decodePublicKeyMultibase } from '../src/crypto/multibase';
import {
  createEddsaJcs2022Proof,
  eddsaJcs2022HashData,
  verifyEddsaJcs2022Proof
} from '../src/crypto/data-integrity';

interface Pin {
  keyPair: string;
  unsigned: string;
  eddsaJcs2022: Record<string, string>;
}

const PIN = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'vc-di-eddsa-test-vectors.json'), 'utf8')
) as Pin;
const DIR = process.env.VC_DI_EDDSA_DIR;
const describeSuite = DIR ? describe : describe.skip;

const text = (file: string) => fs.readFileSync(path.join(DIR as string, file), 'utf8').trim();
const json = (file: string) => JSON.parse(text(file)) as Record<string, unknown>;

/** `z` + base58btc(0x80 0x26 + 32-byte seed): the multicodec Ed25519 private key of the vectors. */
function decodePrivateKeyMultibase(value: string): Uint8Array {
  const bytes = bs58.decode(value.slice(1));
  if (!value.startsWith('z') || bytes.length !== 34 || bytes[0] !== 0x80 || bytes[1] !== 0x26) {
    throw new Error('not an Ed25519 private key multikey');
  }
  return bytes.slice(2);
}

describeSuite('W3C vc-di-eddsa eddsa-jcs-2022 vectors', () => {
  const vectors = PIN.eddsaJcs2022;
  const keyPair = DIR ? json(PIN.keyPair) : {};
  const unsigned = DIR ? json(PIN.unsigned) : {};
  const proofConfig = DIR ? json(vectors.proofConfig) : {};

  it('canonicalizes and hashes the document and the proof configuration', () => {
    const encoder = new TextEncoder();
    expect(canonicalizeJson(unsigned)).toBe(text(vectors.canonicalDocument));
    expect(canonicalizeJson(proofConfig)).toBe(text(vectors.canonicalProofConfig));
    expect(bytesToHex(sha256(encoder.encode(canonicalizeJson(unsigned))))).toBe(text(vectors.documentHash));
    expect(bytesToHex(sha256(encoder.encode(canonicalizeJson(proofConfig))))).toBe(text(vectors.proofConfigHash));
    expect(bytesToHex(eddsaJcs2022HashData(unsigned, proofConfig))).toBe(text(vectors.combinedHash));
  });

  it('creates the signed credential of the vectors', async () => {
    const seed = decodePrivateKeyMultibase(keyPair.privateKeyMultibase as string);
    expect(bytesToHex(ed25519.getPublicKey(seed))).toBe(
      bytesToHex(decodePublicKeyMultibase(keyPair.publicKeyMultibase as string))
    );
    const proof = await createEddsaJcs2022Proof(
      unsigned,
      {
        created: proofConfig.created as string,
        verificationMethod: proofConfig.verificationMethod as string,
        proofPurpose: proofConfig.proofPurpose as string
      },
      async (hashData) => ed25519.sign(hashData, seed)
    );
    expect(bytesToHex(bs58.decode(proof.proofValue.slice(1)))).toBe(text(vectors.signatureHex));
    expect(proof.proofValue).toBe(text(vectors.proofValue));
    expect({ ...unsigned, proof }).toEqual(json(vectors.signed));
  });

  it('verifies the signed credential and rejects a changed one', () => {
    const publicKey = decodePublicKeyMultibase(keyPair.publicKeyMultibase as string);
    const signed = json(vectors.signed);
    expect(verifyEddsaJcs2022Proof(signed, publicKey)).toBe(true);

    const changed = JSON.parse(JSON.stringify(signed));
    changed.credentialSubject.alumniOf = 'Another School';
    expect(verifyEddsaJcs2022Proof(changed, publicKey)).toBe(false);

    const otherContext = JSON.parse(JSON.stringify(signed));
    otherContext['@context'] = ['https://www.w3.org/ns/credentials/v2'];
    expect(verifyEddsaJcs2022Proof(otherContext, publicKey)).toBe(false);
  });
});
