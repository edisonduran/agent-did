import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { hexToBytes } from '@noble/hashes/utils';
import { verifyEd25519 } from '../src/crypto/ed25519-verify';

interface Vector {
  name: string;
  description: string;
  publicKey: string;
  message: string;
  signature: string;
  valid: boolean;
}

const { vectors } = JSON.parse(
  readFileSync(join(__dirname, '..', '..', 'fixtures', 'ed25519-verification-vectors.json'), 'utf8')
) as { vectors: Vector[] };

describe('Ed25519 verification rule (RFC-001 §7, fixtures/ed25519-verification-vectors.json)', () => {
  it('loads the shared vectors', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(16);
    expect(vectors.some((vector) => vector.valid)).toBe(true);
    expect(vectors.some((vector) => !vector.valid)).toBe(true);
  });

  it.each(vectors.map((vector) => [vector.name, vector] as const))('%s', (_name, vector) => {
    const verified = verifyEd25519(hexToBytes(vector.signature), hexToBytes(vector.message), hexToBytes(vector.publicKey));
    expect(verified).toBe(vector.valid);
  });
});
