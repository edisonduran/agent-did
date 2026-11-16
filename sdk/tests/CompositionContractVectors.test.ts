/**
 * Shared composition contract vectors (fixtures/composition-contract-vectors.json, contract §7). Python parity:
 * sdk-python/tests/test_composition_contract_vectors.py.
 */
import fs from 'fs';
import path from 'path';
import { AgentDIDDocument, LocalKeySigner } from '../src';
import { agentCardSigningPayload, parseSignedAgentCard, signAgentCard } from '../src/core/agent-card';
import { agentDidDocumentProblem } from '../src/core/document-guard';
import { compositionReasonForKey } from '../src/core/identity-composition';
import { verifyEd25519 } from '../src/crypto/ed25519-verify';
import { decodePublicKeyMultibase } from '../src/crypto/multibase';

const VECTORS = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'composition-contract-vectors.json'), 'utf8')
) as {
  keys: Record<string, { seedHex: string; publicKeyMultibase: string }>;
  sign: { card: Record<string, unknown>; keyId: string; signedCard: Record<string, unknown> };
  cards: Array<{ name: string; card: unknown; expected: string; did?: string; publishedKeyIds?: string[] }>;
  payloads: Array<{ name: string; card: Record<string, unknown>; payload: string }>;
  documents: Array<{ name: string; document: unknown; valid: boolean }>;
  reasons: Array<{ name: string; document: AgentDIDDocument; keyId: string; expected: string }>;
};

/** Format check, then every signature against the key of its kid: what a resolver-backed verifier does. */
function cardOutcome(card: unknown): { expected: string; did?: string; publishedKeyIds?: string[] } {
  const parsed = parseSignedAgentCard(card);
  if (!parsed) {
    return { expected: 'format_drift' };
  }
  for (const entry of parsed.signatures) {
    const key = VECTORS.keys[entry.keyId];
    const valid =
      key !== undefined &&
      verifyEd25519(entry.signature, new TextEncoder().encode(entry.signingInput), decodePublicKeyMultibase(key.publicKeyMultibase));
    if (!valid) {
      return { expected: 'tampered' };
    }
  }
  return { expected: 'ok', did: parsed.did, publishedKeyIds: parsed.publishedKeyIds };
}

describe('composition contract vectors', () => {
  it('signs the card byte for byte', async () => {
    const signer = new LocalKeySigner(VECTORS.keys[VECTORS.sign.keyId].seedHex);
    const signed = await signAgentCard(VECTORS.sign.card, signer, VECTORS.sign.keyId);
    expect(JSON.stringify(signed)).toBe(JSON.stringify(VECTORS.sign.signedCard));
  });

  it.each(VECTORS.cards.map((vector) => [vector.name, vector] as const))('card: %s', (_name, vector) => {
    const { name: _ignored, card, ...expected } = vector;
    expect(cardOutcome(card)).toEqual(expected);
  });

  it.each(VECTORS.payloads.map((vector) => [vector.name, vector] as const))('payload: %s', (_name, vector) => {
    expect(agentCardSigningPayload(vector.card)).toBe(vector.payload);
  });

  it.each(VECTORS.documents.map((vector) => [vector.name, vector] as const))('document: %s', (_name, vector) => {
    expect(agentDidDocumentProblem(vector.document) === undefined).toBe(vector.valid);
  });

  it.each(VECTORS.reasons.map((vector) => [vector.name, vector] as const))('reason: %s', (_name, vector) => {
    expect(agentDidDocumentProblem(vector.document)).toBeUndefined();
    expect(compositionReasonForKey(vector.document, vector.keyId)).toBe(vector.expected);
  });
});
