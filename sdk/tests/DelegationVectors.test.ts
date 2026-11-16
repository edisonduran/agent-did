/**
 * Shared vectors of capabilities and OAuth client assertions (fixtures/delegation-vectors.json, RFC-001 §6.7, §6.8,
 * ADR-008 D-12f). Python parity: sdk-python/tests/test_delegation_vectors.py.
 */
import fs from 'fs';
import path from 'path';
import { createClientAssertion, LocalKeySigner, rootCapabilityId } from '../src';
import { didOfKeyId } from '../src/core/agent-card';
import { actionAllowed, checkCapabilityChain, parseCapabilityHeader, targetWithin } from '../src/core/capability';
import { buildSignatureBase, parseSignatureInputHeader } from '../src/core/http-signatures';
import { parseClientAssertion } from '../src/core/oauth-client';
import { AgentCapability, JwsEd25519Alg } from '../src/core/types';
import { bytesToBase64Url } from '../src/crypto/base64';
import { eddsaJcs2022HashData, verifyEddsaJcs2022Proof } from '../src/crypto/data-integrity';
import { verifyEd25519 } from '../src/crypto/ed25519-verify';
import { decodePublicKeyMultibase } from '../src/crypto/multibase';

type Json = Record<string, unknown>;
const VECTORS = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'delegation-vectors.json'), 'utf8')
) as {
  keys: Record<string, { seedHex: string; publicKeyMultibase: string }>;
  capabilities: {
    rootId: string;
    sign: Array<{ name: string; unsigned: Json; proofOptions: Json; keyId: string; proofValue: string }>;
    chains: Array<{
      name: string; capability: unknown; rootControllers: Record<string, string[]>; now: string; maxChainLength: number;
      expected: string; capabilityId?: string; delegators?: string[]; allowedAction?: string[]; controller?: string;
    }>;
    targets: Array<{ url: string; method: string; invocationTarget: string; allowedAction?: string[]; matches: boolean }>;
    headers: Array<{ name: string; value: string; expected: string; capability?: Json }>;
    invocation: { request: { method: string; url: string; headers: Record<string, string> }; keyId: string; capabilityId: string; signatureBase: string };
  };
  clientAssertions: {
    sign: Array<{ name: string; params: { clientId: string; issuer: string; verificationMethodId: string; issuedAt: number; jti: string; lifetimeSeconds: number; jwsAlg: JwsEd25519Alg }; assertion: string }>;
    verify: Array<{ name: string; assertion: string; clientId: string; issuer: string; did: string; now: number; maxClockSkewSeconds: number; expected: string }>;
  };
};

const publicKey = (keyId: string): Uint8Array | undefined => {
  const key = VECTORS.keys[keyId];
  return key === undefined ? undefined : decodePublicKeyMultibase(key.publicKeyMultibase);
};

/** checkCapabilityChain, then per link the delegator check and the proof with the key of its verificationMethod. */
function chainOutcome(vector: (typeof VECTORS.capabilities.chains)[number]): Json {
  const checked = checkCapabilityChain(vector.capability, vector.rootControllers, Date.parse(vector.now), vector.maxChainLength);
  if (!checked.ok) {
    return { expected: checked.reason, ...(checked.capabilityId !== undefined ? { capabilityId: checked.capabilityId } : {}) };
  }
  const { capabilities, rootControllers } = checked.value;
  const delegators: string[] = [];
  for (const [index, item] of capabilities.entries()) {
    const delegator = didOfKeyId(item.proof.verificationMethod) as string;
    const allowed = index === 0 ? rootControllers.includes(delegator) : capabilities[index - 1].controller === delegator;
    if (!allowed) return { expected: 'delegator_mismatch', capabilityId: item.id };
    const key = publicKey(item.proof.verificationMethod);
    if (key === undefined || !verifyEddsaJcs2022Proof(item, key)) return { expected: 'signature_invalid', capabilityId: item.id };
    delegators.push(delegator);
  }
  const leaf = capabilities[capabilities.length - 1];
  return {
    expected: 'ok',
    delegators,
    ...(checked.value.allowedAction !== undefined ? { allowedAction: checked.value.allowedAction } : {}),
    controller: leaf.controller
  };
}

describe('delegation vectors: capabilities', () => {
  it('derives the root id', () => {
    expect(rootCapabilityId('https://api.example.com/files')).toBe(VECTORS.capabilities.rootId);
  });

  it.each(VECTORS.capabilities.sign.map((vector) => [vector.name, vector] as const))('signs %s byte for byte', async (_name, vector) => {
    const signer = new LocalKeySigner(VECTORS.keys[vector.keyId].seedHex);
    const signature = Buffer.from(await signer.sign(eddsaJcs2022HashData(vector.unsigned, vector.proofOptions)), 'hex');
    const signed = { ...vector.unsigned, proof: { ...vector.proofOptions, proofValue: vector.proofValue } };
    expect(verifyEddsaJcs2022Proof(signed, publicKey(vector.keyId) as Uint8Array)).toBe(true);
    const { encodeEddsaProofValue } = await import('../src/crypto/data-integrity');
    expect(encodeEddsaProofValue(signature)).toBe(vector.proofValue);
  });

  it.each(VECTORS.capabilities.chains.map((vector) => [vector.name, vector] as const))('chain: %s', (_name, vector) => {
    const { name: _n, capability: _c, rootControllers: _r, now: _t, maxChainLength: _m, ...expected } = vector;
    expect(chainOutcome(vector)).toEqual(expected);
  });

  it.each(VECTORS.capabilities.targets.map((vector) => [`${vector.method} ${vector.url} in ${vector.invocationTarget}`, vector] as const))(
    'target: %s',
    (_name, vector) => {
      const matches = targetWithin(vector.url.split('?')[0], vector.invocationTarget) && actionAllowed(vector.method, vector.allowedAction);
      expect(matches).toBe(vector.matches);
    }
  );

  it.each(VECTORS.capabilities.headers.map((vector) => [vector.name, vector] as const))('header: %s', (_name, vector) => {
    const parsed = parseCapabilityHeader(vector.value, 'sig1');
    if (vector.expected === 'capability') {
      expect(parsed).toEqual(vector.capability);
    } else {
      expect(parsed === 'missing' ? 'missing' : parsed === undefined ? 'malformed' : 'capability').toBe(vector.expected);
    }
  });

  it('rebuilds the signature base of an invocation and verifies it', () => {
    const { request, keyId, capabilityId, signatureBase } = VECTORS.capabilities.invocation;
    const headers = Object.fromEntries(Object.entries(request.headers).map(([key, value]) => [key.toLowerCase(), value]));
    const input = parseSignatureInputHeader(headers['signature-input']).get('sig1');
    expect(input).toBeDefined();
    expect(buildSignatureBase({ method: request.method, url: request.url, headers }, input!)).toBe(signatureBase);
    const signature = new Uint8Array(Buffer.from(headers.signature.slice('sig1=:'.length, -1), 'base64'));
    expect(verifyEd25519(signature, new TextEncoder().encode(signatureBase), publicKey(keyId) as Uint8Array)).toBe(true);
    const capability = parseCapabilityHeader(headers['agent-did-capability'], 'sig1') as AgentCapability;
    expect(capability.id).toBe(capabilityId);
  });
});

describe('delegation vectors: client assertions', () => {
  it.each(VECTORS.clientAssertions.sign.map((vector) => [vector.name, vector] as const))('signs %s byte for byte', async (_name, vector) => {
    const signer = new LocalKeySigner(VECTORS.keys[vector.params.verificationMethodId].seedHex);
    expect(await createClientAssertion({ ...vector.params, signer })).toBe(vector.assertion);
  });

  it.each(VECTORS.clientAssertions.verify.map((vector) => [vector.name, vector] as const))('verify: %s', (_name, vector) => {
    const parsed = parseClientAssertion(vector.assertion, {
      clientId: vector.clientId,
      issuer: vector.issuer,
      did: vector.did,
      nowSeconds: vector.now,
      maxClockSkewSeconds: vector.maxClockSkewSeconds
    });
    let outcome: string;
    if (!parsed.ok) {
      outcome = parsed.reason;
    } else {
      const key = publicKey(parsed.value.keyId);
      const valid = key !== undefined && verifyEd25519(parsed.value.signature, new TextEncoder().encode(parsed.value.signingInput), key);
      outcome = valid ? 'ok' : 'signature_invalid';
    }
    expect(outcome).toBe(vector.expected);
  });

  it('keeps base64url helpers consistent', () => {
    expect(bytesToBase64Url(new Uint8Array([251, 255]))).toBe('-_8');
  });
});
