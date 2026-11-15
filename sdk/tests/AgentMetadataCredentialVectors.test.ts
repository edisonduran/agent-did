/**
 * Shared AgentMetadataCredential vectors (fixtures/agent-metadata-credential-vectors.json, RFC-001 §4.4). Python
 * parity: sdk-python/tests/test_agent_metadata_credential_vectors.py.
 */
import fs from 'fs';
import path from 'path';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { LocalKeySigner } from '../src';
import {
  buildUnsignedAgentMetadataCredential,
  checkAgentMetadataCredentialForm
} from '../src/core/agent-metadata-credential';
import { createEddsaJcs2022Proof, eddsaJcs2022HashData, verifyEddsaJcs2022Proof } from '../src/crypto/data-integrity';
import { decodePublicKeyMultibase } from '../src/crypto/multibase';
import { parseRfc3339Millis } from '../src/verification/key-at-time';

interface Mutation {
  op: 'set' | 'delete';
  path: string[];
  value?: unknown;
}

interface Case {
  name: string;
  now?: string;
  replace?: unknown;
  mutations: Mutation[];
  expected: string;
}

const VECTORS = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'agent-metadata-credential-vectors.json'), 'utf8')
) as {
  seedHex: string;
  publicKeyMultibase: string;
  now: string;
  issue: Record<string, any>;
  hashDataHex: string;
  credential: Record<string, any>;
  cases: Case[];
};

function mutate(credential: Record<string, any>, mutation: Mutation): void {
  let target = credential;
  for (const part of mutation.path.slice(0, -1)) {
    target = target[part];
  }
  const last = mutation.path[mutation.path.length - 1];
  if (mutation.op === 'delete') {
    delete target[last];
  } else {
    target[last] = mutation.value === '$proofSet' ? [credential.proof] : mutation.value;
  }
}

function outcome(testCase: Case): string {
  let credential: unknown;
  if (testCase.replace !== undefined) {
    credential = testCase.replace;
  } else {
    const copy = JSON.parse(JSON.stringify(VECTORS.credential));
    testCase.mutations.forEach((mutation) => mutate(copy, mutation));
    credential = copy;
  }
  const form = checkAgentMetadataCredentialForm(credential, parseRfc3339Millis(testCase.now ?? VECTORS.now) as number);
  if (!form.ok) {
    return form.reason;
  }
  return verifyEddsaJcs2022Proof(credential, decodePublicKeyMultibase(VECTORS.publicKeyMultibase))
    ? 'ok'
    : 'signature_invalid';
}

describe('AgentMetadataCredential vectors', () => {
  it('builds and signs the credential byte for byte', async () => {
    const issue = VECTORS.issue;
    const signer = new LocalKeySigner(VECTORS.seedHex);
    const unsigned = buildUnsignedAgentMetadataCredential({
      issuer: issue.issuer,
      agentDid: issue.agentDid,
      agentMetadata: issue.agentMetadata,
      validFrom: issue.validFrom,
      validUntil: issue.validUntil,
      id: issue.id
    });
    const proof = await createEddsaJcs2022Proof(
      unsigned,
      { created: issue.created, verificationMethod: issue.verificationMethod, proofPurpose: 'assertionMethod' },
      async (hashData) => hexToBytes(await signer.sign(hashData))
    );
    const { proof: expectedProof, ...expectedUnsigned } = VECTORS.credential;
    const { proofValue: _value, ...config } = expectedProof;
    expect(bytesToHex(eddsaJcs2022HashData(unsigned, config))).toBe(VECTORS.hashDataHex);
    expect(JSON.stringify({ ...unsigned, proof })).toBe(JSON.stringify(VECTORS.credential));
    expect(expectedUnsigned).toEqual(unsigned);
  });

  it.each(VECTORS.cases.map((testCase) => [testCase.name, testCase] as const))('%s', (_name, testCase) => {
    expect(outcome(testCase)).toBe(testCase.expected);
  });
});
