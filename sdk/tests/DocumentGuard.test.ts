import { LocalKeySigner } from '../src/core/signer';
import { AgentDidClient } from '../src';
import { agentDidDocumentProblem } from '../src/core/document-guard';
import { createDidWebvhLog, updateDidWebvhLog } from '../src/webvh/adapter';

// Parity: Python validates the same documents with the AgentDIDDocument model (test_document_guard.py)
const valid = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: 'did:example:a',
  controller: 'did:example:c',
  created: '2026-01-01T00:00:00Z',
  updated: '2026-01-01T00:00:00Z',
  agentMetadata: { name: 'a', version: '1', coreModelHash: 'h', systemPromptHash: 'h' },
  verificationMethod: [{ id: 'did:example:a#key-1', type: 'Multikey', controller: 'did:example:c', publicKeyMultibase: 'z' }],
  authentication: ['did:example:a#key-1']
};

describe('runtime check of external Agent-DID documents', () => {
  it('accepts a document with the required members and optional ones set to null', () => {
    expect(agentDidDocumentProblem(valid)).toBeUndefined();
    expect(agentDidDocumentProblem({ ...valid, assertionMethod: null, complianceCertifications: null })).toBeUndefined();
  });

  it.each([
    ['not an object', []],
    ['no agentMetadata', { ...valid, agentMetadata: undefined }],
    ['a verification method without id', { ...valid, verificationMethod: [{ type: 'Multikey', controller: 'c' }] }],
    ['authentication that is not a list', { ...valid, authentication: 'did:example:a#key-1' }],
    ['a numeric id', { ...valid, id: 7 }]
  ])('rejects %s', (_name, document) => {
    expect(agentDidDocumentProblem(document)).toEqual(expect.any(String));
  });

  it('refuses to import a did:webvh log whose state is not an Agent-DID document, with a clear error', async () => {
    const [signer] = LocalKeySigner.generate();
    const created = await createDidWebvhLog({
      domain: 'example.com',
      pathSegments: ['plain'],
      document: { '@context': ['https://www.w3.org/ns/did/v1'], id: '{DID}' } as never,
      signer
    });
    const updated = await updateDidWebvhLog({ log: created.log, signer, document: { ...(created.state as object) } as never });

    await expect(new AgentDidClient().importDidWebvhHistory(updated.log)).rejects.toThrow(/not an Agent-DID document/u);
  });
});
