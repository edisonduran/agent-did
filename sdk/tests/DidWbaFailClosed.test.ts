import { DocumentIntegrityError, InMemoryAgentRegistry, InMemoryDIDResolver, UniversalResolverClient } from '../src';
import { AgentDIDDocument } from '../src/core/types';

// Parity: sdk-python/tests/test_did_wba_fail_closed.py
const DID = 'did:wba:agents.example.com:bot';
const document = (id: string) =>
  ({
    '@context': ['https://www.w3.org/ns/did/v1'],
    id,
    controller: id,
    created: '2026-01-01T00:00:00Z',
    updated: '2026-01-01T00:00:00Z',
    agentMetadata: { name: 'bot', version: '1', coreModelHash: 'h', systemPromptHash: 'h' },
    verificationMethod: [],
    authentication: []
  }) as AgentDIDDocument;

function resolverWith(getByReference: () => Promise<AgentDIDDocument | null>) {
  const fallback = new InMemoryDIDResolver();
  fallback.registerDocument(document(DID));
  return new UniversalResolverClient({
    registry: new InMemoryAgentRegistry(),
    documentSource: { getByReference: async () => null },
    wbaDocumentSource: { getByReference },
    fallbackResolver: fallback
  });
}

describe('did:wba resolution fails closed', () => {
  it('does not answer from the fallback resolver when the host cannot be reached or has no document', async () => {
    await expect(resolverWith(async () => { throw new Error('ECONNREFUSED'); }).resolve(DID)).rejects.toThrow(
      /could not be fetched/u
    );
    await expect(resolverWith(async () => null).resolve(DID)).rejects.toThrow(/not found/u);
  });

  it('reports a document for another DID as an integrity failure', async () => {
    await expect(resolverWith(async () => document('did:wba:evil.example:bot')).resolve(DID)).rejects.toBeInstanceOf(
      DocumentIntegrityError
    );
  });
});
