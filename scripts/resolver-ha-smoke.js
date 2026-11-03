const path = require('node:path');
const { SDK_DIST } = require('./smoke-utils');

async function main() {
  let sdk;
  try {
    sdk = require(SDK_DIST);
  } catch {
    throw new Error('SDK dist no encontrado. Ejecuta `npm --prefix sdk run build`.');
  }

  const { AgentIdentity, InMemoryAgentRegistry, InMemoryDIDResolver, LocalKeySigner } = sdk;
  const { createDidWebvhLog, updateDidWebvhLog } = require(path.join(SDK_DIST, 'webvh', 'adapter.js'));

  // A controller-signed did:webvh v1.0 log with two versions, served by the third endpoint.
  const controllerSigner = new LocalKeySigner('4d'.repeat(32));
  const created = await createDidWebvhLog({
    domain: 'agents.example',
    pathSegments: ['profiles', 'ha-bot'],
    signer: controllerSigner,
    created: '2026-01-01T00:00:00Z',
    document: {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
      id: '{DID}',
      controller: '{DID}',
      created: '2026-01-01T00:00:00Z',
      updated: '2026-01-01T00:00:00Z',
      agentMetadata: {
        name: 'HaDrillBot',
        version: '1.0.0',
        coreModelHash: 'hash://hmac-sha256/model',
        systemPromptHash: 'hash://hmac-sha256/prompt'
      },
      verificationMethod: [{
        id: '{DID}#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: '{DID}',
        publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      }],
      authentication: ['{DID}#key-1'],
      assertionMethod: ['{DID}#key-1']
    }
  });
  const { log: didLog } = await updateDidWebvhLog({
    log: created.log,
    signer: controllerSigner,
    document: { ...created.state, updated: '2026-01-02T00:00:00Z' },
    updated: '2026-01-02T00:00:00Z'
  });
  const did = created.did;
  const attemptedUrls = [];
  const candidateUrls = [
    'https://resolver-primary.example/profiles/ha-bot/did.jsonl',
    'https://resolver-secondary.example/profiles/ha-bot/did.jsonl',
    'https://resolver-tertiary.example/profiles/ha-bot/did.jsonl'
  ];

  const fetchFn = async (url) => {
    attemptedUrls.push(url);

    if (url === candidateUrls[0]) {
      return { ok: false, status: 503, json: async () => ({}), text: async () => '' };
    }

    if (url === candidateUrls[1]) {
      return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
    }

    if (url === candidateUrls[2]) {
      return { ok: true, status: 200, json: async () => ({}), text: async () => didLog };
    }

    throw new Error(`Unexpected HA drill URL: ${url}`);
  };

  const registry = new InMemoryAgentRegistry();

  AgentIdentity.setRegistry(registry);
  AgentIdentity.setResolver(new InMemoryDIDResolver());

  const events = [];
  AgentIdentity.useProductionResolverFromHttp({
    registry,
    cacheTtlMs: 60_000,
    referenceToUrls: () => candidateUrls,
    fetchFn,
    onResolutionEvent: (event) => events.push(event.stage)
  });

  const first = await AgentIdentity.resolve(did);
  const second = await AgentIdentity.resolve(did);

  if (first.id !== did || second.id !== did) {
    throw new Error('Resolución DID fallida durante drill HA');
  }

  const requiredStages = ['cache-miss', 'source-fetch', 'source-fetched', 'resolved', 'cache-hit'];
  for (const stage of requiredStages) {
    if (!events.includes(stage)) {
      throw new Error(`Evento requerido ausente en drill HA: ${stage}`);
    }
  }

  if (attemptedUrls.length !== candidateUrls.length || attemptedUrls.some((url, index) => url !== candidateUrls[index])) {
    throw new Error(`Failover did:webvh no recorrió los candidate URLs esperados: ${attemptedUrls.join(', ')}`);
  }

  console.log('✅ HA resolver drill completed successfully');
}

main().catch((error) => {
  console.error('❌ HA resolver drill failed');
  console.error(error);
  process.exit(1);
});
