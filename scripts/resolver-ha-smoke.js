const path = require('node:path');
const { SDK_DIST } = require('./smoke-utils');

async function main() {
  let sdk;
  try {
    sdk = require(SDK_DIST);
  } catch {
    throw new Error('SDK dist no encontrado. Ejecuta `npm --prefix sdk run build`.');
  }

  const { AgentIdentity, InMemoryAgentRegistry, InMemoryDIDResolver } = sdk;

  const did = 'did:webvh:QmHaDrillScid:agents.example:profiles:ha-bot';
  const document = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: did,
    controller: 'did:webvh:QmHaControllerScid:agents.example:organizations:ops-root',
    created: '2026-01-01T00:00:00.000Z',
    updated: '2026-01-01T00:00:00.000Z',
    agentMetadata: {
      name: 'HaDrillBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: 'zabc'
      }
    ],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`]
  };
  const didLog = [
    JSON.stringify({ versionId: '1-QmHaDrillScid', state: { ...document, updated: '2025-12-31T00:00:00.000Z' } }),
    JSON.stringify({ versionId: '2-QmHaDrillScid', state: document })
  ].join('\n');
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
