const {
  AgentIdentity,
  InMemoryAgentRegistry
} = require('../dist/index.js');

const did = 'did:wba:agents.example:profiles:weather-bot';
const expectedUrl = 'https://agents.example/profiles/weather-bot/did.json';

const didDocument = {
  '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
  id: did,
  controller: 'did:web:agents.example',
  created: '2026-03-22T00:00:00Z',
  updated: '2026-03-22T00:00:00Z',
  agentMetadata: {
    name: 'WeatherBot',
    description: 'Minimal did:wba example',
    version: '1.0.0',
    coreModelHash: 'hash://sha256/weather-model',
    systemPromptHash: 'hash://sha256/weather-prompt'
  },
  verificationMethod: [
    {
      id: `${did}#key-1`,
      type: 'Ed25519VerificationKey2020',
      controller: 'did:web:agents.example',
      publicKeyMultibase: 'z6MkexampleWeatherBotKey'
    }
  ],
  authentication: [`${did}#key-1`]
};

async function main() {
  AgentIdentity.setRegistry(new InMemoryAgentRegistry());

  AgentIdentity.useProductionResolverFromHttp({
    registry: new InMemoryAgentRegistry(),
    fetchFn: async (url) => {
      if (url !== expectedUrl) {
        return {
          ok: false,
          status: 404,
          json: async () => ({})
        };
      }

      return {
        ok: true,
        status: 200,
        json: async () => didDocument
      };
    },
    onResolutionEvent: (event) => {
      console.log(`[resolver:${event.stage}]`, event.message || '');
    }
  });

  const resolved = await AgentIdentity.resolve(did);

  console.log('Resolved DID:', resolved.id);
  console.log('Resolved from:', expectedUrl);
  console.log('Agent name:', resolved.agentMetadata.name);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});