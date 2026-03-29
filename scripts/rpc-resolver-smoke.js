const path = require('node:path');
const { SDK_DIST, createJsonRpcServer } = require('./smoke-utils');

async function main() {
  let sdk;
  try {
    sdk = require(SDK_DIST);
  } catch {
    throw new Error('SDK build not found. Run `npm --prefix sdk run build` before smoke:rpc.');
  }

  const {
    AgentIdentity,
    InMemoryAgentRegistry,
    InMemoryDIDResolver
  } = sdk;

  const did = 'did:agent:polygon:0xrpcsmoke';
  const documentRef = 'hash://sha256/rpc-smoke-doc';
  const sampleDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: did,
    controller: 'did:ethr:0xcontroller',
    created: '2026-01-01T00:00:00.000Z',
    updated: '2026-01-01T00:00:00.000Z',
    agentMetadata: {
      name: 'RpcSmokeBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: 'did:ethr:0xcontroller',
        publicKeyMultibase: 'zabc'
      }
    ],
    authentication: [`${did}#key-1`]
  };

  const failingServer = createJsonRpcServer(async (payload) => ({
    httpStatus: 503,
    payload: {
      jsonrpc: '2.0',
      id: payload.id ?? null,
      error: { code: -32000, message: 'temporary unavailable' }
    }
  }));

  const healthyServer = createJsonRpcServer(async (payload) => {
    const params = Array.isArray(payload.params) ? payload.params : [];
    const requestedRef = params[0];

    if (payload.method !== 'agent_resolveDocumentRef') {
      return {
        payload: {
          jsonrpc: '2.0',
          id: payload.id ?? null,
          error: { code: -32601, message: 'method not found' }
        }
      };
    }

    if (requestedRef !== documentRef) {
      return {
        payload: {
          jsonrpc: '2.0',
          id: payload.id ?? null,
          error: { code: -32004, message: 'document not found' }
        }
      };
    }

    return {
      payload: {
        jsonrpc: '2.0',
        id: payload.id ?? null,
        result: sampleDocument
      }
    };
  });

  const failingPort = await failingServer.start();
  const healthyPort = await healthyServer.start();

  try {
    const registry = new InMemoryAgentRegistry();
    await registry.register(did, sampleDocument.controller, documentRef);

    AgentIdentity.setRegistry(registry);
    AgentIdentity.setResolver(new InMemoryDIDResolver());

    const events = [];
    AgentIdentity.useProductionResolverFromJsonRpc({
      registry,
      endpoints: [
        `http://127.0.0.1:${failingPort}`,
        `http://127.0.0.1:${healthyPort}`
      ],
      onResolutionEvent: (event) => events.push(event.stage),
      httpSecurity: { allowPrivateTargets: true }
    });

    const resolved = await AgentIdentity.resolve(did);

    if (resolved.id !== did) {
      throw new Error(`Resolved DID mismatch. Expected ${did}, got ${resolved.id}`);
    }

    if (!events.includes('source-fetch') || !events.includes('resolved')) {
      throw new Error(`Expected resolver events not emitted. Events: ${events.join(', ')}`);
    }

    console.log('✅ RPC resolver smoke test completed successfully');
  } finally {
    await Promise.all([failingServer.stop(), healthyServer.stop()]);
  }
}

main().catch((error) => {
  console.error('❌ RPC resolver smoke test failed');
  console.error(error);
  process.exit(1);
});
