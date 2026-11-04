#!/usr/bin/env node
/**
 * TypeScript half of the live cross-SDK round trip (M-13).
 *
 *   node scripts/cross-sdk/ts-roundtrip.js emit   > bundle.json   # fresh identity, signs with the TS SDK
 *   node scripts/cross-sdk/ts-roundtrip.js verify < bundle.json   # verifies a bundle produced by the Python SDK
 *
 * Needs `npm --prefix sdk run build` first. Exit code 0 means every check passed.
 */
const fs = require('fs');
const path = require('path');

const sdk = require(path.join(__dirname, '..', '..', 'sdk', 'dist'));

const MESSAGE = 'cross-sdk-roundtrip:v1';
const URL_ = 'https://api.example.com/v1/roundtrip?mode=live';
const BODY = '{"roundtrip":true}';

async function emit() {
  const [controllerSigner] = sdk.LocalKeySigner.generate();
  const client = new sdk.AgentDidClient();
  const identity = new sdk.AgentIdentity({ client, controllerSigner });
  const { document, agentPrivateKey } = await identity.create({
    name: 'CrossSdkTs',
    coreModel: 'roundtrip-model',
    systemPrompt: 'roundtrip-prompt'
  });
  const signatureHex = await identity.signMessage(MESSAGE, agentPrivateKey);
  const headers = await identity.signHttpRequest({
    method: 'POST',
    url: URL_,
    body: BODY,
    agentPrivateKey,
    agentDid: document.id
  });
  const controllerChain = await client.resolveControllerChain(document.id);
  process.stdout.write(JSON.stringify({
    producer: 'typescript',
    document,
    controllerDocuments: controllerChain.filter((d) => d.id !== document.id),
    keyId: document.verificationMethod[0].id,
    message: { payload: MESSAGE, signatureHex },
    http: { method: 'POST', url: URL_, body: BODY, headers }
  }, null, 2));
}

async function verify() {
  const bundle = JSON.parse(fs.readFileSync(0, 'utf8'));
  const resolver = new sdk.InMemoryDIDResolver();
  for (const doc of [bundle.document, ...bundle.controllerDocuments]) resolver.registerDocument(doc);
  const registry = new sdk.InMemoryAgentRegistry();
  await registry.register(bundle.document.id, bundle.document.controller, 'hash://sha256/roundtrip');
  const client = new sdk.AgentDidClient({ resolver, registry });

  const results = {
    message: await client.verifySignature(bundle.document.id, bundle.message.payload, bundle.message.signatureHex, bundle.keyId),
    http: await client.verifyHttpRequestSignature({ ...bundle.http, nonceStore: new sdk.InMemoryNonceStore() }),
    tamperedMessage: await client.verifySignature(bundle.document.id, bundle.message.payload + 'x', bundle.message.signatureHex, bundle.keyId),
    tamperedHttp: await client.verifyHttpRequestSignature({ ...bundle.http, body: bundle.http.body + ' ', nonceStore: new sdk.InMemoryNonceStore() })
  };
  const ok = results.message && results.http && !results.tamperedMessage && !results.tamperedHttp;
  console.error(`typescript verify of ${bundle.producer} bundle: ${JSON.stringify(results)}`);
  process.exit(ok ? 0 : 1);
}

const mode = process.argv[2];
(mode === 'emit' ? emit() : mode === 'verify' ? verify() : Promise.reject(new Error('usage: emit|verify')))
  .catch((err) => { console.error(err); process.exit(1); });
