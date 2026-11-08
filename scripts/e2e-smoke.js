/**
 * End-to-end smoke on the canonical did:webvh path (RFC-001 MUST-09): create an agent, sign, verify, revoke with
 * a controller-signed deactivation entry, and check that the signature no longer verifies, both in the client
 * that revoked and in a fresh verifier that only has the published logs (agent and controller).
 *
 * Python parity: sdk-python/scripts/e2e_smoke.py. Usage: npm --prefix sdk run build && npm run smoke:e2e
 */
const assert = require('node:assert/strict');
const { SDK_DIST } = require('./smoke-utils');

async function main() {
  let sdk;
  try {
    sdk = require(SDK_DIST);
  } catch {
    throw new Error('SDK dist not found. Run `npm --prefix sdk run build` first.');
  }
  const { AgentDidClient, AgentIdentity, LocalKeySigner } = sdk;
  const { resolveDidWebvhLog } = require(require('node:path').join(SDK_DIST, 'webvh', 'adapter.js'));

  const client = new AgentDidClient();
  const [creator] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner: creator, client });

  console.log('[smoke] Creating a did:webvh agent...');
  const { document, agentPrivateKey } = await identity.create({
    name: 'E2ESmokeBot',
    coreModel: 'gpt-4o-mini',
    systemPrompt: 'You are an end-to-end smoke test.'
  });
  const did = document.id;
  assert.ok(did.startsWith('did:webvh:'), `expected a did:webvh DID, got ${did}`);

  console.log('[smoke] Signing and verifying a payload...');
  const payload = JSON.stringify({ action: 'transfer', amount: 10 });
  const signature = await identity.signMessage(payload, agentPrivateKey);
  assert.equal(await client.verifySignature(did, payload, signature), true, 'signature must verify before revocation');
  assert.equal(await client.verifySignature(did, `${payload} `, signature), false, 'a tampered payload must not verify');

  // A verifier resolves the whole controller chain, so it needs the controller's published log too.
  console.log('[smoke] Verifying from the published logs only...');
  const controllerLog = client.exportDidWebvhHistory(document.controller);
  const publishedBefore = client.exportDidWebvhHistory(did);
  const verifierBefore = new AgentDidClient();
  await verifierBefore.importDidWebvhHistory(controllerLog);
  await verifierBefore.importDidWebvhHistory(publishedBefore);
  assert.equal(await verifierBefore.verifySignature(did, payload, signature), true, 'a fresh verifier must accept it');

  console.log('[smoke] Revoking with a controller-signed deactivation entry...');
  await client.revokeDid(did);
  const publishedAfter = client.exportDidWebvhHistory(did);
  const resolved = await resolveDidWebvhLog(publishedAfter, { did });
  assert.equal(resolved.metadata.deactivated, true, 'the log must end in a deactivation entry');
  assert.equal(await client.verifySignature(did, payload, signature), false, 'signature must not verify after revocation');

  const verifierAfter = new AgentDidClient();
  await verifierAfter.importDidWebvhHistory(controllerLog);
  await verifierAfter.importDidWebvhHistory(publishedAfter);
  assert.equal(
    await verifierAfter.verifySignature(did, payload, signature),
    false,
    'a fresh verifier with the published log must reject it'
  );

  console.log('\n✅ E2E smoke test completed successfully');
}

main().catch((error) => {
  console.error('\n❌ E2E smoke test failed');
  console.error(error);
  process.exit(1);
});
