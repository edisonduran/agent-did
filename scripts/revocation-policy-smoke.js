/**
 * Revocation policy smoke on the canonical did:webvh path (RFC-001 §6.6): only the controller's update key can
 * revoke or change a DID; a third party's key cannot, and neither can a registry record on its own. After a
 * controller-signed deactivation, no further change is accepted.
 *
 * Python parity: sdk-python/scripts/revocation_policy_smoke.py. Usage: npm --prefix sdk run build && npm run smoke:policy
 */
const assert = require('node:assert/strict');
const { SDK_DIST } = require('./smoke-utils');

async function expectRejected(action, label) {
  let rejected = false;
  try {
    await action();
  } catch {
    rejected = true;
  }
  assert.ok(rejected, `${label} must be rejected`);
}

async function main() {
  let sdk;
  try {
    sdk = require(SDK_DIST);
  } catch {
    throw new Error('SDK dist not found. Run `npm --prefix sdk run build` first.');
  }
  const { AgentDidClient, AgentIdentity, InMemoryAgentRegistry, LocalKeySigner } = sdk;

  const registry = new InMemoryAgentRegistry();
  const client = new AgentDidClient({ registry });
  const [creator] = LocalKeySigner.generate();
  const [attacker] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner: creator, client });

  const { document, agentPrivateKey } = await identity.create({
    name: 'PolicySmokeBot',
    coreModel: 'gpt-4o-mini',
    systemPrompt: 'You are a revocation policy smoke test.'
  });
  const did = document.id;
  const payload = 'policy-smoke';
  const signature = await identity.signMessage(payload, agentPrivateKey);
  const stillValid = async () => assert.equal(await client.verifySignature(did, payload, signature), true, 'DID must stay active');

  console.log('[smoke] A third party cannot revoke, rotate or update the DID...');
  await expectRejected(() => client.revokeDid(did, { controllerSigner: attacker }), 'revocation by a third-party key');
  await expectRejected(
    () => client.rotateVerificationMethod(did, { controllerSigner: attacker }),
    'key rotation by a third-party key'
  );
  await expectRejected(
    () => client.updateDidDocument(did, { description: 'hijacked' }, { controllerSigner: attacker }),
    'update by a third-party key'
  );
  await stillValid();

  console.log('[smoke] A registry record alone does not revoke a did:webvh DID...');
  await registry.revoke(did);
  await stillValid();

  console.log('[smoke] The controller revokes; nothing changes the DID afterwards...');
  await client.revokeDid(did);
  assert.equal(await client.verifySignature(did, payload, signature), false, 'DID must be revoked by its controller');
  await expectRejected(() => client.rotateVerificationMethod(did), 'key rotation after deactivation');
  await expectRejected(() => client.updateDidDocument(did, { description: 'revived' }), 'update after deactivation');

  console.log('✅ Revocation policy smoke completed successfully');
}

main().catch((error) => {
  console.error('❌ Revocation policy smoke failed');
  console.error(error);
  process.exit(1);
});
