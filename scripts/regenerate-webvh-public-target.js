#!/usr/bin/env node
/**
 * Regenerates the repo-managed public did:webvh smoke target
 * (fixtures/external-smoke/webvh-public-targets/support-bot/did.jsonl) as a
 * did:webvh v1.0 log and updates the DID in webvh-public-targets.json.
 *
 * The controller key is generated at random and discarded: the published log
 * is never updated in place, it is regenerated (with a new SCID) instead.
 *
 * Usage: npm --prefix sdk run build && node scripts/regenerate-webvh-public-target.js
 */
const fs = require('node:fs');
const path = require('node:path');
const { SDK_DIST } = require('./smoke-utils');

const ROOT = path.resolve(__dirname, '..');
const MANIFEST_PATH = path.join(ROOT, 'fixtures', 'external-smoke', 'webvh-public-targets.json');
const TARGET = 'repo-main-support-bot';
const LOG_PATH = path.join(ROOT, 'fixtures', 'external-smoke', 'webvh-public-targets', 'support-bot', 'did.jsonl');
const DOMAIN = 'raw.githubusercontent.com';
const PATH_SEGMENTS = ['edisonduran', 'agent-did', 'main', 'fixtures', 'external-smoke', 'webvh-public-targets', 'support-bot'];

async function main() {
  const { LocalKeySigner } = require(SDK_DIST);
  const { createDidWebvhLog, deriveDidWebvhLogUrl } = require(path.join(SDK_DIST, 'webvh', 'adapter.js'));

  const [controllerSigner] = LocalKeySigner.generate();
  const [agentSigner] = LocalKeySigner.generate();
  const agentKey = require(path.join(SDK_DIST, 'crypto', 'multibase.js')).encodePublicKeyMultibase(
    await agentSigner.getPublicKey()
  );
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z');

  const created = await createDidWebvhLog({
    domain: DOMAIN,
    pathSegments: PATH_SEGMENTS,
    signer: controllerSigner,
    document: {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
      id: '{DID}',
      controller: '{DID}',
      created: timestamp,
      updated: timestamp,
      agentMetadata: {
        name: 'Repo Public Support Bot',
        description: 'Repo-managed public did:webvh v1.0 smoke target served from GitHub main.',
        version: '1.0.0',
        coreModelHash: 'hash://hmac-sha256/0000000000000000000000000000000000000000000000000000000000000000',
        systemPromptHash: 'hash://hmac-sha256/0000000000000000000000000000000000000000000000000000000000000000',
        capabilities: ['read:public-smoke']
      },
      verificationMethod: [{
        id: '{DID}#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: '{DID}',
        publicKeyMultibase: agentKey
      }],
      authentication: ['{DID}#key-1'],
      assertionMethod: ['{DID}#key-1']
    }
  });

  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
  const target = manifest.targets[TARGET];
  if (deriveDidWebvhLogUrl(created.did) !== target.candidateUrls[0]) {
    throw new Error(`DID maps to ${deriveDidWebvhLogUrl(created.did)}, expected ${target.candidateUrls[0]}`);
  }
  target.did = created.did;

  fs.writeFileSync(LOG_PATH, created.log, 'utf8');
  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log(`Regenerated ${TARGET}: ${created.did}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
