#!/usr/bin/env node
/**
 * Checks the `exports` map of @agentdid/sdk against the build in `dist/` (run `npm run build` first):
 * - `import` and `require` of the package name resolve to the same objects (one copy: classes keep `instanceof` and the
 *   default in-memory `NonceStore` is one store);
 * - every export of the CommonJS build is a named export of the ES module;
 * - an ES module consumer can create an agent, sign and verify with it.
 *
 * The package directory is linked as `node_modules/@agentdid/sdk` of a temporary project, so resolution goes through the
 * `exports` map exactly like an installed package.
 */
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const sdkDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const project = mkdtempSync(join(tmpdir(), 'agentdid-esm-check-'));

const CHECK = `import * as sdk from '@agentdid/sdk';
import { createRequire } from 'node:module';

const cjs = createRequire(import.meta.url)('@agentdid/sdk');
const problems = [];
for (const name of Object.keys(cjs).filter((n) => n !== 'default' && n !== '__esModule')) {
  if (!(name in sdk)) problems.push('missing named export ' + name);
  else if (sdk[name] !== cjs[name]) problems.push('different object for ' + name);
}
if (sdk.default !== cjs) problems.push('default export is not the CommonJS module');

const client = new sdk.AgentDidClient();
const [wallet] = sdk.LocalKeySigner.generate();
const identity = new sdk.AgentIdentity({ controllerSigner: wallet, client });
const { document, agentPrivateKey } = await identity.create({ name: 'EsmBot', coreModel: 'm', systemPrompt: 'p' });
const signature = await identity.signMessage('hello', agentPrivateKey);
if (!(await client.verifySignature(document.id, 'hello', signature))) problems.push('verifySignature failed from ESM');
if (!(client instanceof cjs.AgentDidClient)) problems.push('instanceof across import and require failed');

if (problems.length > 0) {
  console.error(problems.join('\\n'));
  process.exit(1);
}
console.log('ESM wrapper OK: ' + Object.keys(cjs).length + ' exports, one copy of the package');
`;

try {
  const scope = join(project, 'node_modules', '@agentdid');
  mkdirSync(scope, { recursive: true });
  try {
    symlinkSync(sdkDir, join(scope, 'sdk'), 'junction');
  } catch {
    cpSync(sdkDir, join(scope, 'sdk'), { recursive: true });
  }
  writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'esm-check', type: 'module' }));
  writeFileSync(join(project, 'check.mjs'), CHECK);
  const result = spawnSync(process.execPath, [join(project, 'check.mjs')], { stdio: 'inherit' });
  process.exitCode = result.status ?? 1;
} finally {
  rmSync(project, { recursive: true, force: true });
}
