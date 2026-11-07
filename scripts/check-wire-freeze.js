#!/usr/bin/env node
/**
 * Wire freeze check: fails when a fixture that defines signed or hashed bytes differs from the digest pinned in
 * fixtures/wire-freeze.json.
 *
 * From the release candidate that sets the freeze until `v1.0.0`, bytes that are signed or hashed must not change
 * (see docs/DEPRECATION-POLICY.md, "Wire freeze"). The fixtures below are the shared vectors for those bytes: the
 * HTTP signature base and profile, the canonicalization behind `documentRef`, the salted commitments and the
 * did:webvh logs. Changing one of them is a decision, not a side effect, so the digest is pinned.
 *
 * Usage:
 *   node scripts/check-wire-freeze.js            check (exit 1 on a difference)
 *   node scripts/check-wire-freeze.js --write    pin the current digests (only when cutting a release candidate,
 *                                                or when a deliberate, explained change needs a new one)
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const manifestPath = path.join(root, 'fixtures', 'wire-freeze.json');

const FROZEN_FIXTURES = [
  'fixtures/interop-vectors.json',
  'fixtures/http-verification-vectors.json',
  'fixtures/canonical-document-reference.json',
  'fixtures/jcs-vectors.json',
  'fixtures/metadata-commitment-vectors.json',
  'fixtures/webvh-log-vectors.json'
];

/** SHA-256 of the file with line endings normalized, so a Windows checkout and Linux CI agree. */
function digest(file) {
  const text = fs.readFileSync(path.join(root, file), 'utf8').replace(/\r\n/gu, '\n');
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function current() {
  return Object.fromEntries(FROZEN_FIXTURES.map((file) => [file, digest(file)]));
}

if (process.argv.includes('--write')) {
  const manifest = {
    description:
      'SHA-256 of the shared fixtures that define signed or hashed bytes, pinned when the wire freeze was set. ' +
      'Change a digest only for a deliberate wire change, in a new release candidate, with an entry in ' +
      'CHANGELOG.md and the migration guides. See docs/DEPRECATION-POLICY.md.',
    check: 'node scripts/check-wire-freeze.js',
    pin: 'node scripts/check-wire-freeze.js --write',
    fixtures: current()
  };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  console.log(`Pinned ${FROZEN_FIXTURES.length} fixture digests in fixtures/wire-freeze.json`);
  process.exit(0);
}

if (!fs.existsSync(manifestPath)) {
  console.log('Wire freeze not pinned yet: fixtures/wire-freeze.json is created when the freeze is set (release candidate cut).');
  process.exit(0);
}

const pinned = JSON.parse(fs.readFileSync(manifestPath, 'utf8')).fixtures;
const now = current();
const problems = [];
for (const file of FROZEN_FIXTURES) {
  if (!pinned[file]) problems.push(`${file}: not in the pinned manifest`);
  else if (pinned[file] !== now[file]) problems.push(`${file}: differs from the pinned digest`);
}
for (const file of Object.keys(pinned)) {
  if (!FROZEN_FIXTURES.includes(file)) problems.push(`${file}: pinned but no longer checked by this script`);
}

if (problems.length > 0) {
  console.error('Wire freeze check failed. These fixtures define signed or hashed bytes and may not change in the freeze:');
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error('If the change is deliberate (a wire change needs a new release candidate, a CHANGELOG entry and migration guides), re-pin with: node scripts/check-wire-freeze.js --write');
  process.exit(1);
}
console.log(`Wire freeze OK: ${FROZEN_FIXTURES.length} fixtures match the pinned digests.`);
