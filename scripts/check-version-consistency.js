#!/usr/bin/env node
/**
 * Fails when the live docs state a release version that the manifests do not declare.
 *
 * Two kinds of claims are checked, against two sources of truth:
 *
 *   1. Train claims ("the current train is rc.N": install pins, the badge, "release train" lines,
 *      the criteria table, the SECURITY.md supported-version rows) must equal the version the
 *      manifests declare.
 *   2. Published claims ("rc.N is published") must equal the last PUBLISHED train: the manifest
 *      version once its `v<version>` git tag exists, the previous RC before that. Without tags
 *      (a shallow clone) both are accepted, and the output says so.
 *
 * The manifests themselves (npm and PyPI packages of the release train) must agree with each other.
 * Historical mentions (migration guide names, CHANGELOG entries, "since rc.3") are not claims and
 * are not matched. The rules are explicit, below: extend them when a doc gains a new claim.
 *
 * Usage: node scripts/check-version-consistency.js
 */

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const errors = [];
const fail = (message) => errors.push(message);

// --- Manifests --------------------------------------------------------------------------------
const NPM_PACKAGES = ['sdk/package.json', 'integrations/langchain/package.json'];
const PYTHON_PACKAGES = [
  'sdk-python/pyproject.toml',
  'integrations/a2a/pyproject.toml',
  'integrations/crewai/pyproject.toml',
  'integrations/langchain-python/pyproject.toml',
  'integrations/microsoft-agent-framework/pyproject.toml',
  'integrations/semantic-kernel/pyproject.toml'
];

const npmVersion = (file) => JSON.parse(read(file)).version;
const pythonVersion = (file) => {
  const match = /^version\s*=\s*"([^"]+)"/mu.exec(read(file));
  return match ? match[1] : undefined;
};

const trainNpm = npmVersion('sdk/package.json'); // e.g. 1.0.0-rc.4
const trainMatch = /^(\d+\.\d+\.\d+)-rc\.(\d+)$/u.exec(trainNpm);
if (!trainMatch) {
  console.error(`sdk/package.json version ${trainNpm} is not a 1.x release candidate (X.Y.Z-rc.N); update this script for the new scheme.`);
  process.exit(1);
}
const [, base, rcText] = trainMatch;
const rc = Number(rcText);
const trainPython = `${base}rc${rc}`; // e.g. 1.0.0rc4

for (const file of NPM_PACKAGES) {
  if (npmVersion(file) !== trainNpm) fail(`${file}: version ${npmVersion(file)}, the train is ${trainNpm}`);
}
for (const file of PYTHON_PACKAGES) {
  if (pythonVersion(file) !== trainPython) fail(`${file}: version ${pythonVersion(file)}, the train is ${trainPython}`);
}

// --- Last published train -----------------------------------------------------------------------
function tagExists(tag) {
  try {
    return execFileSync('git', ['tag', '--list', tag], { cwd: root, encoding: 'utf8' }).trim() === tag;
  } catch {
    return undefined;
  }
}
function hasAnyTags() {
  try {
    return execFileSync('git', ['tag', '--list', 'v*'], { cwd: root, encoding: 'utf8' }).trim() !== '';
  } catch {
    return false;
  }
}

let publishedRc; // the RC number that is published, or undefined when it cannot be decided
let publishedNote = '';
if (!hasAnyTags()) {
  publishedNote = 'no git tags available: published claims may name the train or the previous RC';
} else {
  publishedRc = tagExists(`v${trainNpm}`) ? rc : rc - 1;
}

// --- Doc rules --------------------------------------------------------------------------------
// Each rule: the files, a regex with ONE capture group holding the RC number, and the kind.
// `line` rules only look at lines that match `when`.
const RC_NPM = '1\\.0\\.0-rc\\.(\\d+)';
const RC_PY = '1\\.0\\.0rc(\\d+)';

const LIVE_DOCS = [
  'README.md', 'QUICKSTART.md', 'SECURITY.md', 'CONTRIBUTING.md',
  'sdk/README.md', 'sdk-python/README.md',
  'integrations/langchain/README.md', 'integrations/langchain-python/README.md', 'integrations/crewai/README.md',
  'integrations/semantic-kernel/README.md', 'integrations/microsoft-agent-framework/README.md', 'integrations/a2a/README.md',
  'docs/RELEASE-1.0-CRITERIA.md', 'docs/INDEX.md'
].filter((file) => fs.existsSync(path.join(root, file)));

const RULES = [
  { kind: 'train', what: 'pinned PyPI install', regex: new RegExp(`==\\s*${RC_PY}`, 'gu') },
  { kind: 'train', what: 'pinned npm package', regex: new RegExp(`@agentdid/[a-z]+(?:@|\`\\s+\`)${RC_NPM}`, 'gu') },
  { kind: 'train', what: 'status badge', regex: /status-1\.0\.0--rc\.(\d+)/gu },
  { kind: 'train', what: 'release train line', when: /release train/iu, regex: new RegExp(`${RC_NPM}`, 'gu') },
  { kind: 'train', what: 'breaking changes line', regex: new RegExp(`breaking changes in \`(?:1\\.0\\.0-rc\\.|1\\.0\\.0rc)(\\d+)`, 'gu') },
  { kind: 'train', what: '"the current one"', regex: new RegExp(`current one is \`${RC_NPM}`, 'gu') },
  { kind: 'train', what: 'criteria "declare"', regex: new RegExp(`packages declare \`(?:1\\.0\\.0-rc\\.|1\\.0\\.0rc)(\\d+)`, 'gu') },
  { kind: 'train', what: 'criteria release tag', regex: new RegExp(`release tag is \`v${RC_NPM}`, 'gu') },
  { kind: 'train', what: 'SECURITY supported version', regex: new RegExp(`latest published \\(\`(?:1\\.0\\.0-rc\\.|1\\.0\\.0rc)(\\d+)\``, 'gu') },
  { kind: 'published', what: '"Published prerelease" line', when: /Published prerelease/u, regex: new RegExp(`(?:${RC_NPM}|${RC_PY})`, 'gu') },
  { kind: 'published', what: '"the published" version', regex: new RegExp(`the published \`${RC_NPM}`, 'gu') },
  { kind: 'published', what: '"co-versioned" prerelease', regex: new RegExp(`co-versioned \`${RC_NPM}`, 'gu') },
  { kind: 'published', what: 'criteria table (published column)', when: /^\|.*\((`next`, `latest`)\)/u, regex: new RegExp(`\\|\\s*${RC_NPM}`, 'gu') },
  { kind: 'published', what: 'criteria table (PyPI rows)', when: /^\|\s*`agent-did-[a-z-]+`/u, regex: new RegExp(`\\|\\s*${RC_PY}\\s*\\|`, 'gu') }
];

// Evidence entries record what a past run validated; they are history, not claims about the current train.
const HISTORICAL_LINE = /_Evidence:/u;

function checkClaim(file, lineNumber, rule, found) {
  if (rule.kind === 'train') {
    if (found !== rc) fail(`${file}:${lineNumber}: ${rule.what} names rc.${found}, the manifests declare rc.${rc}`);
    return;
  }
  if (publishedRc === undefined) {
    if (found !== rc && found !== rc - 1) fail(`${file}:${lineNumber}: ${rule.what} names rc.${found}, expected rc.${rc} or rc.${rc - 1}`);
  } else if (found !== publishedRc) {
    fail(`${file}:${lineNumber}: ${rule.what} names rc.${found}, the last published train is rc.${publishedRc}`);
  }
}

for (const file of LIVE_DOCS) {
  read(file).split(/\r?\n/u).forEach((line, index) => {
    if (HISTORICAL_LINE.test(line)) return;
    for (const rule of RULES) {
      if (rule.when && !rule.when.test(line)) continue;
      for (const match of line.matchAll(rule.regex)) {
        // The regexes with two alternatives (npm and PyPI forms) carry the number in either group.
        const found = Number(match.slice(1).find((group) => group !== undefined));
        checkClaim(file, index + 1, rule, found);
      }
    }
  });
}

// SECURITY.md must not advertise a pre-1.0 line as the supported one.
if (fs.existsSync(path.join(root, 'SECURITY.md'))) {
  read('SECURITY.md').split(/\r?\n/u).forEach((line, index) => {
    if (/latest published \(`v?0\.\d+\.x` line\)/u.test(line)) {
      fail(`SECURITY.md:${index + 1}: names a 0.x line as supported, the train is ${trainNpm}`);
    }
  });
}

// --- Report -----------------------------------------------------------------------------------
if (errors.length > 0) {
  console.error(`Version consistency check failed (train ${trainNpm} / ${trainPython}):`);
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}
console.log(`Version consistency OK: train ${trainNpm} / ${trainPython}, ${NPM_PACKAGES.length + PYTHON_PACKAGES.length} manifests, ${LIVE_DOCS.length} docs.`);
if (publishedNote) console.log(`Note: ${publishedNote}.`);
