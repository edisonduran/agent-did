#!/usr/bin/env node
/**
 * Checks the agent-did.org site (docs/Site-Operations.md).
 *
 *   node scripts/check-site.js          builds site-dist/ and verifies the security.txt signature with the
 *                                       repository key (.github/security/agent-did-security.asc). Needs gpg.
 *   node scripts/check-site.js --live   also fetches https://agent-did.org and checks that it serves the
 *                                       repository files: /v1 byte for byte with a JSON-LD media type, the
 *                                       signed security.txt, the vocabulary and the A2A extension pages; and
 *                                       that security.txt does not expire within 30 days.
 */
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { checkContext, checkSecurityTxt, root } = require('./build-site');

// The fingerprint SECURITY.md publishes. Changing it is a change to the security contact (CODEOWNERS).
const SECURITY_KEY_FINGERPRINT = '9C56A73951F49EB7F4FEFF4310377F82E83D3A8A';
const ORIGIN = 'https://agent-did.org';
const MIN_DAYS_TO_EXPIRY = 30;

const problems = [];
const problem = (message) => problems.push(message);

function lf(text) {
  return text.replace(/\r\n/g, '\n');
}

function verifySignature() {
  // gpgv against a keyring holding only the repository key: no agent, no trust database, no user keyring.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-did-gpg-'));
  try {
    const run = (command, args) =>
      execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    // gpgv reads a keyring name without "/" as a file in its home directory: use "/" on Windows too.
    const keyring = path.join(home, 'security-key.gpg').split(path.sep).join('/');
    run('gpg', ['--batch', '--no-tty', '--dearmor', '--output', keyring, path.join(root, '.github', 'security', 'agent-did-security.asc')]);
    let status;
    try {
      status = run('gpgv', ['--status-fd', '1', '--keyring', keyring, path.join(root, 'site', '.well-known', 'security.txt')]);
    } catch (error) {
      status = String(error.stdout || '');
      console.error(String(error.stderr || '').trim());
    }
    const validsig = /^\[GNUPG:\] VALIDSIG \S+ .* ([0-9A-F]{40})$/m.exec(status);
    if (!/^\[GNUPG:\] GOODSIG /m.test(status) || !validsig) {
      problem('site/.well-known/security.txt: the signature does not verify with .github/security/agent-did-security.asc');
    } else if (validsig[1] !== SECURITY_KEY_FINGERPRINT) {
      problem(`site/.well-known/security.txt: signed by primary key ${validsig[1]}, expected ${SECURITY_KEY_FINGERPRINT}`);
    }
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
}

async function fetchPath(urlPath) {
  const response = await fetch(`${ORIGIN}${urlPath}`, { redirect: 'manual', signal: AbortSignal.timeout(15000) });
  const body = Buffer.from(await response.arrayBuffer());
  return { response, body };
}

async function checkLive(context, security) {
  const v1 = await fetchPath('/v1');
  const type = v1.response.headers.get('content-type') || '';
  if (v1.response.status !== 200) problem(`${ORIGIN}/v1: HTTP ${v1.response.status}`);
  else {
    if (!v1.body.equals(context)) problem(`${ORIGIN}/v1: body differs from contexts/v1.jsonld`);
    if (!/^application\/(ld\+)?json\b/.test(type)) problem(`${ORIGIN}/v1: Content-Type "${type}", expected application/ld+json`);
    if (v1.response.headers.get('access-control-allow-origin') !== '*') problem(`${ORIGIN}/v1: no Access-Control-Allow-Origin: *`);
  }

  const txt = await fetchPath('/.well-known/security.txt');
  const signed = lf(fs.readFileSync(path.join(root, 'site', '.well-known', 'security.txt'), 'utf8'));
  if (txt.response.status !== 200) problem(`${ORIGIN}/.well-known/security.txt: HTTP ${txt.response.status}`);
  else if (lf(txt.body.toString('utf8')) !== signed) problem(`${ORIGIN}/.well-known/security.txt: differs from site/.well-known/security.txt`);

  for (const page of ['/vocab', '/a2a/identity/v1']) {
    const { response } = await fetchPath(page);
    const pageType = response.headers.get('content-type') || '';
    if (response.status !== 200 || !pageType.startsWith('text/html')) {
      problem(`${ORIGIN}${page}: HTTP ${response.status} ${pageType}, expected 200 text/html`);
    }
  }

  const days = (Date.parse(security.expires) - Date.now()) / 86400000;
  if (days < MIN_DAYS_TO_EXPIRY) problem(`security.txt expires in ${Math.floor(days)} days (${security.expires}): renew and sign it again`);
}

async function main() {
  const live = process.argv.includes('--live');
  const context = checkContext();
  const security = checkSecurityTxt();
  verifySignature();
  if (live) await checkLive(context, security);
  if (problems.length > 0) {
    for (const message of problems) console.error(`check-site: ${message}`);
    process.exit(1);
  }
  console.log(`check-site: OK${live ? ` (${ORIGIN} serves the repository files)` : ''}`);
}

main().catch((error) => {
  console.error(`check-site: ${error.message}`);
  process.exit(1);
});
