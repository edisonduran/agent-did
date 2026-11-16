#!/usr/bin/env node
/**
 * Builds the static site served at https://agent-did.org (docs/Site-Operations.md) into `site-dist/`.
 *
 * - `site/` is copied as is (pages, `_headers`, the clearsigned `.well-known/security.txt`).
 * - `contexts/v1.jsonld` is copied byte for byte to `site-dist/v1`: the JSON-LD context URL
 *   `https://agent-did.org/v1` (ADR-003). Its SHA-256 must match the pin in `contexts/v1.jsonld.sha256`.
 * - The signed text of `site/.well-known/security.txt` must equal `.github/security/security.txt`.
 *
 * Cloudflare Pages runs this script (build command `node scripts/build-site.js`, output `site-dist`).
 * It uses only Node built-ins, so it needs no `npm install`.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const siteDir = path.join(root, 'site');
const outDir = path.join(root, 'site-dist');

const CLEARSIGN_HEADER = '-----BEGIN PGP SIGNED MESSAGE-----';
const SIGNATURE_HEADER = '-----BEGIN PGP SIGNATURE-----';

function fail(message) {
  console.error(`build-site: ${message}`);
  process.exit(1);
}

function lf(text) {
  return text.replace(/\r\n/g, '\n');
}

/** The cleartext of an OpenPGP clearsigned message (RFC 9580 §7), dash-escaping removed. */
function clearsignedText(signed) {
  const lines = lf(signed).split('\n');
  if (lines[0] !== CLEARSIGN_HEADER) return undefined;
  let i = 1;
  while (i < lines.length && lines[i] !== '') i += 1; // armor headers (Hash: ...)
  const end = lines.indexOf(SIGNATURE_HEADER, i);
  if (end < 0) return undefined;
  return lines
    .slice(i + 1, end)
    .map((line) => (line.startsWith('- ') ? line.slice(2) : line))
    .join('\n');
}

function checkContext() {
  const contextPath = path.join(root, 'contexts', 'v1.jsonld');
  const bytes = fs.readFileSync(contextPath);
  const pinned = fs.readFileSync(`${contextPath}.sha256`, 'utf8').trim().split(/\s+/)[0];
  const actual = crypto.createHash('sha256').update(bytes).digest('hex');
  if (pinned !== actual) fail(`contexts/v1.jsonld sha256 ${actual} does not match the pin ${pinned}`);
  return bytes;
}

function checkSecurityTxt() {
  const signedPath = path.join(siteDir, '.well-known', 'security.txt');
  if (!fs.existsSync(signedPath)) {
    fail('site/.well-known/security.txt is missing: clearsign .github/security/security.txt (docs/Site-Operations.md)');
  }
  const text = clearsignedText(fs.readFileSync(signedPath, 'utf8'));
  if (text === undefined) fail('site/.well-known/security.txt is not an OpenPGP clearsigned message');
  const source = lf(fs.readFileSync(path.join(root, '.github', 'security', 'security.txt'), 'utf8'));
  if (text.trimEnd() !== source.trimEnd()) {
    fail('the signed text of site/.well-known/security.txt differs from .github/security/security.txt: sign it again');
  }
  const expires = /^Expires:\s*(\S+)\s*$/m.exec(text);
  if (!expires || Number.isNaN(Date.parse(expires[1]))) fail('security.txt has no valid Expires field');
  if (Date.parse(expires[1]) <= Date.now()) fail(`security.txt expired on ${expires[1]}`);
  return { text, expires: expires[1] };
}

function copyTree(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const source = path.join(from, entry.name);
    const target = path.join(to, entry.name);
    if (entry.isDirectory()) copyTree(source, target);
    else fs.copyFileSync(source, target);
  }
}

function build() {
  const context = checkContext();
  const security = checkSecurityTxt();
  fs.rmSync(outDir, { recursive: true, force: true });
  copyTree(siteDir, outDir);
  fs.writeFileSync(path.join(outDir, 'v1'), context);
  console.log(`build-site: wrote ${path.relative(root, outDir)} (context v1, security.txt expires ${security.expires})`);
}

module.exports = { clearsignedText, checkContext, checkSecurityTxt, outDir, root };

if (require.main === module) build();
