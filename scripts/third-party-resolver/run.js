#!/usr/bin/env node
/**
 * Third-party did:webvh resolution check (M-17, criterion C-EXT-1).
 *
 * Logs written by AgentIdentity in BOTH SDKs are served over HTTPS and resolved by the DIF Universal Resolver
 * did:webvh driver (a separate program, run from its published container image), not by our own adapters.
 * The driver must return the document we expect, and must refuse a tampered log.
 *
 * Needs: `npm --prefix sdk run build`, `pip install -e sdk-python[dev]`, docker, openssl.
 * The image tag is pinned in fixtures/third-party-resolver.json; change it deliberately, never to make a run pass.
 */
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..', '..');
const sdk = require(path.join(root, 'sdk', 'dist'));
const config = JSON.parse(fs.readFileSync(path.join(root, 'fixtures', 'third-party-resolver.json'), 'utf8'));
const python = process.env.PYTHON || 'python';
const HOST = 'agent-did.test';
const PORT = 8443;
const DOMAIN = `${HOST}:${PORT}`;
const DRIVER_PORT = 18080;
const CONTAINER = `agent-did-webvh-driver-${process.pid}`;
const FIXTURES = `agent-did-webvh-fixtures-${process.pid}`;
const NETWORK = `agent-did-webvh-net-${process.pid}`;

const failures = [];
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : ` -> ${detail}`}`);
  if (!ok) failures.push(name);
}

function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { encoding: 'utf8', cwd: root, maxBuffer: 32 * 1024 * 1024, ...opts });
  if (res.status !== 0) {
    throw new Error(`${cmd} ${args.join(' ')} exited with ${res.status}\n${res.stderr}`);
  }
  return res.stdout;
}

/** did:webvh:SCID:host%3Aport:seg... -> URL of its did.jsonl (did:webvh v1.0 section "DID-to-HTTPS transformation"). */
function logPath(did) {
  const parts = did.split(':').slice(3);
  const segments = parts.slice(1);
  return segments.length ? `/${segments.join('/')}/did.jsonl` : '/.well-known/did.jsonl';
}

async function emitTypeScript() {
  const [controllerSigner] = sdk.LocalKeySigner.generate();
  const client = new sdk.AgentDidClient({ webvhDomain: DOMAIN });
  const identity = new sdk.AgentIdentity({ client, controllerSigner });
  const { document, agentPrivateKey } = await identity.create({
    name: 'ThirdPartyTs', coreModel: 'resolver-check-model', systemPrompt: 'resolver-check'
  });
  const logs = {
    [document.id]: client.exportDidWebvhHistory(document.id),
    [document.controller]: client.exportDidWebvhHistory(document.controller)
  };
  // A second agent with a multi-entry log: create, update, key rotation.
  const multi = await identity.create({ name: 'ThirdPartyTsMulti', coreModel: 'resolver-check-model', systemPrompt: 'resolver-check' });
  await client.updateDidDocument(multi.document.id, { description: 'updated by the resolver check' });
  await client.rotateVerificationMethod(multi.document.id);
  logs[multi.document.id] = client.exportDidWebvhHistory(multi.document.id);
  const multiDocument = await client.resolve(multi.document.id);
  void agentPrivateKey;
  return { logs, expected: { [document.id]: document, [multi.document.id]: multiDocument } };
}

function emitPython() {
  const out = JSON.parse(run(python, [path.join(root, 'sdk-python', 'scripts', 'emit_webvh_logs.py'), DOMAIN]));
  return out;
}

function tamper(log) {
  const lines = log.trim().split('\n');
  const last = JSON.parse(lines[lines.length - 1]);
  last.state.id = last.state.id.replace(/.$/, (c) => (c === 'a' ? 'b' : 'a'));
  lines[lines.length - 1] = JSON.stringify(last);
  return `${lines.join('\n')}\n`;
}

function writeLog(logsDir, did, log) {
  const file = path.join(logsDir, logPath(did));
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, log);
}

function mountPath(p) {
  return p.split(path.sep).join('/');
}

function cleanup() {
  spawnSync('docker', ['rm', '-f', CONTAINER, FIXTURES], { stdio: 'ignore' });
  spawnSync('docker', ['network', 'rm', NETWORK], { stdio: 'ignore' });
}

async function waitForDriver() {
  for (let i = 0; i < 60; i += 1) {
    try {
      const res = await fetch(`http://127.0.0.1:${DRIVER_PORT}/`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error('driver did not become ready within 60 s');
}

async function driverResolve(did) {
  const res = await fetch(`http://127.0.0.1:${DRIVER_PORT}/1.0/identifiers/${did}`, { signal: AbortSignal.timeout(30000) });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = undefined; }
  return { status: res.status, json, text };
}

(async () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'agentdid-resolver-'));
  let driverStarted = false;
  try {
    run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', `/CN=${HOST}`,
      '-addext', `subjectAltName=DNS:${HOST}`, '-keyout', path.join(work, 'key.pem'), '-out', path.join(work, 'cert.pem')]);

    console.log('emitting');
    const ts = await emitTypeScript();
    const py = emitPython();
    const logsDir = path.join(work, 'logs');
    for (const [did, log] of Object.entries({ ...ts.logs, ...py.logs })) writeLog(logsDir, did, log);

    // Everything runs on one docker network so the check does not depend on host-gateway or host firewalls.
    cleanup();
    run('docker', ['network', 'create', NETWORK]);
    fs.copyFileSync(path.join(__dirname, 'fixture-server.js'), path.join(work, 'fixture-server.js'));
    run('docker', ['run', '-d', '--name', FIXTURES, '--network', NETWORK, '--network-alias', HOST,
      '-v', `${mountPath(work)}:/data:ro`, 'node:24-alpine', 'node', '/data/fixture-server.js']);
    run('docker', ['run', '-d', '--name', CONTAINER, '--network', NETWORK,
      '-v', `${mountPath(path.join(work, 'cert.pem'))}:/ca/cert.pem:ro`, '-e', 'NODE_EXTRA_CA_CERTS=/ca/cert.pem',
      '-p', `127.0.0.1:${DRIVER_PORT}:8080`, config.image]);
    driverStarted = true;
    console.log('driver started, waiting');
    await waitForDriver();
    console.log(`driver: ${config.image}`);

    const cases = [
      ['TypeScript agent (single entry)', Object.keys(ts.expected)[0], ts.expected[Object.keys(ts.expected)[0]]],
      ['TypeScript agent after update and key rotation', Object.keys(ts.expected)[1], ts.expected[Object.keys(ts.expected)[1]]],
      ['Python agent', py.agent, undefined]
    ];
    for (const [name, did, expected] of cases) {
      const r = await driverResolve(did);
      const doc = r.json && r.json.didDocument;
      check(`${name}: driver resolves it`, r.status === 200 && !!doc, `${r.status} ${r.text.slice(0, 200)}`);
      if (!doc) continue;
      check(`${name}: document id matches`, doc.id === did, `${doc.id} != ${did}`);
      if (expected) {
        const keys = (d) => d.verificationMethod.map((m) => `${m.id}|${m.publicKeyMultibase}`).sort();
        check(`${name}: verification methods match ours`, JSON.stringify(keys(doc)) === JSON.stringify(keys(expected)),
          `${JSON.stringify(keys(doc))} vs ${JSON.stringify(keys(expected))}`);
      } else {
        check(`${name}: has a verification method`, Array.isArray(doc.verificationMethod) && doc.verificationMethod.length > 0, 'none');
      }
    }

    // Same DID, same URL, but the last log entry is altered: the driver must verify and refuse.
    const tamperedDid = Object.keys(ts.expected)[0];
    writeLog(logsDir, tamperedDid, tamper(ts.logs[tamperedDid]));
    const bad = await driverResolve(tamperedDid);
    console.log('tampered response:', bad.status, bad.text.slice(0, 300));
    check('tampered log is refused by the driver', bad.status !== 200 || !(bad.json && bad.json.didDocument), bad.text.slice(0, 200));
  } finally {
    if (driverStarted) {
      const logs = spawnSync('docker', ['logs', '--tail', '25', CONTAINER], { encoding: 'utf8' });
      if (failures.length) process.stderr.write(`driver log:
${logs.stdout}${logs.stderr}
`);
    }
    cleanup();
    fs.rmSync(work, { recursive: true, force: true });
  }
  if (failures.length) { console.error(`${failures.length} check(s) failed`); process.exit(1); }
  console.log('third-party resolver check OK');
})().catch((err) => { console.error(err); process.exit(1); });
