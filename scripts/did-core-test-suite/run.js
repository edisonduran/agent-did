#!/usr/bin/env node
/**
 * W3C DID Core test suite check (WP-7, External Conformance Matrix row "W3C DID Core").
 *
 * DID documents created by BOTH SDKs are fed to the W3C DID Working Group test suite
 * (https://github.com/w3c/did-test-suite, pinned in fixtures/did-core-test-suite.json) as
 * implementation entries, the way a DID method registers itself there. The suite's own jest
 * spec files run unchanged; only the list of implementations comes from us.
 *
 * Suites run: did-core-properties (§5, §7.3), did-identifier (§3), did-production (§6.1-6.3).
 * Per SDK, two document sources for the same DIDs:
 *   - "AgentDidClient.resolve": the document Agent-DID consumers receive;
 *   - "did:webvh log resolution": the document and DID document metadata from verifying the
 *     DID's did.jsonl with the SDK's did:webvh adapter.
 * A negative control feeds a deliberately broken document and requires the suite to reject it,
 * so a vacuous run (no tests collected, config ignored) cannot pass.
 *
 * Usage:
 *   DID_CORE_TEST_SUITE_DIR=<checkout of w3c/did-test-suite> node scripts/did-core-test-suite/run.js [--prepare]
 * --prepare installs the suite's dependencies first (see prepare() below).
 * Needs: `npm --prefix sdk run build`, `pip install -e sdk-python`.
 */
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..', '..');
const pin = JSON.parse(fs.readFileSync(path.join(root, 'fixtures', 'did-core-test-suite.json'), 'utf8'));
const python = process.env.PYTHON || 'python';
const DOMAIN = 'agent-did.test';
const MEDIA_TYPE = 'application/did+ld+json';
const IMPLEMENTER = 'Agent-DID';

const failures = [];
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : ` -> ${detail}`}`);
  if (!ok) failures.push(name);
}

function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, {
    encoding: 'utf8', cwd: root, maxBuffer: 64 * 1024 * 1024, shell: process.platform === 'win32', ...opts
  });
  if (res.status !== 0) {
    throw new Error(`${cmd} ${args.join(' ')} exited with ${res.status}\n${res.stdout}\n${res.stderr}`);
  }
  return res.stdout;
}

const suiteRoot = process.env.DID_CORE_TEST_SUITE_DIR;
if (!suiteRoot) {
  console.error('DID_CORE_TEST_SUITE_DIR must point to a checkout of w3c/did-test-suite');
  process.exit(2);
}
const serverDir = path.join(path.resolve(suiteRoot), pin.package);
const matcherDir = path.join(path.resolve(suiteRoot), 'packages', 'jest-did-matcher');

/**
 * The suite is a lerna monorepo whose `jest-did-matcher` package is linked locally and never
 * published to npm. Build it from its source and load it by path; install the test server's
 * locked dependencies without that entry. Install scripts are disabled.
 */
function prepare() {
  run('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: matcherDir });
  run('npx', ['--no-install', 'babel', 'src', '-d', 'dist', '--ignore', '*.test.js'], { cwd: matcherDir });
  run('npm', ['pkg', 'delete', 'dependencies.jest-did-matcher'], { cwd: serverDir });
  run('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: serverDir });
}

async function emitTypeScript() {
  const sdk = require(path.join(root, 'sdk', 'dist'));
  // Internal module: the adapter's resolution result carries the did:webvh DID document metadata.
  const { resolveDidWebvhLog } = require(path.join(root, 'sdk', 'dist', 'webvh', 'adapter.js'));
  const [controllerSigner] = sdk.LocalKeySigner.generate();
  const client = new sdk.AgentDidClient({ webvhDomain: DOMAIN });
  const identity = new sdk.AgentIdentity({ client, controllerSigner });
  const single = await identity.create({ name: 'DidCoreTs', coreModel: 'did-core-check-model', systemPrompt: 'did-core-check' });
  const multi = await identity.create({ name: 'DidCoreTsMulti', coreModel: 'did-core-check-model', systemPrompt: 'did-core-check' });
  await client.updateDidDocument(multi.document.id, { description: 'updated by the DID Core check' });
  await client.rotateVerificationMethod(multi.document.id);

  const entry = async (scenario, did) => {
    const webvh = await resolveDidWebvhLog(client.exportDidWebvhHistory(did), { did });
    return {
      scenario,
      did,
      resolved: JSON.parse(JSON.stringify(await client.resolve(did))),
      webvh: { document: webvh.document, metadata: webvh.metadata }
    };
  };
  return [
    await entry('agent (single entry)', single.document.id),
    await entry('agent after update and key rotation', multi.document.id),
    await entry('controller', single.document.controller)
  ];
}

function emitPython() {
  return JSON.parse(run(python, [path.join(root, 'sdk-python', 'scripts', 'emit_did_documents.py'), DOMAIN])).documents;
}

/** One implementation entry in the format of the suite's suites/implementations/*.json. */
function implementation(label, items, source) {
  const impl = {
    didMethod: 'did:webvh',
    implementation: label,
    implementer: IMPLEMENTER,
    supportedContentTypes: [MEDIA_TYPE],
    dids: items.map((item) => item.did),
    didParameters: {}
  };
  for (const item of items) {
    const document = source === 'webvh' ? item.webvh.document : item.resolved;
    if (document.id !== item.did) throw new Error(`${label}: document for ${item.did} has id ${document.id}`);
    const { '@context': context, ...properties } = document;
    const result = {
      didDocumentDataModel: { representationSpecificEntries: context === undefined ? {} : { '@context': context } },
      representation: JSON.stringify(document),
      didResolutionMetadata: { contentType: MEDIA_TYPE }
    };
    if (source === 'webvh') result.didDocumentMetadata = item.webvh.metadata;
    impl[item.did] = { didDocumentDataModel: { properties }, [MEDIA_TYPE]: result };
  }
  return impl;
}

/** A copy of a valid entry with two DID Core violations the suite has tests for. */
function brokenImplementation(valid) {
  const impl = JSON.parse(JSON.stringify(valid));
  impl.implementation = 'negative control';
  const did = impl.dids[0];
  const vm = impl[did].didDocumentDataModel.properties.verificationMethod[0];
  vm.controller = 'not-a-did';
  vm.publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };
  impl[did][MEDIA_TYPE].representation = JSON.stringify({
    ...impl[did][MEDIA_TYPE].didDocumentDataModel.representationSpecificEntries,
    ...impl[did].didDocumentDataModel.properties
  });
  return impl;
}

function runSuite(work, name, implementations) {
  const configPath = path.join(work, `${name}-implementations.json`);
  const reportPath = path.join(work, `${name}-report.json`);
  fs.writeFileSync(configPath, JSON.stringify(implementations, null, 2));
  const jestConfig = {
    rootDir: serverDir,
    testMatch: pin.suites.map((suite) => `<rootDir>/${suite}`),
    testEnvironment: 'node',
    setupFilesAfterEnv: ['jest-extended', path.join(matcherDir, 'dist', 'index.js'), path.join(__dirname, 'jest-setup.js')]
  };
  const jestConfigPath = path.join(work, `${name}-jest.config.json`);
  fs.writeFileSync(jestConfigPath, JSON.stringify(jestConfig));
  const res = spawnSync(process.execPath, [
    path.join(serverDir, 'node_modules', 'jest', 'bin', 'jest.js'),
    '--ci', '--silent', '--json', `--outputFile=${reportPath}`, `--config=${jestConfigPath}`
  ], { cwd: serverDir, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...process.env, AGENT_DID_CORE_SUITE_CONFIG: configPath } });
  if (!fs.existsSync(reportPath)) {
    throw new Error(`jest wrote no report (exit ${res.status})\n${res.stdout}\n${res.stderr}`);
  }
  return { status: res.status, report: JSON.parse(fs.readFileSync(reportPath, 'utf8')), stderr: res.stderr };
}

/** Assertion results grouped by the implementation label in the suite's "IMPLEMENTATION ::..." describe. */
function byImplementation(report) {
  const groups = new Map();
  for (const file of report.testResults) {
    const spec = path.basename(file.name);
    for (const a of file.assertionResults) {
      const marker = a.ancestorTitles.find((t) => t.startsWith('IMPLEMENTATION ::'));
      const label = marker ? marker.split('::')[2] : '(none)';
      if (!groups.has(label)) groups.set(label, []);
      groups.get(label).push({ ...a, spec });
    }
  }
  return groups;
}

(async () => {
  if (process.argv.includes('--prepare')) prepare();
  const head = run('git', ['rev-parse', 'HEAD'], { cwd: suiteRoot }).trim();
  check('suite checkout is the pinned commit', head === pin.commit, `${head} != ${pin.commit}`);
  if (head !== pin.commit) process.exit(1);
  if (!fs.existsSync(path.join(matcherDir, 'dist', 'index.js')) || !fs.existsSync(path.join(serverDir, 'node_modules', 'jest'))) {
    console.error('suite dependencies are not installed; run with --prepare');
    process.exit(2);
  }

  const ts = await emitTypeScript();
  const py = emitPython();
  const implementations = [
    implementation('Agent-DID TypeScript SDK: AgentDidClient.resolve', ts, 'resolved'),
    implementation('Agent-DID TypeScript SDK: did:webvh log resolution', ts, 'webvh'),
    implementation('Agent-DID Python SDK: AgentDidClient.resolve', py, 'resolved'),
    implementation('Agent-DID Python SDK: did:webvh log resolution', py, 'webvh')
  ];

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'agentdid-didcore-'));
  try {
    console.log(`suite: ${pin.repository} @ ${pin.commit}`);
    const main = runSuite(work, 'agent-did', implementations);
    const groups = byImplementation(main.report);
    for (const impl of implementations) {
      const results = groups.get(impl.implementation) || [];
      const failed = results.filter((a) => a.status === 'failed');
      const passed = results.filter((a) => a.status === 'passed');
      const specs = new Set(passed.map((a) => a.spec));
      console.log(`      ${impl.implementation}: ${passed.length} passed, ${failed.length} failed, DIDs: ${impl.dids.length}`);
      check(`${impl.implementation}: no failing test`, failed.length === 0,
        failed.slice(0, 10).map((a) => `${a.ancestorTitles.slice(-2).join(' > ')} > ${a.title}`).join('\n    '));
      check(`${impl.implementation}: every suite ran`, pin.suites.every((s) => specs.has(path.basename(s))),
        `ran: ${[...specs].join(', ')}`);
      if (impl.implementation.endsWith('did:webvh log resolution')) {
        check(`${impl.implementation}: §7.3 metadata structure checked`,
          passed.some((a) => a.ancestorTitles.some((t) => t.startsWith('7.3 Metadata Structure'))), 'no §7.3 test ran');
      }
    }
    const strays = [...groups.keys()].filter((label) => !implementations.some((i) => i.implementation === label));
    check('only our implementations ran', strays.length === 0, strays.join(', '));
    check('jest exited cleanly', main.status === 0 && main.report.numRuntimeErrorTestSuites === 0,
      `exit ${main.status}, suites with runtime errors: ${main.report.numRuntimeErrorTestSuites}\n${main.stderr.slice(-2000)}`);

    const negative = runSuite(work, 'negative-control', [brokenImplementation(implementations[0])]);
    const failedTitles = negative.report.testResults.flatMap((f) => f.assertionResults)
      .filter((a) => a.status === 'failed').map((a) => a.title);
    check('negative control: suite rejects a verification method controller that is not a DID',
      failedTitles.some((t) => t.startsWith('5.2 Verification Methods - The value of the controller property')), failedTitles.join(' | '));
    check('negative control: suite rejects two kinds of key material in one verification method',
      failedTitles.some((t) => t.startsWith('5.2.1 Verification Material')), failedTitles.join(' | '));
    check('negative control: jest exits non-zero', negative.status !== 0, `exit ${negative.status}`);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }

  if (failures.length) { console.error(`${failures.length} check(s) failed`); process.exit(1); }
  console.log('W3C DID Core test suite check OK');
})().catch((err) => { console.error(err); process.exit(1); });
