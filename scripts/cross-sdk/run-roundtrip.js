#!/usr/bin/env node
/**
 * Live cross-SDK round trip (M-13): each SDK creates a fresh identity and signs a message and an HTTP request,
 * and the other SDK must verify both (and reject tampered copies). Complements the static, independently generated
 * fixtures/interop-vectors.json. Needs `npm --prefix sdk run build` and `pip install -e sdk-python[dev]`.
 */
const { spawnSync } = require('child_process');
const path = require('path');

const root = path.join(__dirname, '..', '..');
const python = process.env.PYTHON || 'python';
const tsScript = path.join(__dirname, 'ts-roundtrip.js');
const pyScript = path.join(root, 'sdk-python', 'scripts', 'cross_sdk_roundtrip.py');

function run(cmd, args, input) {
  const res = spawnSync(cmd, args, { input, encoding: 'utf8', cwd: root, maxBuffer: 16 * 1024 * 1024 });
  if (res.stderr) process.stderr.write(res.stderr);
  if (res.status !== 0) {
    console.error(`FAIL: ${cmd} ${args.join(' ')} exited with ${res.status}`);
    process.exit(1);
  }
  return res.stdout;
}

const tsBundle = run(process.execPath, [tsScript, 'emit']);
const pyBundle = run(python, [pyScript, 'emit']);

run(python, [pyScript, 'verify'], tsBundle); // TS -> Python
run(process.execPath, [tsScript, 'verify'], pyBundle); // Python -> TS
run(process.execPath, [tsScript, 'verify'], tsBundle); // sanity: self
run(python, [pyScript, 'verify'], pyBundle);

console.log('cross-SDK round trip OK: TS -> Python and Python -> TS');
