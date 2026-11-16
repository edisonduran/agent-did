#!/usr/bin/env node
/**
 * Integrations and examples must use the SDKs only through their public entry points
 * (docs/DEPRECATION-POLICY.md, "Public API contract"):
 * - Python: `from agent_did_sdk import ...`, never `agent_did_sdk.<submodule>`.
 * - JavaScript/TypeScript: `@agentdid/sdk`, never `@agentdid/sdk/<path>`.
 * Tests are exempt: they may check internals on purpose.
 */
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const SCAN_ROOTS = ['integrations', 'examples', 'sdk/examples', 'sdk-python/examples'];
const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', '.venv', 'venv', '__pycache__', 'tests', 'test', '__tests__', '.pytest_cache', '.mypy_cache', '.ruff_cache']);
const PY_INTERNAL = /^\s*(?:from\s+agent_did_sdk\.[\w.]+\s+import\b|import\s+agent_did_sdk\.[\w.]+)/;
const JS_INTERNAL = /(?:from\s+|require\(\s*|import\(\s*)['"]@agentdid\/sdk\/(?!package\.json['"])[^'"]+['"]/;

function* walk(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) yield* walk(full);
    } else {
      yield full;
    }
  }
}

const violations = [];
for (const scanRoot of SCAN_ROOTS) {
  for (const file of walk(path.join(ROOT, scanRoot))) {
    const isPython = file.endsWith('.py');
    const isJs = /\.(?:[cm]?js|tsx?)$/.test(file);
    if (!isPython && !isJs) continue;
    if (/(?:^|[\\/])(?:test_[^\\/]*\.py|[^\\/]*\.test\.[cm]?[jt]sx?|conftest\.py)$/.test(file)) continue;
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    lines.forEach((line, index) => {
      if ((isPython && PY_INTERNAL.test(line)) || (isJs && JS_INTERNAL.test(line))) {
        violations.push(`${path.relative(ROOT, file).replace(/\\/g, '/')}:${index + 1}: ${line.trim()}`);
      }
    });
  }
}

if (violations.length > 0) {
  console.error('SDK internals imported outside tests (use the package entry point instead):');
  for (const violation of violations) console.error(`  ${violation}`);
  process.exit(1);
}
console.log('Public API imports: OK (integrations and examples use only the SDK entry points).');
