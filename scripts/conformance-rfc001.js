const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CHECKLIST_PATH = path.join(ROOT, 'docs', 'RFC-001-Compliance-Checklist.md');

function run(command, cwd = ROOT) {
  try {
    execSync(command, {
      cwd,
      stdio: 'inherit',
      encoding: 'utf8'
    });
    return { ok: true };
  } catch (error) {
    return { ok: false, error };
  }
}

function parseChecklist(content, prefix) {
  const lines = content.split('\n');
  const rows = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith(`| ${prefix}-`)) {
      continue;
    }

    const cells = trimmed
      .split('|')
      .map((cell) => cell.trim())
      .filter(Boolean);

    if (cells.length < 3) {
      continue;
    }

    const id = cells[0];
    const status = cells[2].toUpperCase();
    rows.push({ id, status, raw: trimmed });
  }

  return rows;
}

function summarize(rows) {
  return rows.reduce(
    (acc, row) => {
      if (row.status === 'PASS') acc.pass += 1;
      else if (row.status === 'PARTIAL') acc.partial += 1;
      else if (row.status === 'FAIL') acc.fail += 1;
      else acc.unknown += 1;
      return acc;
    },
    { pass: 0, partial: 0, fail: 0, unknown: 0 }
  );
}

function printSection(title, rows) {
  console.log(`\n${title}`);
  for (const row of rows) {
    console.log(`- ${row.id}: ${row.status}`);
  }
}

function main() {
  if (!fs.existsSync(CHECKLIST_PATH)) {
    console.error(`Checklist not found: ${CHECKLIST_PATH}`);
    process.exit(1);
  }

  console.log('\\n[conformance] Running technical verification checks...');

  const checks = [
    { name: 'SDK build', cmd: 'npm --prefix sdk run build' },
    { name: 'SDK tests', cmd: 'npm --prefix sdk test' },
    { name: 'Revocation policy smoke', cmd: 'npm run smoke:policy' },
    { name: 'HA resolver drill', cmd: 'npm run smoke:ha' },
    { name: 'RPC resolver smoke', cmd: 'npm run smoke:rpc' },
    { name: 'E2E smoke', cmd: 'npm run smoke:e2e' }
  ];

  const checkResults = [];
  for (const check of checks) {
    console.log(`\\n[conformance] ${check.name}`);
    const result = run(check.cmd);
    checkResults.push({ ...check, ...result });
    if (!result.ok) {
      console.error(`[conformance] FAILED: ${check.name}`);
      break;
    }
  }

  const checklist = fs.readFileSync(CHECKLIST_PATH, 'utf8');
  const mustRows = parseChecklist(checklist, 'MUST');
  const shouldRows = parseChecklist(checklist, 'SHOULD');

  const mustSummary = summarize(mustRows);
  const shouldSummary = summarize(shouldRows);

  printSection('MUST Controls', mustRows);
  printSection('SHOULD Controls', shouldRows);

  console.log('\nSummary');
  console.log(`- MUST: ${mustSummary.pass} PASS / ${mustSummary.partial} PARTIAL / ${mustSummary.fail} FAIL / ${mustSummary.unknown} UNKNOWN`);
  console.log(`- SHOULD: ${shouldSummary.pass} PASS / ${shouldSummary.partial} PARTIAL / ${shouldSummary.fail} FAIL / ${shouldSummary.unknown} UNKNOWN`);

  const technicalChecksFailed = checkResults.some((check) => !check.ok);
  const mustFailed = mustSummary.fail > 0;

  if (technicalChecksFailed) {
    const failedNames = checkResults.filter((c) => !c.ok).map((c) => c.name);
    console.error(`\n[conformance] Technical checks failed: ${failedNames.join(', ')}`);
  }

  if (mustSummary.unknown > 0) {
    console.warn(`[conformance] ${mustSummary.unknown} MUST controls have UNKNOWN status — verify manually.`);
  }

  if (shouldSummary.unknown > 0) {
    console.warn(`[conformance] ${shouldSummary.unknown} SHOULD controls have UNKNOWN status — verify manually.`);
  }

  if (technicalChecksFailed || mustFailed) {
    console.error('\n❌ RFC-001 conformance FAILED');
    if (technicalChecksFailed) {
      console.error('- At least one technical verification check failed.');
    }
    if (mustFailed) {
      console.error('- At least one MUST control is marked FAIL in checklist.');
    }
    process.exit(1);
  }

  console.log('\n✅ RFC-001 conformance PASSED');
}

main();
