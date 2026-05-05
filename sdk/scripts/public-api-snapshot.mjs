import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import ts from "typescript";

const rootDir = path.resolve(import.meta.dirname, "..");
const entrypointPath = path.join(rootDir, "src", "index.ts");
const snapshotPath = path.join(rootDir, "public-api.snapshot.txt");

function loadExportNames() {
  const sourceText = fs.readFileSync(entrypointPath, "utf8");
  const sourceFile = ts.createSourceFile(entrypointPath, sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const exportNames = new Set();

  for (const statement of sourceFile.statements) {
    if (!ts.isExportDeclaration(statement)) {
      continue;
    }

    if (!statement.exportClause || !ts.isNamedExports(statement.exportClause)) {
      continue;
    }

    for (const element of statement.exportClause.elements) {
      exportNames.add(element.name.text);
    }
  }

  return [...exportNames].sort((left, right) => left.localeCompare(right));
}

function renderSnapshot() {
  const lines = [
    "# Public API snapshot for @agentdid/sdk",
    ...loadExportNames(),
  ];

  return `${lines.join("\n")}\n`;
}

function main() {
  let mode = null;

  if (process.argv.includes("--write")) {
    mode = "write";
  } else if (process.argv.includes("--check")) {
    mode = "check";
  }

  if (!mode) {
    console.error("Usage: node ./scripts/public-api-snapshot.mjs --write | --check");
    process.exit(1);
  }

  const nextSnapshot = renderSnapshot();

  if (mode === "write") {
    fs.writeFileSync(snapshotPath, nextSnapshot, "utf8");
    console.log(`Wrote ${path.relative(rootDir, snapshotPath)}`);
    return;
  }

  const currentSnapshot = fs.existsSync(snapshotPath) ? fs.readFileSync(snapshotPath, "utf8") : "";

  if (currentSnapshot !== nextSnapshot) {
    console.error("Public API snapshot is out of date. Run `npm run api:snapshot` in sdk/ or `npm run api:snapshot` at the repo root.");
    process.exit(1);
  }

  console.log(`Public API snapshot is up to date: ${path.relative(rootDir, snapshotPath)}`);
}

main();