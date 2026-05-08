import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import ts from "typescript";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(scriptDir, "..");
const tsconfigPath = path.join(rootDir, "tsconfig.json");
const snapshotPath = path.join(rootDir, "public-api.signature.snapshot.txt");

function collectDeclarationFiles(dirPath) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const entryPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectDeclarationFiles(entryPath));
      continue;
    }

    if (entry.isFile() && entry.name.endsWith(".d.ts")) {
      files.push(entryPath);
    }
  }

  return files.sort((left, right) => left.localeCompare(right));
}

function formatDiagnostics(diagnostics) {
  return ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCanonicalFileName: (fileName) => fileName,
    getCurrentDirectory: () => rootDir,
    getNewLine: () => "\n",
  });
}

function emitDeclarationsToTempDir() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentdid-api-signature-"));
  const configFile = ts.readConfigFile(tsconfigPath, ts.sys.readFile);

  if (configFile.error) {
    throw new Error(formatDiagnostics([configFile.error]));
  }

  const parsedConfig = ts.parseJsonConfigFileContent(
    configFile.config,
    ts.sys,
    rootDir,
    {
      declaration: true,
      declarationMap: false,
      emitDeclarationOnly: true,
      incremental: false,
      noEmit: false,
      outDir: tempDir,
      tsBuildInfoFile: undefined,
    },
    tsconfigPath,
  );

  const program = ts.createProgram({
    rootNames: parsedConfig.fileNames,
    options: parsedConfig.options,
  });
  const emitResult = program.emit();
  const diagnostics = ts
    .getPreEmitDiagnostics(program)
    .concat(emitResult.diagnostics)
    .filter((diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error);

  if (diagnostics.length > 0) {
    throw new Error(formatDiagnostics(diagnostics));
  }

  return tempDir;
}

function normalizeDeclarationText(sourceText) {
  return sourceText
    .replaceAll("\r\n", "\n")
    .replaceAll(/[ \t]+$/gm, "")
    .trimEnd();
}

function renderSnapshot() {
  const tempDir = emitDeclarationsToTempDir();

  try {
    const declarationFiles = collectDeclarationFiles(tempDir);
    const sections = ["# Public API signature snapshot for @agentdid/sdk"];

    for (const declarationFile of declarationFiles) {
      const relativePath = path.relative(tempDir, declarationFile).split(path.sep).join("/");
      const declarationText = normalizeDeclarationText(fs.readFileSync(declarationFile, "utf8"));

      sections.push("", `## ${relativePath}`, declarationText);
    }

    return `${sections.join("\n")}\n`;
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function main() {
  let mode = null;

  if (process.argv.includes("--write")) {
    mode = "write";
  } else if (process.argv.includes("--check")) {
    mode = "check";
  }

  if (!mode) {
    console.error("Usage: node ./scripts/public-api-signature-snapshot.mjs --write | --check");
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
    console.error(
      "Public API signature snapshot is out of date. Run `npm run api:signature:snapshot` in sdk/ or `npm run api:signature:snapshot:ts` at the repo root.",
    );
    process.exit(1);
  }

  console.log(`Public API signature snapshot is up to date: ${path.relative(rootDir, snapshotPath)}`);
}

main();