const { execFileSync } = require("node:child_process");

const RULES = [
  {
    name: "LangChain integrations",
    watchedPrefixes: ["integrations/langchain/", "integrations/langchain-python/"],
    requiredDocs: [
      "docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md",
      "docs/F1-03-LangChain-Integration-Parity-Review-Checklist.md",
    ],
  },
  {
    name: "CrewAI integration",
    watchedPrefixes: ["integrations/crewai/"],
    requiredDocs: [
      "docs/F2-05-CrewAI-Implementation-Checklist.md",
      "docs/F2-05-CrewAI-Integration-Review-Checklist.md",
    ],
  },
  {
    name: "Semantic Kernel integration",
    watchedPrefixes: ["integrations/semantic-kernel/"],
    requiredDocs: [
      "docs/F2-04-Semantic-Kernel-Implementation-Checklist.md",
      "docs/F2-04-Semantic-Kernel-Integration-Review-Checklist.md",
    ],
  },
];

function main() {
  const baseRef = normalizeRef(process.argv[2]);
  const headRef = normalizeRef(process.argv[3]) || "HEAD";
  const changedFiles = getChangedFiles(baseRef, headRef);

  if (changedFiles.length === 0) {
    console.log("No changed files detected for integration governance check.");
    return;
  }

  const failures = [];

  for (const rule of RULES) {
    const touchedIntegration = changedFiles.some((filePath) =>
      rule.watchedPrefixes.some((prefix) => filePath.startsWith(prefix))
    );

    if (!touchedIntegration) {
      continue;
    }

    const missingDocs = rule.requiredDocs.filter((docPath) => !changedFiles.includes(docPath));
    if (missingDocs.length > 0) {
      failures.push({ rule, missingDocs });
    }
  }

  if (failures.length > 0) {
    console.error("Integration governance check failed.");
    console.error("Changed files:");
    for (const filePath of changedFiles) {
      console.error(`- ${filePath}`);
    }
    console.error("");
    for (const failure of failures) {
      console.error(`${failure.rule.name} changed without required governance updates:`);
      for (const docPath of failure.missingDocs) {
        console.error(`- ${docPath}`);
      }
      console.error("");
    }
    process.exit(1);
  }

  console.log("Integration governance check passed.");
}

function getChangedFiles(baseRef, headRef) {
  const output = baseRef
    ? runGit(["diff", "--name-only", "--diff-filter=ACMR", baseRef, headRef])
    : runGit(["diff-tree", "--no-commit-id", "--name-only", "-r", headRef]);

  return output
    .split(/\r?\n/)
    .map((entry) => entry.trim().replaceAll("\\", "/"))
    .filter(Boolean);
}

function normalizeRef(value) {
  if (!value || /^0+$/.test(value)) {
    return "";
  }

  try {
    runGit(["rev-parse", "--verify", value]);
    return value;
  } catch {
    return "";
  }
}

function runGit(args) {
  return execFileSync("git", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

main();