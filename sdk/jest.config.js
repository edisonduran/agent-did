const { createDefaultPreset } = require("ts-jest");

const tsJestTransformCfg = createDefaultPreset().transform;

/** @type {import("jest").Config} **/
module.exports = {
  testEnvironment: "node",
  transform: {
    ...tsJestTransformCfg,
    "^.+\\.(js|jsx)$": "babel-jest",
  },
  coverageThreshold: {
    global: {
      lines: 85,
    },
    // C-QA-2 (docs/RELEASE-1.0-CRITERIA.md): every line of the crypto, signing, verification and resolver
    // modules, per file. A defensive branch no input can reach carries an `istanbul ignore` comment with the reason.
    "./src/crypto/": { lines: 100 },
    "./src/verification/": { lines: 100 },
    "./src/resolver/": { lines: 100 },
    "./src/http-signatures/": { lines: 100 },
    "./src/core/http-signatures.ts": { lines: 100 },
    "./src/core/message-signing.ts": { lines: 100 },
  },
  transformIgnorePatterns: [
    "node_modules/(?!@noble/curves|@noble/hashes|jose)"
  ]
};