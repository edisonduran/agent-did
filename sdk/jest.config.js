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
  },
  transformIgnorePatterns: [
    "node_modules/(?!@noble/curves|@noble/hashes)"
  ]
};