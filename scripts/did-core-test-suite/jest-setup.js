/**
 * Jest setup file loaded by scripts/did-core-test-suite/run.js into the W3C DID Core test suite.
 *
 * The suite's spec files read `global.systemSuiteConfig` and use its `didMethods` instead of the
 * implementations bundled in the suite. This hands them the implementation entries that run.js wrote.
 */
const fs = require('fs');

const configPath = process.env.AGENT_DID_CORE_SUITE_CONFIG;
if (!configPath) {
  throw new Error('AGENT_DID_CORE_SUITE_CONFIG is not set; run scripts/did-core-test-suite/run.js');
}
global.systemSuiteConfig = { didMethods: JSON.parse(fs.readFileSync(configPath, 'utf8')) };
