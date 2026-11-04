const {
  CONTRACTS_DIR,
  SDK_DIR,
  EVM_DIR,
  run,
  waitForHardhatNode,
  stopProcessTree,
  parseDeployedAddress,
  spawnHardhatNode,
  smokeEnv,
} = require('./smoke-utils');

async function main() {
  const nodeProcess = spawnHardhatNode();

  try {
    await waitForHardhatNode(nodeProcess);

    console.log('\n[smoke] Building contracts...');
    run('npm run build', CONTRACTS_DIR);

    console.log('[smoke] Deploying AgentRegistry on localhost...');
    const deployOutput = run('npm run deploy:local', CONTRACTS_DIR);
    const deployedAddress = parseDeployedAddress(deployOutput);
    console.log(`[smoke] Deployed at ${deployedAddress}`);

    console.log('[smoke] Exporting ABI to SDK examples...');
    run('npm run export:abi', CONTRACTS_DIR);

    console.log('[smoke] Building SDK and EVM adapter...');
    run('npm run build', SDK_DIR);
    run('npm install --no-audit --no-fund', EVM_DIR);
    run('npm run build', EVM_DIR);

    console.log('[smoke] Running SDK end-to-end scenario...');
    run('node examples/e2e-smoke.js', EVM_DIR, smokeEnv({
      RPC_URL: 'http://127.0.0.1:8545',
      AGENT_REGISTRY_ADDRESS: deployedAddress,
      CREATOR_ACCOUNT_INDEX: '1'
    }));

    console.log('\n✅ E2E smoke test completed successfully');
  } finally {
    stopProcessTree(nodeProcess.pid);
  }
}

main().catch((error) => {
  console.error('\n❌ E2E smoke test failed');
  console.error(error);
  process.exit(1);
});
