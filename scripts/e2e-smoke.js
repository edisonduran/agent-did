const { spawn, execSync } = require('child_process');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CONTRACTS_DIR = path.join(ROOT, 'contracts');
const SDK_DIR = path.join(ROOT, 'sdk');
const VERBOSE_SMOKE = process.env.VERBOSE_SMOKE === '1';
const NPM_COMMAND = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function run(command, cwd, env = process.env) {
  return execSync(command, {
    cwd,
    env,
    stdio: VERBOSE_SMOKE ? 'inherit' : 'pipe',
    encoding: 'utf8'
  });
}

function waitForHardhatNode(processHandle, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        reject(new Error('Timeout waiting for Hardhat node startup'));
      }
    }, timeoutMs);

    const onData = (chunk) => {
      const text = chunk.toString();
      if (text.includes('Started HTTP and WebSocket JSON-RPC server at')) {
        if (!settled) {
          settled = true;
          clearTimeout(timeout);
          resolve();
        }
      }
    };

    processHandle.stdout.on('data', onData);
    processHandle.stderr.on('data', onData);
    processHandle.on('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`Hardhat node exited before startup. Exit code: ${code}`));
      }
    });
  });
}

function stopProcessTree(pid) {
  if (process.platform === 'win32') {
    try {
      execSync(`taskkill /PID ${pid} /T /F`, { stdio: 'ignore' });
    } catch {
      // noop
    }
    return;
  }

  try {
    process.kill(-pid, 'SIGTERM');
  } catch {
    // noop
  }
}

function parseDeployedAddress(output) {
  const match = output.match(/AgentRegistry deployed at:\s*(0x[a-fA-F0-9]{40})/);
  if (!match) {
    throw new Error(`Unable to parse deployed address from output:\n${output}`);
  }
  return match[1];
}

async function main() {
  const nodeProcess = spawn(NPM_COMMAND, ['run', 'node:local'], {
    cwd: CONTRACTS_DIR,
    shell: process.platform === 'win32',
    detached: process.platform !== 'win32',
    stdio: ['ignore', 'pipe', 'pipe']
  });

  if (VERBOSE_SMOKE) {
    nodeProcess.stdout.on('data', (chunk) => process.stdout.write(`[hardhat] ${chunk}`));
    nodeProcess.stderr.on('data', (chunk) => process.stderr.write(`[hardhat] ${chunk}`));
  }

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

    console.log('[smoke] Building SDK...');
    run('npm run build', SDK_DIR);

    console.log('[smoke] Running SDK end-to-end scenario...');
    run('node examples/e2e-smoke.js', SDK_DIR, {
      ...process.env,
      RPC_URL: 'http://127.0.0.1:8545',
      AGENT_REGISTRY_ADDRESS: deployedAddress,
      CREATOR_ACCOUNT_INDEX: '1'
    });

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
