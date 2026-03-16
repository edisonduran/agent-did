const { spawn, execSync } = require('child_process');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CONTRACTS_DIR = path.join(ROOT, 'contracts');
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

    run('npm run build', CONTRACTS_DIR);
    const deployOutput = run('npm run deploy:local', CONTRACTS_DIR);
    const deployedAddress = parseDeployedAddress(deployOutput);

    run('npm run export:abi', CONTRACTS_DIR);

    run('npx hardhat run scripts/revocation-policy-check.js --network localhost', CONTRACTS_DIR, {
      ...process.env,
      AGENT_REGISTRY_ADDRESS: deployedAddress
    });

    console.log('✅ Revocation policy smoke completed successfully');
  } finally {
    stopProcessTree(nodeProcess.pid);
  }
}

main().catch((error) => {
  console.error('❌ Revocation policy smoke failed');
  console.error(error);
  process.exit(1);
});
