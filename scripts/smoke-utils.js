const { spawn, execSync } = require('node:child_process');
const http = require('node:http');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const CONTRACTS_DIR = path.join(ROOT, 'contracts');
const SDK_DIR = path.join(ROOT, 'sdk');
const EVM_DIR = path.join(ROOT, 'evm');
const SDK_DIST = path.join(SDK_DIR, 'dist');
const VERBOSE_SMOKE = process.env.VERBOSE_SMOKE === '1';
const NPM_COMMAND = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function run(command, cwd, env) {
  const safeEnv = env || {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA,
    NODE_ENV: process.env.NODE_ENV,
    SystemRoot: process.env.SystemRoot,
    TEMP: process.env.TEMP,
    TMP: process.env.TMP,
  };
  return execSync(command, {
    cwd,
    env: safeEnv,
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
        cleanup();
        reject(new Error('Timeout waiting for Hardhat node startup'));
      }
    }, timeoutMs);

    const onData = (chunk) => {
      const text = chunk.toString();
      if (text.includes('Started HTTP and WebSocket JSON-RPC server at')) {
        if (!settled) {
          settled = true;
          cleanup();
          resolve();
        }
      }
    };

    const onExit = (code) => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new Error(`Hardhat node exited before startup. Exit code: ${code}`));
      }
    };

    function cleanup() {
      clearTimeout(timeout);
      processHandle.stdout.removeListener('data', onData);
      processHandle.stderr.removeListener('data', onData);
      processHandle.removeListener('exit', onExit);
    }

    processHandle.stdout.on('data', onData);
    processHandle.stderr.on('data', onData);
    processHandle.on('exit', onExit);
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

function spawnHardhatNode() {
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

  return nodeProcess;
}

function createJsonRpcServer(handler) {
  const server = http.createServer((req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'method not allowed' }));
      return;
    }

    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const body = Buffer.concat(chunks).toString('utf8') || '{}';
        const payload = JSON.parse(body);
        const response = await handler(payload);
        res.writeHead(response.httpStatus || 200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(response.payload));
      } catch (error) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32000, message: error instanceof Error ? error.message : String(error) }
        }));
      }
    });
  });

  return {
    start: () => new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve(server.address().port));
    }),
    stop: () => new Promise((resolve) => server.close(() => resolve()))
  };
}

function smokeEnv(extraVars = {}) {
  const base = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA,
    NODE_ENV: process.env.NODE_ENV,
    SystemRoot: process.env.SystemRoot,
    TEMP: process.env.TEMP,
    TMP: process.env.TMP,
  };
  return { ...base, ...extraVars };
}

module.exports = {
  ROOT,
  CONTRACTS_DIR,
  SDK_DIR,
  EVM_DIR,
  SDK_DIST,
  VERBOSE_SMOKE,
  NPM_COMMAND,
  run,
  waitForHardhatNode,
  stopProcessTree,
  parseDeployedAddress,
  spawnHardhatNode,
  createJsonRpcServer,
  smokeEnv,
};
