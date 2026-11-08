const http = require('node:http');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const SDK_DIR = path.join(ROOT, 'sdk');
const SDK_DIST = path.join(SDK_DIR, 'dist');

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

module.exports = {
  ROOT,
  SDK_DIR,
  SDK_DIST,
  createJsonRpcServer,
};
