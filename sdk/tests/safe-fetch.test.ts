import http from 'node:http';
import { AddressInfo } from 'node:net';
import { assertResolvedTargetAllowed, createSafeFetch } from '../src/core/safe-fetch';

const lookupTo = (...addresses: string[]) => async () => addresses.map((address) => ({ address }));

describe('createSafeFetch', () => {
  const original = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = original;
  });

  it('uses the platform fetch without following redirects for IP literals and allowed private targets', async () => {
    const spy = jest.fn().mockImplementation(async () => new Response(null, { status: 302 }));
    globalThis.fetch = spy as unknown as typeof fetch;
    const lookup = jest.fn();

    const first = await createSafeFetch({}, lookup)('https://93.184.216.34/a', {
      method: 'PUT',
      headers: { a: 'b', 'Accept-Encoding': 'gzip' },
      redirect: 'follow'
    });
    await createSafeFetch({ allowPrivateTargets: true }, lookup)('http://internal.example.com/b');

    expect(first.status).toBe(302);
    expect(spy).toHaveBeenNthCalledWith(1, 'https://93.184.216.34/a', {
      method: 'PUT',
      headers: { a: 'b', 'accept-encoding': 'identity' },
      redirect: 'manual',
      signal: expect.any(AbortSignal)
    });
    expect(spy).toHaveBeenNthCalledWith(2, 'http://internal.example.com/b', {
      headers: { 'accept-encoding': 'identity' },
      redirect: 'manual',
      signal: expect.any(AbortSignal)
    });
    expect(lookup).not.toHaveBeenCalled();
  });

  it('rejects limits that are not positive integers', () => {
    expect(() => createSafeFetch({ timeoutMs: 0 })).toThrow(TypeError);
    expect(() => createSafeFetch({ timeoutMs: 1.5 })).toThrow(TypeError);
    expect(() => createSafeFetch({ maxResponseBytes: -1 })).toThrow(TypeError);
    expect(() => createSafeFetch({ maxResponseBytes: Number.POSITIVE_INFINITY })).toThrow(TypeError);
  });

  describe('limits, on both request paths', () => {
    const LIMIT = 1000;
    let server: http.Server;
    let port: number;
    let acceptEncodings: Array<string | undefined>;
    const timers = new Set<NodeJS.Timeout>();

    beforeEach(async () => {
      acceptEncodings = [];
      server = http.createServer((req, res) => {
        acceptEncodings.push(String(req.headers['accept-encoding']));
        switch (req.url) {
          case '/hang':
            return; // never answers
          case '/trickle': {
            res.writeHead(200, { 'content-type': 'application/json' });
            const timer = setInterval(() => res.write(' '), 20);
            timers.add(timer);
            req.on('close', () => clearInterval(timer));
            return;
          }
          case '/declared-too-large':
            res.writeHead(200, { 'content-length': String(LIMIT + 1) });
            res.end('x'.repeat(LIMIT + 1));
            return;
          case '/streamed-too-large':
            res.writeHead(200, { 'content-type': 'application/json' });
            res.write('x'.repeat(LIMIT));
            res.end('x');
            return;
          case '/at-limit':
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ pad: 'x'.repeat(LIMIT - 10) }));
            return;
          case '/gzip':
            res.writeHead(200, { 'content-encoding': 'gzip' });
            res.end('not really gzip');
            return;
          default:
            res.writeHead(404);
            res.end();
        }
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      port = (server.address() as AddressInfo).port;
    });

    afterEach(async () => {
      timers.forEach((timer) => clearInterval(timer));
      timers.clear();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    const paths: Array<[string, (path: string, options: { timeoutMs?: number; maxResponseBytes?: number }) => Promise<any>]> = [
      [
        'pinned connection',
        (path, options) =>
          createSafeFetch(options, async () => [{ address: '127.0.0.1' }], () => false)(`http://pinned.test:${port}${path}`)
      ],
      [
        'platform fetch',
        (path, options) => createSafeFetch({ ...options, allowPrivateTargets: true })(`http://127.0.0.1:${port}${path}`)
      ]
    ];

    describe.each(paths)('%s', (_name, request) => {
      it('asks for an unencoded body and accepts a body at the size limit', async () => {
        const response = await request('/at-limit', { maxResponseBytes: LIMIT });

        expect(response.ok).toBe(true);
        expect(((await response.json()) as { pad: string }).pad).toHaveLength(LIMIT - 10);
        expect(acceptEncodings).toEqual(['identity']);
      });

      it('gives up when the server does not answer within the deadline', async () => {
        await expect(request('/hang', { timeoutMs: 200 })).rejects.toThrow('exceeded the 200 ms deadline');
      });

      it('applies the deadline to the whole body, so a server sending bytes slowly cannot extend it', async () => {
        await expect(request('/trickle', { timeoutMs: 300 })).rejects.toThrow('exceeded the 300 ms deadline');
      });

      it('rejects a body larger than the limit, declared or streamed', async () => {
        await expect(request('/declared-too-large', { maxResponseBytes: LIMIT })).rejects.toThrow(
          `exceeds the ${LIMIT}-byte limit`
        );
        await expect(request('/streamed-too-large', { maxResponseBytes: LIMIT })).rejects.toThrow(
          `exceeds the ${LIMIT}-byte limit`
        );
      });

      it('rejects an encoded body, since its decoded size is not bounded by the limit', async () => {
        await expect(request('/gzip', {})).rejects.toThrow('Content-Encoding "gzip"');
      });
    });
  });

  describe('against a local server', () => {
    let server: http.Server;
    let port: number;
    let received: Array<{ method?: string; url?: string; host?: string; body: string }>;

    beforeEach(async () => {
      received = [];
      server = http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', () => {
          received.push({ method: req.method, url: req.url, host: req.headers.host, body: Buffer.concat(chunks).toString() });
          if (req.url === '/redirect') {
            res.writeHead(302, { location: 'http://169.254.169.254/' });
            res.end();
            return;
          }
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        });
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      port = (server.address() as AddressInfo).port;
    });

    afterEach(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it('connects to the validated address, resolves once, and keeps the Host header', async () => {
      const lookup = jest.fn().mockResolvedValue([{ address: '127.0.0.1' }]);
      const safeFetch = createSafeFetch({}, lookup, () => false);

      const response = await safeFetch(`http://pinned.test:${port}/doc?x=1`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"a":1}'
      });

      expect(response.ok).toBe(true);
      expect(await response.json()).toEqual({ ok: true });
      expect(lookup).toHaveBeenCalledTimes(1);
      expect(received).toEqual([
        { method: 'POST', url: '/doc?x=1', host: `pinned.test:${port}`, body: '{"a":1}' }
      ]);
    });

    it('does not follow redirects', async () => {
      const safeFetch = createSafeFetch({}, async () => [{ address: '127.0.0.1' }], () => false);

      const response = await safeFetch(`http://pinned.test:${port}/redirect`);

      expect(response.status).toBe(302);
      expect(response.ok).toBe(false);
      expect(response.headers.get('location')).toBe('http://169.254.169.254/');
      expect(received).toHaveLength(1);
    });

    it.each([['127.0.0.1'], ['10.0.0.5'], ['169.254.169.254'], ['fd00::1']])(
      'refuses to connect when the name resolves to %s',
      async (address) => {
        const safeFetch = createSafeFetch({}, async () => [{ address }]);

        await expect(safeFetch(`http://rebind.test:${port}/`)).rejects.toThrow('private/reserved');
        expect(received).toHaveLength(0);
      }
    );

    it('opens its own connection instead of reusing a pooled socket to the same host', async () => {
      // Other code in the process talks to the same host:port through the global keep-alive agent
      await new Promise<void>((resolve, reject) => {
        http
          .get(
            { host: 'pooled.test', port, path: '/app', agent: http.globalAgent, lookup: (_h, _o, cb) => cb(null, [{ address: '127.0.0.1', family: 4 }] as never, 4) },
            (res) => {
              res.resume();
              res.on('end', resolve);
            }
          )
          .on('error', reject);
      });

      await expect(createSafeFetch({}, lookupTo('127.0.0.1'))(`http://pooled.test:${port}/did.jsonl`)).rejects.toThrow(
        'private/reserved'
      );
      expect(received.map(({ url }) => url)).toEqual(['/app']);
    });

    it('refuses when any resolved address is private, and when the name does not resolve', async () => {
      await expect(
        createSafeFetch({}, async () => [{ address: '93.184.216.34' }, { address: '127.0.0.1' }])(`http://mixed.test:${port}/`)
      ).rejects.toThrow('private/reserved');
      await expect(
        createSafeFetch({}, async () => { throw new Error('ENOTFOUND'); })(`http://nope.test:${port}/`)
      ).rejects.toThrow('could not resolve');
      expect(received).toHaveLength(0);
    });
  });
});

describe('assertResolvedTargetAllowed', () => {
  it.each([
    ['10.0.0.5'], ['127.0.0.1'], ['100.64.0.1'], ['fd00::1'], ['fe80::1'], ['::1'], ['::ffff:10.0.0.1'],
  ])('rejects a name that resolves to %s', async (address) => {
    await expect(assertResolvedTargetAllowed('https://app.example.com/', {}, lookupTo(address)))
      .rejects.toThrow('private/reserved');
  });

  it('rejects when any of several addresses is private', async () => {
    await expect(assertResolvedTargetAllowed('https://app.example.com/', {}, lookupTo('93.184.216.34', '10.0.0.5')))
      .rejects.toThrow('private/reserved');
  });

  it('allows names that resolve only to public addresses', async () => {
    await expect(assertResolvedTargetAllowed(
      'https://app.example.com/', {}, lookupTo('93.184.216.34', '2606:4700:4700::1111')
    )).resolves.toBeUndefined();
  });

  it('fails closed when the name cannot be resolved or has no addresses', async () => {
    const failing = async () => { throw new Error('ENOTFOUND'); };
    await expect(assertResolvedTargetAllowed('https://nope.example.com/', {}, failing)).rejects.toThrow('could not resolve');
    await expect(assertResolvedTargetAllowed('https://nope.example.com/', {}, lookupTo())).rejects.toThrow('private/reserved');
  });

  it('skips the lookup for IP literals and when private targets are allowed', async () => {
    const lookup = jest.fn();
    await assertResolvedTargetAllowed('https://93.184.216.34/', {}, lookup);
    await assertResolvedTargetAllowed('https://[2606:4700:4700::1111]/', {}, lookup);
    await assertResolvedTargetAllowed('https://internal.example.com/', { allowPrivateTargets: true }, lookup);
    expect(lookup).not.toHaveBeenCalled();
  });
});
