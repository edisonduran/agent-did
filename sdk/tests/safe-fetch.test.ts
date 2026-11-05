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
    const spy = jest.fn().mockResolvedValue({ ok: false, status: 302 });
    globalThis.fetch = spy as unknown as typeof fetch;
    const lookup = jest.fn();

    await createSafeFetch({}, lookup)('https://93.184.216.34/a', { method: 'PUT', headers: { a: 'b' }, redirect: 'follow' });
    await createSafeFetch({ allowPrivateTargets: true }, lookup)('http://internal.example.com/b');

    expect(spy).toHaveBeenNthCalledWith(1, 'https://93.184.216.34/a', {
      method: 'PUT',
      headers: { a: 'b' },
      redirect: 'manual'
    });
    expect(spy).toHaveBeenNthCalledWith(2, 'http://internal.example.com/b', { redirect: 'manual' });
    expect(lookup).not.toHaveBeenCalled();
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
