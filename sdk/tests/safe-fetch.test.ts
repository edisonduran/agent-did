import { assertResolvedTargetAllowed, createSafeFetch } from '../src/core/safe-fetch';

const lookupTo = (...addresses: string[]) => async () => addresses.map((address) => ({ address }));

describe('createSafeFetch', () => {
  const original = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = original;
  });

  it('never follows redirects and preserves the caller init', async () => {
    const spy = jest.fn().mockResolvedValue({ ok: false, status: 302 });
    globalThis.fetch = spy as unknown as typeof fetch;

    await createSafeFetch({}, lookupTo('93.184.216.34'))(
      'https://example.com/a',
      { method: 'PUT', headers: { a: 'b' }, redirect: 'follow' }
    );

    expect(spy).toHaveBeenCalledWith('https://example.com/a', {
      method: 'PUT',
      headers: { a: 'b' },
      redirect: 'manual'
    });
  });

  it('does not send the request when the host resolves to a private address', async () => {
    const spy = jest.fn();
    globalThis.fetch = spy as unknown as typeof fetch;

    await expect(createSafeFetch({}, lookupTo('169.254.169.254'))('https://metadata.example.com/'))
      .rejects.toThrow('private/reserved');
    expect(spy).not.toHaveBeenCalled();
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
