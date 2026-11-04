import { noRedirectFetch } from '../src/core/safe-fetch';

describe('noRedirectFetch', () => {
  const original = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = original;
  });

  it('never follows redirects and preserves the caller init', async () => {
    const spy = jest.fn().mockResolvedValue({ ok: false, status: 302 });
    globalThis.fetch = spy as unknown as typeof fetch;

    await noRedirectFetch('https://example.com/a', { method: 'PUT', headers: { a: 'b' }, redirect: 'follow' });

    expect(spy).toHaveBeenCalledWith('https://example.com/a', {
      method: 'PUT',
      headers: { a: 'b' },
      redirect: 'manual'
    });
  });
});
