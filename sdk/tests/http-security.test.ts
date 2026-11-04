import { validateHttpTarget } from '../src/core/http-security';

describe('validateHttpTarget — SSRF protection', () => {
  // ── Allowed URLs ─────────────────────────────────────────────────
  it('should allow public HTTPS URLs', () => {
    expect(() => validateHttpTarget('https://api.example.com/v1')).not.toThrow();
  });

  it('should allow public HTTP URLs', () => {
    expect(() => validateHttpTarget('http://api.example.com/v1')).not.toThrow();
  });

  // ── Blocked protocols ────────────────────────────────────────────
  it('should reject ftp protocol', () => {
    expect(() => validateHttpTarget('ftp://files.example.com/doc')).toThrow('Unsupported protocol');
  });

  it('should reject file protocol', () => {
    expect(() => validateHttpTarget('file:///etc/passwd')).toThrow('Unsupported protocol');
  });

  // ── Embedded credentials ─────────────────────────────────────────
  it('should reject URLs with embedded credentials', () => {
    expect(() => validateHttpTarget('https://user:pass@example.com/')).toThrow('embedded credentials');
  });

  // ── Loopback ─────────────────────────────────────────────────────
  it('should block 127.0.0.1', () => {
    expect(() => validateHttpTarget('https://127.0.0.1/api')).toThrow('private/reserved');
  });

  it('should block 127.0.0.2 (full /8)', () => {
    expect(() => validateHttpTarget('https://127.0.0.2/api')).toThrow('private/reserved');
  });

  it('should block localhost', () => {
    expect(() => validateHttpTarget('http://localhost:3000/')).toThrow('private/reserved');
  });

  it('should block IPv6 loopback ::1', () => {
    expect(() => validateHttpTarget('http://[::1]:8080/api')).toThrow('private/reserved');
  });

  it('should block IPv6-mapped loopback ::ffff:127.0.0.1', () => {
    expect(() => validateHttpTarget('http://[::ffff:127.0.0.1]/api')).toThrow('private/reserved');
  });

  // ── Zero address ─────────────────────────────────────────────────
  it('should block 0.0.0.0', () => {
    expect(() => validateHttpTarget('http://0.0.0.0/')).toThrow('private/reserved');
  });

  // ── Private ranges ───────────────────────────────────────────────
  it('should block 10.x.x.x', () => {
    expect(() => validateHttpTarget('http://10.0.1.5/api')).toThrow('private/reserved');
  });

  it('should block 172.16.x.x', () => {
    expect(() => validateHttpTarget('http://172.16.0.1/api')).toThrow('private/reserved');
  });

  it('should block 172.31.x.x', () => {
    expect(() => validateHttpTarget('http://172.31.255.255/api')).toThrow('private/reserved');
  });

  it('should block 192.168.x.x', () => {
    expect(() => validateHttpTarget('http://192.168.1.100/')).toThrow('private/reserved');
  });

  // ── Metadata endpoint (link-local) ──────────────────────────────
  it('should block cloud metadata endpoint 169.254.169.254', () => {
    expect(() => validateHttpTarget('http://169.254.169.254/latest/meta-data/')).toThrow('private/reserved');
  });

  it('should block IPv6-mapped metadata endpoint ::ffff:169.254.169.254', () => {
    expect(() => validateHttpTarget('http://[::ffff:169.254.169.254]/metadata/instance')).toThrow('private/reserved');
  });

  // ── Ranges beyond loopback/RFC1918 ───────────────────────────────
  it.each([
    'http://[fc00::1]/', 'http://[fd12:3456::1]/', 'http://[fe80::1]/', 'http://[::]/',
    'http://[ff02::1]/', 'http://[::ffff:7f00:1]/', 'http://[::ffff:a9fe:a9fe]/',
    'http://[64:ff9b::a9fe:a9fe]/', 'http://[2002:a9fe:a9fe::1]/', 'http://[2001:db8::1]/',
    'http://0.1.2.3/', 'http://100.64.0.1/', 'http://100.127.255.255/', 'http://192.0.0.1/',
    'http://198.18.0.1/', 'http://224.0.0.1/', 'http://240.0.0.1/', 'http://255.255.255.255/',
    'http://localhost./', 'http://app.localhost/', 'http://2130706433/', 'http://0x7f.1/',
  ])('should block %s', (url) => {
    expect(() => validateHttpTarget(url)).toThrow('private/reserved');
  });

  it.each([
    'http://[2606:4700:4700::1111]/', 'http://8.8.8.8/', 'http://100.63.255.255/',
    'http://100.128.0.1/', 'http://172.32.0.1/', 'https://localhost.example.com/',
  ])('should allow public %s', (url) => {
    expect(() => validateHttpTarget(url)).not.toThrow();
  });

  // ── allowPrivateTargets flag ─────────────────────────────────────
  it('should allow private targets when allowPrivateTargets is true', () => {
    const opts = { allowPrivateTargets: true };
    expect(() => validateHttpTarget('http://127.0.0.1/api', opts)).not.toThrow();
    expect(() => validateHttpTarget('http://10.0.0.1/api', opts)).not.toThrow();
    expect(() => validateHttpTarget('http://192.168.1.1/api', opts)).not.toThrow();
    expect(() => validateHttpTarget('http://169.254.169.254/latest/', opts)).not.toThrow();
  });

  it('should still block embedded credentials even with allowPrivateTargets', () => {
    expect(() => validateHttpTarget('https://user:pass@127.0.0.1/', { allowPrivateTargets: true }))
      .toThrow('embedded credentials');
  });

  it('should still block non-http protocols even with allowPrivateTargets', () => {
    expect(() => validateHttpTarget('ftp://127.0.0.1/', { allowPrivateTargets: true }))
      .toThrow('Unsupported protocol');
  });
});
