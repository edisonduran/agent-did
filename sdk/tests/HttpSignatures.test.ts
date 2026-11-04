import { ed25519 } from '@noble/curves/ed25519';
import { computeContentDigest } from '../src/core/http-profile';
import {
  buildSignatureBase,
  HttpSignatureError,
  parseSignatureHeader,
  parseSignatureInputHeader,
  serializeSignatureInput,
} from '../src/core/http-signatures';

// RFC 9421 Appendix B.1.4 (test-key-ed25519) and B.2 (test-request).
const TEST_KEY_D = 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU';
const TEST_KEY_X = 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs';
const TEST_REQUEST = {
  method: 'POST',
  url: 'https://example.com/foo?param=Value&Pet=dog',
  headers: {
    Host: 'example.com',
    Date: 'Tue, 20 Apr 2021 02:07:55 GMT',
    'Content-Type': 'application/json',
    'Content-Digest':
      'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
    'Content-Length': '18',
  },
};
const B26_INPUT =
  'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"';
const B26_SIGNATURE =
  'sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:';
const B26_BASE = [
  '"date": Tue, 20 Apr 2021 02:07:55 GMT',
  '"@method": POST',
  '"@path": /foo',
  '"@authority": example.com',
  '"content-type": application/json',
  '"content-length": 18',
  '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
].join('\n');

const b64url = (value: string) => new Uint8Array(Buffer.from(value, 'base64url'));

describe('RFC 9421 primitives', () => {
  it('reproduces the Appendix B.2.6 signature base and Ed25519 signature byte for byte', () => {
    const input = parseSignatureInputHeader(B26_INPUT).get('sig-b26')!;
    const base = buildSignatureBase(TEST_REQUEST, input);
    expect(base).toBe(B26_BASE);

    const privateKey = b64url(TEST_KEY_D);
    expect(Buffer.from(ed25519.getPublicKey(privateKey)).toString('base64url')).toBe(TEST_KEY_X);
    const signature = ed25519.sign(new TextEncoder().encode(base), privateKey);
    expect(Buffer.from(signature)).toEqual(Buffer.from(parseSignatureHeader(B26_SIGNATURE).get('sig-b26')!));
    expect(ed25519.verify(signature, new TextEncoder().encode(base), b64url(TEST_KEY_X))).toBe(true);
  });

  it('derives @query, @target-uri, @scheme and @request-target', () => {
    const input = parseSignatureInputHeader('s=("@query" "@target-uri" "@scheme" "@request-target");created=1').get('s')!;
    expect(buildSignatureBase(TEST_REQUEST, input).split('\n').slice(0, 4)).toEqual([
      '"@query": ?param=Value&Pet=dog',
      '"@target-uri": https://example.com/foo?param=Value&Pet=dog',
      '"@scheme": https',
      '"@request-target": /foo?param=Value&Pet=dog',
    ]);
    const noQuery = { ...TEST_REQUEST, url: 'https://example.com/' };
    expect(buildSignatureBase(noQuery, parseSignatureInputHeader('s=("@query")').get('s')!)).toMatch(/^"@query": \?\n/u);
  });

  it('round-trips parameters with canonical serialization', () => {
    const input = parseSignatureInputHeader(
      'sig1=("@method" "content-digest");created=1;expires=2;nonce="a\\"b\\\\c";keyid="did:x#k";alg="ed25519";tag="agent-did";flag;neg=-5;tok=abc'
    ).get('sig1')!;
    expect(serializeSignatureInput(input)).toBe(
      '("@method" "content-digest");created=1;expires=2;nonce="a\\"b\\\\c";keyid="did:x#k";alg="ed25519";tag="agent-did";flag;neg=-5;tok=abc'
    );
  });

  it('parses dictionaries with several members and whitespace', () => {
    const parsed = parseSignatureInputHeader('a=("@method");created=1 ,  b=("date");created=2');
    expect([...parsed.keys()]).toEqual(['a', 'b']);
    expect(parseSignatureHeader('a=:AAAA:, b=:AQID:').get('b')).toEqual(new Uint8Array([1, 2, 3]));
  });

  it.each([
    ['unterminated string', 's=("@method);created=1'],
    ['bad escape', 's=("a\n")'],
    ['component parameters', 's=("@query-param";name="x")'],
    ['duplicate parameter', 's=("@method");created=1;created=2'],
    ['decimal', 's=("@method");created=1.5'],
    ['uppercase key', 'S=("@method")'],
    ['trailing comma', 's=("@method"),'],
    ['missing value', 's'],
    ['not an inner list', 's=1'],
    ['token component', 's=(@method)'],
    ['byte sequence parameter', 's=("@method");created=:AAAA:'],
    ['date parameter', 's=("@method");created=@1'],
  ])('rejects malformed Signature-Input (%s)', (_label, value) => {
    expect(() => parseSignatureInputHeader(value)).toThrow(HttpSignatureError);
  });

  it.each([['bad base64', 's=:@@@@:'], ['unterminated', 's=:AAAA'], ['not bytes', 's="x"'], ['parameters', 's=:AAAA:;x=1'], ['inner list', 's=(:AAAA:)']])(
    'rejects malformed Signature (%s)',
    (_label, value) => {
      expect(() => parseSignatureHeader(value)).toThrow(HttpSignatureError);
    }
  );

  it('does not mistake semicolons inside strings for parameters', () => {
    const parsed = parseSignatureInputHeader('s=("a;b");keyid="x;\\"y;z";tag="t"');
    expect(parsed.get('s')?.params).toEqual([['keyid', 'x;"y;z'], ['tag', 't']]);
  });

  it.each([
    ['missing header', 's=("x-missing")'],
    ['duplicate component', 's=("@method" "@method")'],
    ['uppercase component', 's=("Date")'],
    ['unknown derived component', 's=("@status")'],
  ])('rejects an invalid signature base (%s)', (_label, value) => {
    expect(() => buildSignatureBase(TEST_REQUEST, parseSignatureInputHeader(value).get('s')!)).toThrow(HttpSignatureError);
  });

  it('combines repeated header lines and trims values', () => {
    const request = { method: 'GET', url: 'https://example.com/', headers: { 'X-Multi': ['  a ', 'b'] } };
    expect(buildSignatureBase(request, parseSignatureInputHeader('s=("x-multi")').get('s')!)).toMatch(
      /^"x-multi": a, b\n/u
    );
  });
});

// RFC 9530 example: the SHA-256 Content-Digest of the body `{"hello": "world"}`.
describe('RFC 9530 Content-Digest', () => {
  it('matches the RFC 9530 SHA-256 example', () => {
    expect(computeContentDigest('{"hello": "world"}')).toBe(
      'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:'
    );
  });

  it('digests an absent body as the empty string (SHA-256 of zero bytes)', () => {
    expect(computeContentDigest()).toBe('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:');
  });
});
