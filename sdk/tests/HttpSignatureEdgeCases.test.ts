import {
  buildSignatureBase,
  HttpSignatureError,
  parseSignatureInputHeader,
  requestUrlFormProblem,
  serializeSignature,
  serializeSignatureInput
} from '../src/core/http-signatures';
import { signatureResultForKey } from '../src/verification/key-at-time';
import { verifyWithActiveKeys } from '../src/verification/signature';
import type { AgentDIDDocument, KeyAtTimeResult } from '../src';

// Edge cases of the RFC 9421 module and the signature checks that the protocol tests do not reach (C-QA-2).

describe('Structured Field serialization of signature inputs', () => {
  const input = (params: Array<[string, unknown]>, components: unknown[] = ['@method']) =>
    serializeSignatureInput({ components, params } as Parameters<typeof serializeSignatureInput>[0]);

  it('serializes booleans and tokens, and rejects values Structured Fields cannot carry', () => {
    expect(input([['flag', true], ['off', false], ['alg', { token: 'ed25519' }]])).toBe('("@method");flag;off=?0;alg=ed25519');
    expect(() => input([['nonce', 'café']])).toThrow(HttpSignatureError);
    expect(() => input([['created', 1.5]])).toThrow('integers');
    expect(() => input([['created', 1e16]])).toThrow('integers');
    expect(() => input([['alg', { token: '1bad' }]])).toThrow('token');
    expect(() => input([['Bad', 1]])).toThrow('key');
  });

  it('rejects an invalid signature label', () => {
    expect(() => serializeSignature('Sig', new Uint8Array(64))).toThrow('label');
  });
});

describe('parseSignatureInputHeader', () => {
  it('does not count a semicolon inside a string as a parameter', () => {
    const parsed = parseSignatureInputHeader('sig1=("@method");nonce="a;b";tag="agent-did"');
    expect(parsed.get('sig1')?.params).toEqual([
      ['nonce', 'a;b'],
      ['tag', 'agent-did']
    ]);
  });

  it('rejects covered components that are not strings', () => {
    expect(() => parseSignatureInputHeader('sig1=(1 "@method")')).toThrow('must be strings');
  });
});

describe('buildSignatureBase', () => {
  const request = { method: 'GET', url: 'https://example.com/a', headers: { date: 'x', 'agent-did': 'sig1="did:x"' } };
  const params: Array<[string, string]> = [['tag', 'agent-did']];

  it('rejects a header value with a bare line break', () => {
    expect(() =>
      buildSignatureBase({ ...request, headers: { date: 'a\nb' } }, { components: ['date'], params })
    ).toThrow('line breaks');
  });

  it('rejects a key parameter on a derived component and a missing dictionary member', () => {
    expect(() => buildSignatureBase(request, { components: [{ name: '@method', key: 'sig1' }], params })).toThrow(
      'only to header fields'
    );
    expect(() => buildSignatureBase(request, { components: [{ name: 'agent-did', key: 'sig2' }], params })).toThrow(
      'member is missing'
    );
  });

  it('rejects a request URL that is not in normalized form', () => {
    expect(() =>
      buildSignatureBase({ ...request, url: 'https://example.com/./a' }, { components: ['@path'], params })
    ).toThrow('normalized form');
  });
});

describe('requestUrlFormProblem', () => {
  it('reports ports out of range, unparsable IPv6 hosts and empty host labels', () => {
    expect(requestUrlFormProblem('https://example.com:65536/')).toBe('its port is out of range');
    expect(requestUrlFormProblem('https://[1:2:3:4:5:6:7:8:9]/')).toBe('its IPv6 host is not in canonical form');
    expect(requestUrlFormProblem('https://example..com/')).toBe('its host has an empty label');
  });
});

describe('signature checks with a malformed key or signature', () => {
  const keyId = 'did:example:a#key-1';
  const document = {
    id: 'did:example:a',
    verificationMethod: [{ id: keyId, type: 'Multikey', controller: 'did:example:a', publicKeyMultibase: 'z-not-base58' }],
    assertionMethod: [keyId],
    authentication: [keyId]
  } as unknown as AgentDIDDocument;

  it('treats a key that does not decode as not verifying', () => {
    expect(verifyWithActiveKeys(document, 'payload', '00'.repeat(64), keyId, 'assertionMethod')).toBe(false);
  });

  it('reports history_unavailable as indeterminate and a bad signature as invalid', () => {
    const unavailable = { status: 'indeterminate', reason: 'history_unavailable' } as unknown as KeyAtTimeResult;
    expect(signatureResultForKey(unavailable, 'payload', '00')).toEqual({ status: 'indeterminate', key: unavailable });

    const authorized = { status: 'authorized', publicKeyMultibase: 'z-not-base58' } as unknown as KeyAtTimeResult;
    expect(signatureResultForKey(authorized, 'payload', 'not hex')).toMatchObject({
      status: 'invalid',
      reason: 'signature_invalid'
    });
  });
});
