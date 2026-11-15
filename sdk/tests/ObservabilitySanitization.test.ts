import * as fs from 'fs';
import * as path from 'path';
import {
  isRedactedMarker,
  isSensitiveFieldName,
  sanitizeHeaders,
  sanitizeObservabilityAttributes,
  sanitizeUrl
} from '../src';

// Parity: sdk-python/tests/test_observability_sanitization.py
const vectors = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'observability-sanitization-vectors.json'), 'utf8')
).vectors as Array<{ id: string; input: unknown; expected: unknown }>;

describe('observability sanitization', () => {
  it.each(vectors.map((v) => [v.id, v]))('shared vector %s', (_id, vector) => {
    expect(sanitizeObservabilityAttributes(vector.input)).toEqual(vector.expected);
  });

  it('hides class instances and walks Maps and Sets', () => {
    class Output {
      raw = 'secret 4111 1111 1111 1111';
    }
    const result = sanitizeObservabilityAttributes({
      output: new Output(),
      map: new Map<string, unknown>([['signature', 's'], ['note', 'n']]),
      set: new Set([1]),
      data: new Uint8Array([0, 1]),
      when: new Date('2026-01-01T00:00:00Z')
    });
    expect(result).toEqual({
      output: '<Output>',
      map: { signature: { redacted: true, length: 1 }, note: 'n' },
      set: [1],
      data: { redacted: true, length: 2 },
      when: '2026-01-01T00:00:00.000Z'
    });
    expect(() => JSON.stringify(result)).not.toThrow();
  });

  it('bounds cycles and depth', () => {
    const loop: Record<string, unknown> = {};
    loop.self = loop;
    expect(sanitizeObservabilityAttributes(loop)).toEqual({ self: '<cycle>' });
    const deep: Record<string, unknown> = {};
    let node = deep;
    for (let i = 0; i < 40; i += 1) {
      node.next = {};
      node = node.next as Record<string, unknown>;
    }
    expect(JSON.stringify(sanitizeObservabilityAttributes(deep))).toContain('<max depth>');
  });

  it('helpers', () => {
    expect(isSensitiveFieldName('agentPrivateKey') && isSensitiveFieldName('API_KEY')).toBe(true);
    expect(isSensitiveFieldName('did')).toBe(false);
    expect(sanitizeUrl('not a url')).toBe('<invalid url>');
    expect(sanitizeUrl('https://[::1]:8443/x?y#z')).toBe('https://[::1]:8443/x');
    expect(sanitizeHeaders({ Cookie: 'c', Accept: 'a' })).toEqual({ Cookie: { redacted: true, length: 1 }, Accept: 'a' });
    expect(isRedactedMarker({ redacted: true, length: 1 })).toBe(true);
    expect(isRedactedMarker({ redacted: true, length: 1, x: 1 })).toBe(false);
  });
});
