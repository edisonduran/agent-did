/**
 * Property tests / fuzzing of the SDK's input parsers (M-14): Structured Fields
 * (Signature-Input / Signature), did.jsonl and publicKeyMultibase.
 *
 * Default budget is small so the normal suite stays fast; the nightly workflow
 * `ci-fuzz.yml` raises it with FUZZ_RUNS. Python parity:
 * sdk-python/tests/test_fuzz_properties.py.
 */
import fc from 'fast-check';
import { LocalKeySigner } from '../src/core/signer';
import {
  HttpSignatureError,
  parseSignatureHeader,
  parseSignatureInputHeader,
} from '../src/core/http-signatures';
import { decodePublicKeyMultibase, encodePublicKeyMultibase } from '../src/crypto/multibase';
import {
  createDidWebvhLog,
  DID_WEBVH_PLACEHOLDER,
  DidWebvhError,
  resolveDidWebvhLog,
} from '../src/webvh/adapter';

const RUNS = Number.parseInt(process.env.FUZZ_RUNS ?? '', 10) || 100;
const SLOW_RUNS = Math.max(10, Math.floor(RUNS / 5));

/** Runs `fn`, returning the thrown value (or undefined). */
function thrown(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

/** Strings biased towards the structured-field alphabet so the parser goes past the first byte. */
const sfLike = fc.oneof(
  fc.string({ maxLength: 120 }),
  fc.stringMatching(/^[a-z0-9=:;,()" *@._\-/+]{0,120}$/u),
  fc.string({ unit: 'binary', maxLength: 60 })
);

describe('Structured Fields parsers (property)', () => {
  it('parseSignatureInputHeader only throws HttpSignatureError', () => {
    fc.assert(
      fc.property(sfLike, (input) => {
        const error = thrown(() => parseSignatureInputHeader(input));
        expect(error === undefined || error instanceof HttpSignatureError).toBe(true);
      }),
      { numRuns: RUNS * 5 }
    );
  });

  it('parseSignatureHeader only throws HttpSignatureError', () => {
    fc.assert(
      fc.property(sfLike, (input) => {
        const error = thrown(() => parseSignatureHeader(input));
        expect(error === undefined || error instanceof HttpSignatureError).toBe(true);
      }),
      { numRuns: RUNS * 5 }
    );
  });

  it('parseSignatureHeader round-trips serialized byte sequences', () => {
    const label = fc.stringMatching(/^[a-z][a-z0-9_-]{0,10}$/u);
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.tuple(label, fc.uint8Array({ minLength: 0, maxLength: 80 })), {
          minLength: 1,
          maxLength: 4,
          selector: ([name]) => name,
        }),
        (members) => {
          const header = members
            .map(([name, bytes]) => `${name}=:${Buffer.from(bytes).toString('base64')}:`)
            .join(', ');
          const parsed = parseSignatureHeader(header);
          expect([...parsed.keys()]).toEqual(members.map(([name]) => name));
          for (const [name, bytes] of members) {
            expect(Array.from(parsed.get(name) as Uint8Array)).toEqual(Array.from(bytes));
          }
        }
      ),
      { numRuns: RUNS }
    );
  });

  it('parseSignatureInputHeader round-trips serialized inner lists', () => {
    const label = fc.stringMatching(/^[a-z][a-z0-9_-]{0,10}$/u);
    const component = fc.constantFrom('@method', '@authority', '@path', '@query', 'content-digest', 'date');
    fc.assert(
      fc.property(
        label,
        fc.array(component, { minLength: 1, maxLength: 6 }),
        fc.integer({ min: 0, max: 2 ** 31 }),
        fc.stringMatching(/^[A-Za-z0-9_-]{1,20}$/u),
        (name, components, created, nonce) => {
          const header = `${name}=(${components.map((c) => `"${c}"`).join(' ')});created=${created};nonce="${nonce}"`;
          const member = parseSignatureInputHeader(header).get(name);
          expect(member?.components).toEqual(components);
          expect(Object.fromEntries(member?.params ?? []).created).toBe(created);
          expect(Object.fromEntries(member?.params ?? []).nonce).toBe(nonce);
        }
      ),
      { numRuns: RUNS }
    );
  });
});

describe('publicKeyMultibase (property)', () => {
  it('round-trips any 32-byte key', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (key) => {
        const encoded = encodePublicKeyMultibase(key);
        expect(encoded.startsWith('z')).toBe(true);
        expect(Array.from(decodePublicKeyMultibase(encoded))).toEqual(Array.from(key));
      }),
      { numRuns: RUNS * 5 }
    );
  });

  it('rejects any key that is not 32 bytes', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ maxLength: 64 }).filter((key) => key.length !== 32),
        (key) => {
          expect(() => encodePublicKeyMultibase(key)).toThrow(Error);
        }
      ),
      { numRuns: RUNS }
    );
  });

  it('decode throws only Error and returns exactly 32 bytes otherwise', () => {
    const b58Like = fc.stringMatching(/^z?[1-9A-HJ-NP-Za-km-z0-9]{0,60}$/u);
    fc.assert(
      fc.property(fc.oneof(fc.string({ maxLength: 80 }), b58Like), (input) => {
        let result: Uint8Array | undefined;
        const error = thrown(() => {
          result = decodePublicKeyMultibase(input);
        });
        if (error === undefined) {
          expect(result?.length).toBe(32);
        } else {
          expect(error).toBeInstanceOf(Error);
        }
      }),
      { numRuns: RUNS * 5 }
    );
  });

  it('legacy z+hex keys always decode to 32 bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (key) => {
        const hex = Buffer.from(key).toString('hex');
        expect(decodePublicKeyMultibase(`z${hex}`)).toHaveLength(32);
      }),
      { numRuns: RUNS }
    );
  });
});

describe('did.jsonl resolution (property)', () => {
  let validLog: string;
  let validDocument: unknown;

  beforeAll(async () => {
    const created = await createDidWebvhLog({
      domain: 'agents.example.com',
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: DID_WEBVH_PLACEHOLDER,
        controller: 'did:webvh:controller.example.com',
      },
      signer: new LocalKeySigner('1'.repeat(64)),
      created: '2026-01-01T00:00:00Z',
    });
    validLog = created.log;
    validDocument = (await resolveDidWebvhLog(validLog)).document;
  });

  /** Either rejected with DidWebvhError, or resolved to exactly the original document. */
  async function resolveOutcome(text: string): Promise<'ok' | 'rejected'> {
    try {
      const result = await resolveDidWebvhLog(text);
      expect(result.document).toEqual(validDocument);
      return 'ok';
    } catch (error) {
      expect(error).toBeInstanceOf(DidWebvhError);
      return 'rejected';
    }
  }

  it('arbitrary text only fails with DidWebvhError', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(fc.string({ maxLength: 200 }), fc.string({ unit: 'binary', maxLength: 80 })),
        async (text) => {
          expect(await resolveOutcome(text)).toBe('rejected');
        }
      ),
      { numRuns: RUNS }
    );
  });

  it('arbitrary JSON lines only fail with DidWebvhError', async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(fc.jsonValue(), { minLength: 1, maxLength: 3 }), async (values) => {
        const text = values.map((value) => JSON.stringify(value)).join('\n');
        expect(await resolveOutcome(text)).toBe('rejected');
      }),
      { numRuns: RUNS }
    );
  });

  it('a mutated valid log is rejected or resolves to the identical document', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.nat({ max: validLog.length - 1 }),
        fc.string({ minLength: 1, maxLength: 3 }),
        async (index, replacement) => {
          await resolveOutcome(validLog.slice(0, index) + replacement + validLog.slice(index + 1));
        }
      ),
      { numRuns: SLOW_RUNS }
    );
  });

  it('a truncated valid log is rejected or resolves to the identical document', async () => {
    await fc.assert(
      fc.asyncProperty(fc.nat({ max: validLog.length }), async (end) => {
        await resolveOutcome(validLog.slice(0, end));
      }),
      { numRuns: SLOW_RUNS }
    );
  });
});
