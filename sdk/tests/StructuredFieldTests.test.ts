/**
 * httpwg/structured-field-tests (RFC 8941) against the Signature-Input and
 * Signature parsers.
 *
 * Runs only when STRUCTURED_FIELD_TESTS_DIR points at a checkout of the suite at
 * the commit pinned in fixtures/structured-field-tests.json (the CI workflow
 * `ci-structured-field-tests.yml` does this). Python parity:
 * sdk-python/tests/test_structured_field_tests.py.
 */
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { parseSignatureHeader, parseSignatureInputHeader } from '../src/core/http-signatures';

interface Pin {
  commit: string;
  files: string[];
  exceptions: Record<string, string>;
}

interface SuiteCase {
  name: string;
  raw: string[];
  header_type: string;
  expected?: unknown;
  must_fail?: boolean;
  can_fail?: boolean;
}

const PIN = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'structured-field-tests.json'), 'utf8')
) as Pin;
const SUITE_DIR = process.env.STRUCTURED_FIELD_TESTS_DIR;

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(value: string): number[] {
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const char of value.replace(/=+$/u, '')) {
    buffer = (buffer << 5) | BASE32.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return bytes;
}

const isTyped = (value: unknown, type: string): boolean =>
  typeof value === 'object' && value !== null && !Array.isArray(value) && (value as any).__type === type;

type Member = [string, [unknown, Array<[string, unknown]>]];

/** What the Signature parser must return for `expected`, or null when the input is outside its subset. */
function expectedSignature(expected: Member[]): Array<[string, number[]]> | null {
  const result: Array<[string, number[]]> = [];
  for (const [label, [value, params]] of expected) {
    if (!isTyped(value, 'binary') || params.length > 0) return null;
    result.push([label, base32Decode((value as any).value)]);
  }
  return result;
}

/** What the Signature-Input parser must return for `expected`, or null when outside its subset. */
function expectedSignatureInput(expected: Member[]): unknown[] | null {
  const result: unknown[] = [];
  for (const [label, [value, params]] of expected) {
    if (!Array.isArray(value)) return null;
    const components: string[] = [];
    for (const [item, itemParams] of value as Array<[unknown, unknown[]]>) {
      if (typeof item !== 'string' || itemParams.length > 0) return null;
      components.push(item);
    }
    const mapped: Array<[string, unknown]> = [];
    for (const [name, param] of params) {
      if (typeof param === 'string' || typeof param === 'boolean') mapped.push([name, param]);
      else if (typeof param === 'number' && Number.isInteger(param)) mapped.push([name, param]);
      else if (isTyped(param, 'token')) mapped.push([name, { token: (param as any).value }]);
      else return null;
    }
    result.push([label, { components, params: mapped }]);
  }
  return result;
}

function loadCases(): Array<[string, SuiteCase]> {
  const cases: Array<[string, SuiteCase]> = [];
  for (const file of PIN.files) {
    const tests = JSON.parse(fs.readFileSync(path.join(SUITE_DIR as string, file), 'utf8')) as SuiteCase[];
    for (const test of tests) {
      if (test.header_type === 'dictionary') cases.push([`${file}: ${test.name}`, test]);
    }
  }
  return cases;
}

const suiteDescribe = SUITE_DIR ? describe : describe.skip;

suiteDescribe(`structured-field-tests @ ${PIN.commit.slice(0, 12)}`, () => {
  const cases = SUITE_DIR ? loadCases() : [];

  it('runs against the pinned commit and every exception names a real case', () => {
    const head = fs.existsSync(path.join(SUITE_DIR as string, '.git'))
      ? execFileSync('git', ['-C', SUITE_DIR as string, 'rev-parse', 'HEAD']).toString().trim()
      : PIN.commit;
    expect(head).toBe(PIN.commit);
    expect(cases.length).toBeGreaterThan(400);
    const names = cases.map(([name]) => name);
    for (const [name, reason] of Object.entries(PIN.exceptions)) {
      expect(names).toContain(name);
      expect(reason.length).toBeGreaterThan(10);
    }
  });

  for (const [name, test] of cases) {
    if (test.can_fail || PIN.exceptions[name]) continue;
    it(name, () => {
      const raw = test.raw.join(',');
      if (test.must_fail) {
        expect(() => parseSignatureHeader(raw)).toThrow();
        expect(() => parseSignatureInputHeader(raw)).toThrow();
        return;
      }
      const expected = test.expected as Member[];

      const signature = expectedSignature(expected);
      if (signature === null) {
        expect(() => parseSignatureHeader(raw)).toThrow();
      } else {
        const parsed = Array.from(parseSignatureHeader(raw), ([label, bytes]) => [label, Array.from(bytes)]);
        expect(parsed).toEqual(signature);
      }

      const input = expectedSignatureInput(expected);
      if (input === null) {
        expect(() => parseSignatureInputHeader(raw)).toThrow();
      } else {
        expect(Array.from(parseSignatureInputHeader(raw))).toEqual(input);
      }
    });
  }
});
