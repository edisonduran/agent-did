/**
 * DIF didwebvh-test-suite against the did:webvh adapter (ADR-002, condition 6).
 *
 * Runs only when DIDWEBVH_TEST_SUITE_DIR points at a checkout of the suite at
 * the commit pinned in fixtures/didwebvh-test-suite.json (the CI workflow
 * `ci-didwebvh-test-suite.yml` does this). Python parity:
 * sdk-python/tests/test_webvh_test_suite.py.
 */
import fs from 'fs';
import path from 'path';
import { deriveDidWebvhLogUrl, DidWebvhError, resolveDidWebvhLog } from '../src/webvh/adapter';

interface SuiteExpectations {
  commit: string;
  unsupported: Record<string, string>;
  didUrlNegative: Record<string, string>;
  vectorDefects: Record<string, string>;
}

const EXPECTATIONS = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'didwebvh-test-suite.json'), 'utf8')
) as SuiteExpectations;
const SUITE_DIR = process.env.DIDWEBVH_TEST_SUITE_DIR;
const VECTORS = SUITE_DIR ? path.join(SUITE_DIR, 'vectors') : '';

type PositiveCase = [string, { log: string; expected: any; versionNumber?: number }];
type RejectCase = [string, string];

/** A valid base58btc SCID, substituted to show the host/path rules (not the SCID) reject the DID. */
const VALID_SCID = 'QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ';

function listDirs(dir: string): string[] {
  return fs
    .readdirSync(dir)
    .filter((name) => fs.statSync(path.join(dir, name)).isDirectory())
    .sort();
}

function readLog(dir: string): string | undefined {
  const file = path.join(dir, 'did.jsonl');
  if (!fs.existsSync(file)) return undefined;
  const text = fs.readFileSync(file, 'utf8');
  return text.trim().length > 0 ? text : undefined;
}

function collect() {
  const positive: PositiveCase[] = [];
  const unsupported: RejectCase[] = [];
  const negative: RejectCase[] = [];
  const didUrlNegative: RejectCase[] = [];
  const scenarios = SUITE_DIR ? listDirs(VECTORS) : [];

  for (const scenario of scenarios) {
    if (scenario in EXPECTATIONS.didUrlNegative) {
      const script = fs.readFileSync(path.join(VECTORS, scenario, 'script.yaml'), 'utf8');
      for (const match of script.matchAll(/^\s+did:\s*"([^"]+)"/gmu)) {
        didUrlNegative.push([`${scenario} ${match[1]}`, match[1]]);
      }
      continue;
    }
    const isNegative = scenario.startsWith('negative-');
    for (const impl of listDirs(path.join(VECTORS, scenario))) {
      const dir = path.join(VECTORS, scenario, impl);
      const log = readLog(dir);
      if (!log) continue;
      if (isNegative) {
        negative.push([`${scenario}/${impl}`, log]);
      } else if (scenario in EXPECTATIONS.unsupported) {
        unsupported.push([`${scenario}/${impl}`, log]);
      } else {
        for (const file of fs.readdirSync(dir).filter((name) => /^resolutionResult(\.\d+)?\.json$/u.test(name)).sort()) {
          const match = /^resolutionResult\.(\d+)\.json$/u.exec(file);
          positive.push([
            `${scenario}/${impl}/${file}`,
            {
              log,
              expected: JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8')),
              versionNumber: match ? Number(match[1]) : undefined,
            },
          ]);
        }
      }
    }
  }
  return { scenarios, positive, unsupported, negative, didUrlNegative };
}

const IMPLICIT_SERVICE = /#(files|whois)$/u;

/** Drops the implicit #files / #whois services, whose serialization differs between resolvers. */
function withoutImplicitServices(document: Record<string, any>): Record<string, any> {
  const copy = { ...document };
  if (Array.isArray(copy.service)) {
    copy.service = copy.service.filter((service: { id?: string }) => !IMPLICIT_SERVICE.test(service.id ?? ''));
    if (copy.service.length === 0) delete copy.service;
  }
  return copy;
}

const CASES = collect();
const suiteDescribe = SUITE_DIR ? describe : describe.skip;

suiteDescribe(`didwebvh-test-suite @ ${EXPECTATIONS.commit.slice(0, 12)}`, () => {
  it('runs against the pinned commit and classifies every scenario', () => {
    const head = fs.existsSync(path.join(SUITE_DIR as string, '.git'))
      ? require('child_process').execFileSync('git', ['-C', SUITE_DIR, 'rev-parse', 'HEAD']).toString().trim()
      : EXPECTATIONS.commit;
    expect(head).toBe(EXPECTATIONS.commit);

    for (const listed of [...Object.keys(EXPECTATIONS.unsupported), ...Object.keys(EXPECTATIONS.didUrlNegative)]) {
      expect(CASES.scenarios).toContain(listed);
    }
    const positiveNames = CASES.positive.map(([name]) => name);
    for (const listed of Object.keys(EXPECTATIONS.vectorDefects)) {
      expect(positiveNames).toContain(listed);
    }
    const covered = new Set(
      [...CASES.positive, ...CASES.unsupported, ...CASES.negative, ...CASES.didUrlNegative].map(
        ([name]) => name.split(/[/ ]/u)[0]
      )
    );
    const unclassified = CASES.scenarios.filter((scenario) => !covered.has(scenario));
    expect(unclassified).toEqual([]);
  });

  it.each(CASES.positive)('resolves %s', async (name, { log, expected, versionNumber }) => {
    const resolved = await resolveDidWebvhLog(log, versionNumber !== undefined ? { versionNumber } : {});
    const entries = log
      .split(/\r?\n/u)
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line));
    const selected = entries[(versionNumber ?? entries.length) - 1];

    // Valid DIDs from every implementation must map to a log URL.
    expect(deriveDidWebvhLogUrl(resolved.did)).toMatch(/^https:\/\/[a-z0-9.-]+(:\d+)?\/.*did\.jsonl$/u);
    expect(resolved.metadata.versionId).toBe(selected.versionId);
    expect(resolved.metadata.versionTime).toBe(selected.versionTime);
    expect(resolved.metadata.updated).toBe(selected.versionTime);
    expect(resolved.metadata.created).toBe(entries[0].versionTime);
    expect(resolved.metadata.scid).toBe(entries[0].parameters.scid);
    expect(resolved.metadata.deactivated).toBe(expected.didDocumentMetadata?.deactivated === true);

    if (name in EXPECTATIONS.vectorDefects) {
      // Keep the exception honest: it must be removed once upstream fixes the vector.
      expect(expected.didDocumentMetadata.versionId).not.toBe(selected.versionId);
    } else if (expected.didDocument !== null) {
      expect(withoutImplicitServices(resolved.document)).toEqual(withoutImplicitServices(expected.didDocument));
    }
  });

  it.each(CASES.unsupported)('rejects %s (witnesses unsupported)', async (_name, log) => {
    const fetchSpy = jest.spyOn(globalThis, 'fetch');
    try {
      await expect(resolveDidWebvhLog(log)).rejects.toBeInstanceOf(DidWebvhError);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it.each(CASES.negative)('rejects %s', async (_name, log) => {
    await expect(resolveDidWebvhLog(log)).rejects.toBeInstanceOf(DidWebvhError);
  });

  it.each(CASES.didUrlNegative)('rejects DID URL %s', (_name, did) => {
    const withValidScid = did.replace(/^did:webvh:[^:]+:/u, `did:webvh:${VALID_SCID}:`);
    for (const candidate of [did, withValidScid]) {
      expect(() => deriveDidWebvhLogUrl(candidate)).toThrow(DidWebvhError);
    }
  });
});

describe('didwebvh-test-suite expectations fixture', () => {
  it('pins a full commit and gives a reason for every exception', () => {
    expect(EXPECTATIONS.commit).toMatch(/^[0-9a-f]{40}$/u);
    for (const reason of [
      ...Object.values(EXPECTATIONS.unsupported),
      ...Object.values(EXPECTATIONS.didUrlNegative),
      ...Object.values(EXPECTATIONS.vectorDefects),
    ]) {
      expect(reason.length).toBeGreaterThan(0);
    }
  });
});
