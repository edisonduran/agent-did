import fs from 'fs';
import path from 'path';

// docs/DEPRECATION-POLICY.md "Public API Contract": only the package entry point is public.
describe('public surface of @agentdid/sdk', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));

  it('exposes only the entry point and package.json, so deep imports fail', () => {
    expect(Object.keys(manifest.exports).sort()).toEqual(['.', './package.json']);
  });

  it('points every condition of the entry point at the built index', () => {
    const entry = manifest.exports['.'];
    expect(entry.types).toBe('./dist/index.d.ts');
    for (const condition of ['import', 'require', 'default']) {
      expect(entry[condition]).toMatch(/^\.\/dist\/index\.(?:m?js)$/);
    }
  });
});
