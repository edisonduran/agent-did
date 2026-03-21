import {
  isUnixTimestampString,
  unixStringToIso,
  isoToUnixString,
  normalizeTimestampToIso
} from '../src/core/time';

describe('Time utilities', () => {
  it('should detect unix timestamp strings', () => {
    expect(isUnixTimestampString('1740566400')).toBe(true);
    expect(isUnixTimestampString('2026-02-26T00:00:00Z')).toBe(false);
  });

  it('should convert unix string to ISO and back', () => {
    const unix = '1740566400';
    const iso = unixStringToIso(unix);

    expect(iso.endsWith('Z')).toBe(true);
    expect(isoToUnixString(iso)).toEqual(unix);
  });

  it('should normalize unix to ISO and keep ISO unchanged', () => {
    const unix = '1740566400';
    const normalizedFromUnix = normalizeTimestampToIso(unix);
    const iso = '2026-02-26T10:20:30Z';
    const normalizedFromIso = normalizeTimestampToIso(iso);

    expect(normalizedFromUnix).toBeDefined();
    expect(normalizedFromUnix?.endsWith('Z')).toBe(true);
    expect(normalizedFromIso).toEqual('2026-02-26T10:20:30.000Z');
  });
});
