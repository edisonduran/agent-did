export function isUnixTimestampString(value: string): boolean {
  return /^\d+$/.test(value.trim());
}

export function unixStringToIso(value: string): string {
  if (!isUnixTimestampString(value)) {
    throw new Error(`Invalid unix timestamp string: ${value}`);
  }

  const seconds = Number(value);
  const date = new Date(seconds * 1000);

  if (Number.isNaN(date.getTime())) {
    throw new Error(`Invalid unix timestamp value: ${value}`);
  }

  return date.toISOString();
}

export function isoToUnixString(value: string): string {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) {
    throw new Error(`Invalid ISO timestamp: ${value}`);
  }

  return Math.floor(ms / 1000).toString();
}

export function normalizeTimestampToIso(value?: string): string | undefined {
  if (!value) {
    return undefined;
  }

  if (isUnixTimestampString(value)) {
    return unixStringToIso(value);
  }

  const ms = Date.parse(value);
  if (Number.isNaN(ms)) {
    throw new Error(`Invalid ISO timestamp: ${value}`);
  }

  return new Date(ms).toISOString();
}
