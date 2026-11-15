/**
 * Standard base64 (RFC 4648 §4) of bytes, without `Buffer`: the core runs where only web platform globals exist
 * (`btoa` is available in Node.js 16+ and in browsers and workers).
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunk));
  }
  return btoa(binary);
}

/** Base64url without padding (RFC 4648 §5), as JWS uses it (RFC 7515 §2). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

/**
 * Decodes unpadded base64url. Returns `undefined` for anything that is not the canonical encoding of some bytes
 * (other characters, padding, a length that no encoding has, or non-zero trailing bits).
 */
export function base64UrlToBytes(value: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) {
    return undefined;
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return undefined;
  }
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return bytesToBase64Url(bytes) === value ? bytes : undefined;
}
