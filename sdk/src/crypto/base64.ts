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
