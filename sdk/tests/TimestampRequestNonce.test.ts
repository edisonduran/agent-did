import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

// A random nonce whose first byte is 0 must still encode as a positive, minimally encoded INTEGER (1 in 128 requests)
jest.mock('@noble/hashes/utils', () => ({
  ...jest.requireActual('@noble/hashes/utils'),
  randomBytes: (length: number) => new Uint8Array(length)
}));

import { createTimestampRequest } from '../src/crypto/timestamp';

describe('createTimestampRequest nonce', () => {
  it('replaces a leading zero byte so the nonce stays a minimal positive INTEGER', () => {
    const request = new pkijs.TimeStampReq({ schema: asn1js.fromBER(createTimestampRequest(new Uint8Array([1]))).result });
    const nonce = new Uint8Array(request.nonce!.valueBlock.valueHexView);
    expect(nonce[0]).toBe(1);
    expect(nonce.length).toBe(8);
  });
});
