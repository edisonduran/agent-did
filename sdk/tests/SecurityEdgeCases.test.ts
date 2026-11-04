import { HttpDIDDocumentSource } from '../src/resolver/HttpDIDDocumentSource';
import { JsonRpcDIDDocumentSource } from '../src/resolver/JsonRpcDIDDocumentSource';

describe('Security Edge Cases', () => {
  describe('HttpDIDDocumentSource SSRF protection', () => {
    it('should reject file:// protocol URLs', async () => {
      const fetchFn = jest.fn();
      const source = new HttpDIDDocumentSource({
        fetchFn,
        referenceToUrl: () => 'file:///etc/passwd',
      });

      const result = await source.getByReference('hash://sha256/test');
      expect(result).toBeNull();
      expect(fetchFn).not.toHaveBeenCalled();
    });

    it('should reject data: protocol URLs', async () => {
      const fetchFn = jest.fn();
      const source = new HttpDIDDocumentSource({
        fetchFn,
        referenceToUrl: () => 'data:text/html,<h1>malicious</h1>',
      });

      const result = await source.getByReference('hash://sha256/test');
      expect(result).toBeNull();
      expect(fetchFn).not.toHaveBeenCalled();
    });

    it('should accept https: protocol URLs', async () => {
      const fetchFn = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ id: 'did:agent:polygon:0xtest' }),
      });

      const source = new HttpDIDDocumentSource({
        fetchFn,
        referenceToUrl: () => 'https://resolver.example/doc/test',
      });

      const result = await source.getByReference('hash://sha256/test');
      expect(result).toBeDefined();
      expect(fetchFn).toHaveBeenCalledTimes(1);
    });
  });

  describe('JsonRpcDIDDocumentSource SSRF protection', () => {
    it('should reject file:// protocol endpoints', async () => {
      const source = new JsonRpcDIDDocumentSource({
        endpoints: ['file:///etc/passwd'],
      });

      const result = await source.getByReference('hash://sha256/test');
      expect(result).toBeNull();
    });

    it('should reject javascript: protocol endpoints', async () => {
      expect(() => new JsonRpcDIDDocumentSource({
        endpoints: ['javascript:alert(1)'],
      })).not.toThrow();

      const source = new JsonRpcDIDDocumentSource({
        endpoints: ['javascript:alert(1)'],
      });
      const result = await source.getByReference('hash://sha256/test');
      expect(result).toBeNull();
    });
  });
});
