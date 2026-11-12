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

      await expect(source.getByReference('hash://sha256/test')).rejects.toThrow(/blocked by SSRF policy/u);
      expect(fetchFn).not.toHaveBeenCalled();
    });

    it('should reject data: protocol URLs', async () => {
      const fetchFn = jest.fn();
      const source = new HttpDIDDocumentSource({
        fetchFn,
        referenceToUrl: () => 'data:text/html,<h1>malicious</h1>',
      });

      await expect(source.getByReference('hash://sha256/test')).rejects.toThrow(/blocked by SSRF policy/u);
      expect(fetchFn).not.toHaveBeenCalled();
    });

    it('should accept https: protocol URLs', async () => {
      // 404: the protocol was accepted and the request sent (parity: test_security_edge_cases.py)
      const fetchFn = jest.fn().mockResolvedValue({ ok: false, status: 404 });

      const source = new HttpDIDDocumentSource({
        fetchFn,
        referenceToUrl: () => 'https://resolver.example/doc/test',
      });

      const result = await source.getByReference('hash://sha256/test');
      expect(result).toBeNull();
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
