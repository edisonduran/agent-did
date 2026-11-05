# @agentdid/sdk Migration Guide: 1.0.0-rc.4 -> 1.0.0-rc.5

Behavior changes between `1.0.0-rc.4` and `1.0.0-rc.5`. There are no wire-format changes and no public API removals: DID documents, DID logs, hash URIs and signature bases are unchanged, and documents or signatures produced by rc.4 stay valid.

All changes below tighten the defaults of the SDK's HTTP handling. Code that already passes its own `fetchFn`, or that only talks to public HTTPS hosts and signs with the default lifetime, needs no change.

## 1. Default HTTP client: redirects, DNS and target addresses

The default `fetch` of the HTTP document sources (`HttpDIDDocumentSource`, `BearerTokenHttpDIDDocumentSource`, `JsonRpcDIDDocumentSource`, `WebvhDIDDocumentSource`, `AwsSigV4S3DIDDocumentSource`) now:

- **Does not follow redirects.** A `3xx` response is reported as a non-OK status. If your resolver endpoint redirects (for example `http://` to `https://`, or a moved path), point the source at the final URL.
- **Resolves the host name once and connects to the validated address.** The request is refused when the name does not resolve, or when any resolved address is not globally routable. The connection uses the address that was checked, and TLS still verifies the original host name.
- **Rejects every non-globally-routable range.** This covers private, shared (`100.64.0.0/10`), loopback, link-local, documentation, benchmarking, multicast and reserved IPv4, and IPv6 outside global unicast space (`2000::/3`). IPv4-mapped, NAT64 and 6to4 addresses are judged by the IPv4 address they embed.
- **Relies on Node.js modules** (`node:http`, `node:https`, `node:dns`). Where those are not available, supply your own `fetchFn` to the sources that accept one.

If you must reach an internal endpoint (a resolver inside a private network, a local test server), opt out explicitly:

```ts
new HttpDIDDocumentSource({
  referenceToUrl: (ref) => `http://did-resolver.internal:8080/${ref}`,
  httpSecurity: { allowPrivateTargets: true },
});
```

A `fetchFn` you supply owns its own redirect and DNS policy; the SDK does not wrap it.

## 2. Target validation is stricter and the same in both SDKs

`validateHttpTarget` (TypeScript) and `validate_http_target` (Python) now give the same answer for the same input, verified by `fixtures/http-target-vectors.json`.

- Hosts such as `0.0.0.0`, `192.0.0.0/24` and any IPv6 address outside `2000::/3`, `2001::/23`, `2001:db8::/32` and `3fff::/20` are rejected.
- An unparseable bracketed IPv6 literal is rejected.

## 3. HTTP signature verification bounds the signature lifetime

`verifyHttpRequestSignature` rejects a signature whose `expires - created` is greater than `maxSignatureLifetimeSeconds`, **300 seconds by default**.

- Signatures from the SDK's own signer use a 30 second lifetime by default, so they are unaffected.
- If another signer issues longer-lived signatures that you trust, raise the limit on the verifying side:

```ts
await client.verifyHttpRequestSignature({
  method, url, headers, body,
  maxSignatureLifetimeSeconds: 900,
});
```

## 4. EVM profile (`@agentdid/evm`)

`AgentRegistry` registration now requires an EIP-712 attestation from a registrar, so an unrelated account can no longer register someone else's DID. The EVM profile is deferred outside core 1.0; see the `@agentdid/evm` README for the registrar flow. `revokeAgent` also works while the registry is paused.

## Checklist

- [ ] Resolver endpoints no longer rely on redirects.
- [ ] Internal endpoints set `httpSecurity: { allowPrivateTargets: true }`.
- [ ] Non-Node runtimes pass their own `fetchFn`.
- [ ] Third-party signers with a lifetime above 300 s are covered by `maxSignatureLifetimeSeconds`.
