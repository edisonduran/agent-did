# @agentdid/sdk Migration Guide: 1.0.0-rc.2 -> 1.0.0-rc.3

This guide covers the breaking changes between `1.0.0-rc.2` and `1.0.0-rc.3`. It is updated as each change lands on `main`; `rc.3` is not published yet.

## 1. `documentRef` canonicalization is RFC 8785 (JCS)

### What changed

`generateCanonicalDocumentHash` (used by `AgentIdentity` to compute `documentRef`) and `canonicalizeJson` now implement the JSON Canonicalization Scheme, RFC 8785:

| Aspect | `rc.2` and earlier | `rc.3` |
|---|---|---|
| Member order | `String.prototype.localeCompare` (locale-dependent) | UTF-16 code units (RFC 8785 §3.2.3) |
| `created` / `updated` / `timestamp` values | Rewritten to `toISOString()` before hashing | Hashed exactly as written |
| Numbers, strings | `JSON.stringify` | `JSON.stringify` (unchanged, as RFC 8785 requires) |
| `NaN`, `Infinity`, `bigint` | Serialized as `null` / threw inconsistently | Throw `TypeError` |

`UniversalResolverClient` also stores documents under this canonical reference. In `rc.2` it hashed a plain `JSON.stringify` of the document, so the key it stored under did not match the `documentRef` registered by `AgentIdentity`.

### Impact

- A `documentRef` computed by `rc.2` or earlier differs from the one `rc.3` computes for the same document. Verifiers on `rc.3` that recompute references will not match records written by older versions.
- Documents that `UniversalResolverClient` stored by reference in `rc.2` sit under keys that `rc.3` will not look up.
- The shared fixture `fixtures/canonical-document-reference.json` has a new `expectedDocumentRef`.
- If you relied on `canonicalizeJson` treating `"2024-01-01T00:00:00Z"` and `"2024-01-01T00:00:00.000Z"` as equal, they now hash differently. Documents produced by the SDK already use a single timestamp format, so SDK-created documents are unaffected by this rule.

### What to do

1. Upgrade every producer and verifier together; mixed `rc.2` / `rc.3` deployments disagree on `documentRef`.
2. For each agent you manage, recompute the reference from the current document and update the registry record:

   ```ts
   import { generateCanonicalDocumentHash } from '@agentdid/sdk';

   const documentRef = generateCanonicalDocumentHash(document);
   // Persist documentRef wherever your registry stores it, and re-store the
   // document in any content-addressed source under the new key.
   ```

3. If you call `canonicalizeJson` yourself, pass JSON-compatible values only (no `NaN`, `Infinity` or `bigint`), and normalize timestamps before building the document if you need equivalent instants to hash identically.

No public function was renamed or removed by this change, and their signatures did not change.

## 2. Resolution verifies `documentRef`

### What changed

When `UniversalResolverClient` resolves a DID through the registry (DIDs that are not `did:webvh` or `did:wba`), it now checks the fetched document before returning it:

- its `id` must equal the requested DID, and
- it must hash to the registry `documentRef` (section 1 above).

On failure it throws `DocumentIntegrityError` and does **not** consult the fallback resolver. Fallback still happens when the source is unreachable or returns no document.

`documentRef` values that are not `hash://sha256/...` cannot be verified and are now rejected by default.

### What to do

- Make sure registry records hold the canonical reference of the document your source serves (section 1, step 2).
- If you serve documents through IPFS or another scheme you trust at the transport level, opt in explicitly:

  ```ts
  AgentIdentity.useProductionResolverFromHttp({
    registry,
    ipfsGateways: ['https://gateway.example/ipfs'],
    unverifiedDocumentRefSchemes: ['ipfs'],
  });
  ```

  Each such resolution emits a `source-fetched` event whose `message` starts with `integrity=unverified`.
- Catch `DocumentIntegrityError` (exported from `@agentdid/sdk`) where you want to treat tampering differently from unavailability.

`canonicalizeJson` and `generateCanonicalDocumentHash` are now exported from the package root.
