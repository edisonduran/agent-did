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

No public function was renamed or removed, and their signatures did not change.
