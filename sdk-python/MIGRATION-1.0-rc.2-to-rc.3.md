# agent-did-sdk Migration Guide: 1.0.0rc2 -> 1.0.0rc3

This guide covers the breaking changes between `1.0.0rc2` and `1.0.0rc3`. It is updated as each change lands on `main`; `rc3` is not published yet.

## 1. `documentRef` canonicalization is RFC 8785 (JCS)

### What changed

`generate_canonical_document_hash` (used by `AgentIdentity` to compute `documentRef`) and `canonicalize_json` now implement the JSON Canonicalization Scheme, RFC 8785, through the [`rfc8785`](https://pypi.org/project/rfc8785/) package (new runtime dependency):

| Aspect | `rc2` and earlier | `rc3` |
|---|---|---|
| Member order | `sorted()` (Unicode code points) | UTF-16 code units (RFC 8785 §3.2.3) |
| `created` / `updated` / `timestamp` values | Rewritten to ISO-8601 milliseconds before hashing | Hashed exactly as written |
| `None` members | Dropped | Serialized as `null` |
| Numbers | `json.dumps` (e.g. `56.0`, `1e-06`) | ECMAScript serialization (`56`, `0.000001`) |
| `NaN`, `inf`, integers beyond ±(2⁵³−1) | Serialized | Raise `rfc8785.CanonicalizationError` |

`UniversalResolverClient` also stores documents under this canonical reference. In `rc2` it hashed `json.dumps(..., sort_keys=True)` with default separators, so the key it stored under did not match the `documentRef` registered by `AgentIdentity`, nor the key the TypeScript SDK used.

### Impact

- A `documentRef` computed by `rc2` or earlier differs from the one `rc3` computes for the same document. Verifiers on `rc3` that recompute references will not match records written by older versions.
- Documents that `UniversalResolverClient` stored by reference in `rc2` sit under keys that `rc3` will not look up.
- The shared fixture `fixtures/canonical-document-reference.json` has a new `expectedDocumentRef`.
- `AgentDIDDocument.model_dump_jsonld()` still drops `None` fields, so SDK-created documents hash identically in Python and TypeScript.

### What to do

1. Upgrade every producer and verifier together; mixed `rc2` / `rc3` deployments disagree on `documentRef`.
2. For each agent you manage, recompute the reference from the current document and update the registry record:

   ```python
   from agent_did_sdk.crypto.hash import generate_canonical_document_hash

   document_ref = generate_canonical_document_hash(document.model_dump_jsonld())
   # Persist document_ref wherever your registry stores it, and re-store the
   # document in any content-addressed source under the new key.
   ```

3. If you call `canonicalize_json` yourself, pass JSON-compatible values only, keep integers within ±(2⁵³−1), and remove `None` members first if you want them omitted rather than serialized as `null`.

No public function was renamed or removed, and their signatures did not change.
