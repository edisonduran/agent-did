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
   from agent_did_sdk import generate_canonical_document_hash

   document_ref = generate_canonical_document_hash(document.model_dump_jsonld())
   # Persist document_ref wherever your registry stores it, and re-store the
   # document in any content-addressed source under the new key.
   ```

3. If you call `canonicalize_json` yourself, pass JSON-compatible values only, keep integers within ±(2⁵³−1), and remove `None` members first if you want them omitted rather than serialized as `null`.

No public function was renamed or removed by this change, and their signatures did not change.

## 2. Resolution verifies `documentRef`

### What changed

When `UniversalResolverClient` resolves a DID through the registry (DIDs that are not `did:webvh` or `did:wba`), it now checks the fetched document before returning it:

- its `id` must equal the requested DID, and
- it must hash to the registry `documentRef` (section 1 above).

On failure it raises `DocumentIntegrityError` (a `ValueError` subclass) and does **not** consult the fallback resolver. Fallback still happens when the source is unreachable or returns no document.

`documentRef` values that are not `hash://sha256/...` cannot be verified and are now rejected by default.

### What to do

- Make sure registry records hold the canonical reference of the document your source serves (section 1, step 2).
- If you serve documents through IPFS or another scheme you trust at the transport level, opt in explicitly:

  ```python
  AgentIdentity.use_production_resolver_from_http(ProductionHttpResolverProfileConfig(
      registry=registry,
      ipfs_gateways=["https://gateway.example/ipfs"],
      unverified_document_ref_schemes=["ipfs"],
  ))
  ```

  Each such resolution emits a `source-fetched` event whose `message` starts with `integrity=unverified`.
- Catch `DocumentIntegrityError` (exported from `agent_did_sdk`) where you want to treat tampering differently from unavailability.

`canonicalize_json` and `generate_canonical_document_hash` are now exported from `agent_did_sdk`.

## 3. `systemPromptHash` and `coreModelHash` are salted commitments

### What changed

`create()` now commits to `system_prompt` and `core_model` with `hash://hmac-sha256/<hex>`, an HMAC-SHA256 keyed with a random 32-byte salt per field, instead of an unsalted `hash://sha256/` digest. Unsalted digests of short or predictable prompts can be confirmed by anyone who guesses them.

- `CreateAgentResult.metadata_commitment_salts` returns a `MetadataCommitmentSalts(core_model, system_prompt)` **once**. The SDK does not store it.
- `CreateAgentParams.core_model_salt` / `system_prompt_salt` let you supply your own salts (64 hex characters).
- `update_did_document` **requires** `core_model_salt` / `system_prompt_salt` when the patch changes `core_model` / `system_prompt`; it raises `ValueError` otherwise.

### What to do

```python
from agent_did_sdk import generate_commitment_salt, verify_metadata_commitment

result = await identity.create(CreateAgentParams(name=name, core_model=model, system_prompt=prompt))
# Store result.metadata_commitment_salts with the agent's other secrets.

await AgentIdentity.update_did_document(did, UpdateAgentDocumentParams(
    system_prompt=new_prompt,
    system_prompt_salt=generate_commitment_salt(),
))

# An auditor who receives (prompt, salt) out of band:
verify_metadata_commitment(result.document.agent_metadata.system_prompt_hash, prompt, salt)  # True
```

Existing documents keep their `hash://sha256/` values; `verify_metadata_commitment` still verifies them without a salt. Code that recomputed `generate_agent_metadata_hash(prompt)` to compare against a new document must switch to `verify_metadata_commitment` with the salt.

## 4. New `did-webvh` dependency and platform support

### What changed

`agent-did-sdk` depends on [`did-webvh`](https://pypi.org/project/did-webvh/) for `did:webvh` v1.0 support ([ADR-002](../docs/ADR-002-did-webvh-v1.0-Implementation.md)). It pulls `aries-askar`, a native library, and `aiohttp`.

### Impact

`aries-askar` publishes wheels for `manylinux2014` (x86_64, aarch64), macOS (universal2) and Windows x86_64 only. `pip install agent-did-sdk` fails on Alpine (musl) images and on Windows ARM64.

### What to do

Use a glibc-based image (for example `python:3.12-slim`) instead of Alpine. An upstream change to make these dependencies optional is tracked; this section will be updated when it lands.
