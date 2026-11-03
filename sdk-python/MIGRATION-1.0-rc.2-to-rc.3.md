# agent-did-sdk Migration Guide: 1.0.0rc2 -> 1.0.0rc3

This guide covers the breaking changes between `1.0.0rc2` and `1.0.0rc3`. Read it before upgrading; rc2 and rc3 do not interoperate.

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

## 5. `did:webvh` DIDs are did:webvh v1.0 DIDs

### What changed

[ADR-002](../docs/ADR-002-did-webvh-v1.0-Implementation.md) moves the canonical `did:webvh` path to the DIF did:webvh v1.0 specification, through the reference implementation `did-webvh`:

| | `rc2` | `rc3` |
|---|---|---|
| SCID | Random (or `webvh.scid`) | Derived from the genesis log entry; `scid` is removed and rejected (`extra="forbid"`) |
| `did.jsonl` | Agent-DID format: `versionId`, `versionTime`, `state` | v1.0: `parameters` (`updateKeys`, ...), hash-chained `versionId`, `eddsa-jcs-2022` proof per entry |
| Who signs the log | Nobody | The controller key (`updateKeys`) |
| Explicit profile (`webvh.domain`) | `domain`, `controller_did` | Also `controller_signer: AgentSigner` (required) |
| Implicit `agents.local` profile | Controller DID derived from the wallet address | Controller DID is a v1.0 log; a new bootstrap is a new DID |
| `revoke_did` | Registry only | Appends `deactivated: true` to the log; the registry record is a derived index |
| Revocation state on `resolve` | Registry `is_revoked` | The verified log; `registry.revoke` alone no longer revokes a `did:webvh` DID |
| Resolution | — | `UniversalResolverClient` fetches `did.jsonl` and verifies it; failures raise `DocumentIntegrityError` without fallback; deactivated DIDs are refused |

### Impact

- `did:webvh` DIDs and `did.jsonl` files produced by `rc2` or earlier do not verify and cannot be upgraded in place: the SCID is bound to the genesis entry.
- `AgentIdentity.resolve` takes the revocation state of a `did:webvh` DID from its verified log, not from the registry. Code that revoked a `did:webvh` DID by calling the registry directly must call `revoke_did` (with the controller signer) instead. A stored log that no longer verifies makes `resolve` raise.
- `update_did_document`, `rotate_verification_method` and `revoke_did` need the controller signer. In the process that created the DID it is retained automatically. After `import_did_webvh_history` (or the file/source restore helpers) pass it explicitly; otherwise they raise `ValueError`.
- A `webvh_document_source` must implement `get_did_log_by_reference`. Sources that only return parsed documents are refused for `did:webvh` (`TypeError`).
- `did:webvh` DIDs must use a lowercase ASCII host name (no IP literals), an optional port encoded as `%3A`, and unencoded path segments.

### What to do

1. Re-issue each `did:webvh` agent with `rc3` and publish the new `did.jsonl` (`export_did_webvh_history(did)`) at the URL the DID maps to: `https://<host>/<path...>/did.jsonl`, or `https://<host>/.well-known/did.jsonl` without a path.
2. Explicit profile: pass the controller's key, ideally KMS/HSM-backed:

   ```python
   await identity.create(CreateAgentParams(
       name="support-bot", core_model=core_model, system_prompt=system_prompt,
       webvh=CreateDidWebvhOptions(
           domain="agents.example.com", path_segments=["support-bot"],
           controller_did=controller_did, controller_signer=controller_signer,
       ),
   ))
   ```

3. Lifecycle operations on an imported DID:

   ```python
   await AgentIdentity.import_did_webvh_history(log)
   await AgentIdentity.update_did_document(
       did, UpdateAgentDocumentParams(version="1.1.0"), controller_signer=controller_signer
   )
   ```

4. Catch `DidWebvhError` (exported; `code` is `invalidDid`, `unauthorized`, ...) where you import logs or change DIDs.

## 6. HTTP request signatures are RFC 9421

### What changed

| | `rc2` | `rc3` |
|---|---|---|
| Covered components | `"@request-target" "host" "date" "content-digest" "x-request-nonce"` (signature base not RFC 9421) | `"@method" "@authority" "@path" "@query" "content-digest" "date" "signature-agent"` (RFC 9421 §2.5) |
| Nonce | `X-Request-Nonce` header | `nonce` signature parameter |
| Other parameters | `created`, `expires`, `keyid`, `alg` (optional on verify) | Also `tag="agent-did"`; `alg="ed25519"`, `expires` and `nonce` required |
| Replay protection | Left to the integrator | Built in: `verify_http_request_signature` records `(keyid, nonce)` in a `NonceStore` |
| Signature labels | Any | Lowercase RFC 8941 keys (`sig1`, `sig-a`, ...) |

### Impact

- Signatures made by `rc2` do not verify under `rc3`, and the other way round. Upgrade signers and verifiers together.
- `sign_http_request` no longer returns `X-Request-Nonce`; forward every header it returns (`Signature-Agent`, `Date`, `Content-Digest`, `Signature-Input`, `Signature`).
- Verifying the same signed request twice now returns `False` the second time. Tests that re-verify fixed headers need a fresh `InMemoryNonceStore` per check.
- Remove any custom nonce cache built on `X-Request-Nonce`.

### What to do

1. Upgrade both sides. Proxies must forward `Signature-Agent`, `Date`, `Content-Digest`, `Signature-Input` and `Signature` unchanged, and must not rewrite the method, host, path or query.
2. With several verifier instances, pass a shared store: `VerifyHttpRequestSignatureParams(..., nonce_store=store)`. A Redis example is in [Anti-Replay-HTTP-Signatures.md](../docs/Anti-Replay-HTTP-Signatures.md).
