# @agentdid/sdk Migration Guide: 1.0.0-rc.2 -> 1.0.0-rc.3

This guide covers the breaking changes between `1.0.0-rc.2` and `1.0.0-rc.3`. Read it before upgrading; rc.2 and rc.3 do not interoperate.

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

## 3. `systemPromptHash` and `coreModelHash` are salted commitments

### What changed

`create()` now commits to `systemPrompt` and `coreModel` with `hash://hmac-sha256/<hex>`, an HMAC-SHA256 keyed with a random 32-byte salt per field, instead of an unsalted `hash://sha256/` digest. Unsalted digests of short or predictable prompts can be confirmed by anyone who guesses them.

- `CreateAgentResult.metadataCommitmentSalts` returns `{ coreModel, systemPrompt }` salts **once**. The SDK does not store them.
- `CreateAgentParams.coreModelSalt` / `systemPromptSalt` let you supply your own salts (64 hex characters).
- `updateDidDocument` **requires** `coreModelSalt` / `systemPromptSalt` when the patch changes `coreModel` / `systemPrompt`; it throws otherwise.

### What to do

```ts
import { generateCommitmentSalt, verifyMetadataCommitment } from '@agentdid/sdk';

const { document, metadataCommitmentSalts } = await identity.create({ name, coreModel, systemPrompt });
// Store metadataCommitmentSalts with the agent's other secrets.

await AgentIdentity.updateDidDocument(did, {
  systemPrompt: newPrompt,
  systemPromptSalt: generateCommitmentSalt(),
});

// An auditor who receives (systemPrompt, salt) out of band:
verifyMetadataCommitment(document.agentMetadata.systemPromptHash, systemPrompt, salt); // true
```

Existing documents keep their `hash://sha256/` values; `verifyMetadataCommitment` still verifies them without a salt. Code that recomputed `generateAgentMetadataHash(prompt)` to compare against a new document must switch to `verifyMetadataCommitment` with the salt.

## 4. Node.js 22.12 or later

### What changed

`engines.node` is now `>=22.12.0` (was `>=22.0.0`). The SDK depends on `didwebvh-ts` for `did:webvh` v1.0 support ([ADR-002](../docs/ADR-002-did-webvh-v1.0-Implementation.md)), and that package needs `require(esm)`, which is unflagged from Node.js 22.12.

### What to do

Run on Node.js 22.12 or later. The October 2026 security releases (22.23.4+, 24.22.1+ or 26.12.1+) already meet the floor.

## 5. `did:webvh` DIDs are did:webvh v1.0 DIDs

### What changed

[ADR-002](../docs/ADR-002-did-webvh-v1.0-Implementation.md) moves the canonical `did:webvh` path to the DIF did:webvh v1.0 specification, through the reference implementation `didwebvh-ts`:

| | `rc.2` | `rc.3` |
|---|---|---|
| SCID | Random (or `webvh.scid`) | Derived from the genesis log entry; `webvh.scid` is removed and rejected |
| `did.jsonl` | Agent-DID format: `versionId`, `versionTime`, `state` | v1.0: `parameters` (`updateKeys`, ...), hash-chained `versionId`, `eddsa-jcs-2022` proof per entry |
| Who signs the log | Nobody | The controller key (`updateKeys`) |
| Explicit profile (`webvh.domain`) | `domain`, `controllerDid` | Also `controllerSigner: AgentSigner` (required) |
| Implicit `agents.local` profile | Controller DID derived from the wallet address | Controller DID is a v1.0 log; a new bootstrap is a new DID |
| `revokeDid` | Registry only | Appends `deactivated: true` to the log; the registry record is a derived index |
| Revocation state on `resolve` | Registry `isRevoked` | The verified log; `registry.revoke` alone no longer revokes a `did:webvh` DID |
| Resolution | — | `UniversalResolverClient` fetches `did.jsonl` and verifies it; failures raise `DocumentIntegrityError` without fallback; deactivated DIDs are refused |

### Impact

- `did:webvh` DIDs and `did.jsonl` files produced by `rc.2` or earlier do not verify and cannot be upgraded in place: the SCID is bound to the genesis entry.
- `AgentIdentity.resolve` takes the revocation state of a `did:webvh` DID from its verified log, not from the registry. Code that revoked a `did:webvh` DID by calling the registry directly must call `revokeDid` (with the controller signer) instead. A stored log that no longer verifies makes `resolve` throw.
- `updateDidDocument`, `rotateVerificationMethod` and `revokeDid` need the controller signer. In the process that created the DID it is retained automatically. After `importDidWebvhHistory` (or the file/source restore helpers) pass it explicitly; otherwise they throw.
- A `webvhDocumentSource` passed to `useProductionResolver` must implement `getDidLogByReference`. Sources that only return parsed documents are refused for `did:webvh`.
- `did:webvh` DIDs must use a lowercase ASCII host name (no IP literals), an optional port encoded as `%3A`, and unencoded path segments.

### What to do

1. Re-issue each `did:webvh` agent with `rc.3` and publish the new `did.jsonl` (`exportDidWebvhHistory(did)`) at the URL the DID maps to: `https://<host>/<path...>/did.jsonl`, or `https://<host>/.well-known/did.jsonl` without a path.
2. Explicit profile: pass the controller's key, ideally KMS/HSM-backed:

   ```ts
   await identity.create({
     name: 'support-bot', coreModel, systemPrompt,
     webvh: { domain: 'agents.example.com', pathSegments: ['support-bot'], controllerDid, controllerSigner }
   });
   ```

3. Lifecycle operations on an imported DID:

   ```ts
   await AgentIdentity.importDidWebvhHistory(log);
   await AgentIdentity.updateDidDocument(did, { version: '1.1.0' }, { controllerSigner });
   ```

4. Catch `DidWebvhError` (exported; `code` is `invalidDid`, `unauthorized`, ...) where you import logs or change DIDs.

## 6. HTTP request signatures are RFC 9421

### What changed

| | `rc.2` | `rc.3` |
|---|---|---|
| Covered components | `"@request-target" "host" "date" "content-digest" "x-request-nonce"` (signature base not RFC 9421) | `"@method" "@authority" "@path" "@query" "content-digest" "date" "signature-agent"` (RFC 9421 §2.5) |
| Nonce | `X-Request-Nonce` header | `nonce` signature parameter |
| Other parameters | `created`, `expires`, `keyid`, `alg` (optional on verify) | Also `tag="agent-did"`; `alg="ed25519"`, `expires` and `nonce` required |
| Replay protection | Left to the integrator | Built in: `verifyHttpRequestSignature` records `(keyid, nonce)` in a `NonceStore` |
| Signature labels | Any | Lowercase RFC 8941 keys (`sig1`, `sig-a`, ...) |

### Impact

- Signatures made by `rc.2` do not verify under `rc.3`, and the other way round. Upgrade signers and verifiers together.
- `signHttpRequest` no longer returns `X-Request-Nonce`; forward every header it returns (`Signature-Agent`, `Date`, `Content-Digest`, `Signature-Input`, `Signature`).
- Verifying the same signed request twice now returns `false` the second time. Tests that re-verify fixed headers need a fresh `InMemoryNonceStore` per check.
- Remove any custom nonce cache built on `X-Request-Nonce`.

### What to do

1. Upgrade both sides. Proxies must forward `Signature-Agent`, `Date`, `Content-Digest`, `Signature-Input` and `Signature` unchanged, and must not rewrite the method, host, path or query.
2. With several verifier instances, pass a shared store: `verifyHttpRequestSignature({ ..., nonceStore })`. A Redis example is in [Anti-Replay-HTTP-Signatures.md](../docs/Anti-Replay-HTTP-Signatures.md).
