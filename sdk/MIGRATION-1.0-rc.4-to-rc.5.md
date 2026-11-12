# @agentdid/sdk Migration Guide: 1.0.0-rc.4 -> 1.0.0-rc.5

Behavior changes between `1.0.0-rc.4` and `1.0.0-rc.5`. There are no wire-format changes (the API removals are in sections 8 and 10): DID documents, DID logs, hash URIs and signature bases are unchanged, and documents or signatures produced by rc.4 stay valid.

All changes below tighten the defaults of the SDK's HTTP handling. Code that already passes its own `fetchFn`, or that only talks to public HTTPS hosts and signs with the default lifetime, needs no change.

## 1. Default HTTP client: redirects, DNS and target addresses

The default `fetch` of the HTTP document sources (`HttpDIDDocumentSource`, `BearerTokenHttpDIDDocumentSource`, `JsonRpcDIDDocumentSource`, `WebvhDIDDocumentSource`, `AwsSigV4S3DIDDocumentSource`) now:

- **Does not follow redirects.** A `3xx` response is reported as a non-OK status. If your resolver endpoint redirects (for example `http://` to `https://`, or a moved path), point the source at the final URL.
- **Resolves the host name once and connects to the validated address.** The request is refused when the name does not resolve, or when any resolved address is not globally routable. The connection uses the address that was checked, and TLS still verifies the original host name.
- **Rejects every non-globally-routable range.** This covers private, shared (`100.64.0.0/10`), loopback, link-local, documentation, benchmarking, multicast and reserved IPv4, and IPv6 outside global unicast space (`2000::/3`). IPv4-mapped, NAT64 and 6to4 addresses are judged by the IPv4 address they embed.
- **Gives each request one deadline** (`timeoutMs`, default 10 s, `DEFAULT_HTTP_TIMEOUT_MS`) that covers the lookup, the connection and the whole body. rc.4 relied on the platform `fetch` defaults, which wait up to 5 minutes for the headers and between body chunks, so a server sending the body slowly could hold a request open indefinitely.
- **Caps the response body** (`maxResponseBytes`, default 1 MiB, `DEFAULT_MAX_RESPONSE_BYTES`), whether or not the server declares a `Content-Length`. A did:webvh log grows with every entry; raise the limit if yours is larger.
- **Asks for an unencoded body** (`Accept-Encoding: identity`) and rejects a response with any other `Content-Encoding`, so the cap applies to the bytes that are parsed. Servers that compress regardless of `Accept-Encoding` fail; serve those files uncompressed or supply your own `fetchFn`.
- **Relies on Node.js modules** (`node:http`, `node:https`, `node:dns`). Where those are not available, supply your own `fetchFn` to the sources that accept one.

The limits are part of `httpSecurity` (type `HttpSecurityOptions`), on the sources and on `useProductionResolverFromHttp` / `useProductionResolverFromJsonRpc`:

```ts
client.useProductionResolverFromHttp({
  registry,
  httpSecurity: { timeoutMs: 5_000, maxResponseBytes: 4 * 1024 * 1024 },
});
```

If you must reach an internal endpoint (a resolver inside a private network, a local test server), opt out explicitly:

```ts
new HttpDIDDocumentSource({
  referenceToUrl: (ref) => `http://did-resolver.internal:8080/${ref}`,
  httpSecurity: { allowPrivateTargets: true },
});
```

A `fetchFn` you supply owns its own redirect, DNS and limit policy; the SDK does not wrap it.

The `UniversalResolverClient` cache is now bounded: `maxCacheEntries` (default 1000, `DEFAULT_RESOLVER_MAX_CACHE_ENTRIES`; also on the `useProductionResolver*` configs). When it is full, expired entries are dropped first and then the least recently used. A process that relies on more than 1000 documents staying in the cache (for example documents registered locally with `registerDocument`) should raise it.

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

## 4. HTTP signature verification enforces the component order and never throws for an unbound key

- `verifyHttpRequestSignature` now requires the signature to cover `"@method" "@authority" "@path" "@query" "content-digest" "date" "signature-agent"` **in this order**, as RFC-001 §6.5 item 2 states; additional components may only follow. Before, any order (and any position of extra components) was accepted. Signatures from the SDK's own signer already use this order, so they are unaffected. A third-party signer that lists the components in another order must change its `Signature-Input`.
- A signed request whose `keyid` is not an `assertionMethod` key of the `Signature-Agent` DID (a fragment the document does not have, or a key listed only under `keyAgreement`) is now rejected: `verifyHttpRequestSignature` resolves to `false`. In rc.4 it rejected with an `IdentityCompositionError`. Remove any `try/catch` that only handled that case; keep the check on the returned value.
- `Content-Digest` must be exactly `sha-256=:<base64>:`. A dictionary with further algorithms is rejected, as before; RFC-001 §6.5 item 1 now says so.

## 5. New: the reason of a rejected HTTP signature (optional)

`client.verifyHttpRequestSignatureDetailed(params)` returns `{ ok: true }` or `{ ok: false, reason }` (`HttpSignatureRejection`). `verifyHttpRequestSignature` is unchanged and still returns a boolean; nothing needs to change. If you adopt the detailed method, test `result.ok`: the result object is truthy for a rejection too. See [docs/Anti-Replay-HTTP-Signatures.md](../docs/Anti-Replay-HTTP-Signatures.md) for the reasons.

## 6. New: did:webvh pre-rotation (optional)

Nothing changes for DIDs that do not use it. To be able to recover a DID after a compromise of its controller key, commit at creation to keys that will sign the next log entry, and keep their private keys offline:

```ts
const { document } = await identity.create({
  /* ... */
  didMethod: 'webvh',
  webvh: {
    domain, controllerDid, controllerSigner,
    nextUpdateKeys: [encodePublicKeyMultibase(await recoverySigner.getPublicKey())],
  },
});

// After a compromise: the committed key takes the DID back and commits to the following key.
await client.rotateControllerKey(document.id, { newControllerSigner: recoverySigner, nextUpdateKeys: [nextRecoveryKey] });
```

While commitments are in force the key in `controllerSigner` can no longer sign log entries, so operations on such a DID (`updateDidDocument`, `rotateVerificationMethod`, `revokeDid`) need the committed key as `controllerSigner`. It protects only if committed before the compromise. `DidWebvhMetadata` gains `nextKeyHashes`; `client.getDidWebvhControllerKeys(did)` returns the active keys and the commitments.

## 7. New: required verification relationship per artifact kind (optional)

Nothing changes for code that verifies payloads or HTTP requests: the defaults are still `assertionMethod`, now read from `REQUIRED_RELATIONSHIP_BY_ARTIFACT`. If you verify other signed artifacts, pass the relationship RFC-001 §6.2.1.3 requires for them instead of the default:

```ts
import { AgentIdentity, requiredRelationshipFor } from '@agentdid/sdk';

await AgentIdentity.verifySignature(issuerDid, payload, signature, keyId, requiredRelationshipFor('delegation'));
```

A key listed only under `assertionMethod` is rejected for a delegation with `key_purpose_violation`. Documents created by the SDK list the agent key under `authentication` and `assertionMethod`. An agent that issues delegations (or invokes delegated capabilities) opts in at creation; the key is then also listed under those relationships, and key rotation carries them over to the new key:

```ts
await identity.create({ ...params, additionalVerificationRelationships: ['capabilityDelegation'] });
```

Without the option the document is the same as before.

## 8. Breaking: `verifyHistoricalSignature` is removed; use `verifySignatureAtTime`

`verifyHistoricalSignature` (on `AgentDidClient` and the `AgentIdentity` facade) is removed. It accepted any retired key still in the document, with no time check, so it also accepted signatures forged with a key after it was retired. Replace it with `verifySignatureAtTime`, which checks the key against the DID's did:webvh log at the time the artifact states (RFC-001 §6.2.2):

```ts
await client.importDidWebvhHistory(didLog); // for DIDs not created by this client
const result = await client.verifySignatureAtTime(did, payload, signature, keyId, { statedTime });
// result.status: 'valid' | 'invalid' | 'indeterminate'
```

A key retired after `statedTime` gives `indeterminate`, not `valid`: the stated time is the signer's claim. Pass `trustedTimeNotAfter` only from evidence you trust (for example a verified RFC 3161 timestamp). Code that accepted rotated-key signatures through `verifyHistoricalSignature` must now decide what to do with `indeterminate`; accepting it reopens the gap the new API closes.

## 9. EVM profile (`@agentdid/evm`): moved to its own repository

The EVM profile (the `AgentRegistry` contract and `@agentdid/evm`) now lives in [edisonduran/agent-did-evm](https://github.com/edisonduran/agent-did-evm) ([ADR-004](../docs/ADR-004-EVM-Profile-Satellite.md)). The npm package keeps its name, so nothing changes in your imports. `@agentdid/sdk` never depended on it.

`AgentRegistry` registration now requires an EIP-712 attestation from a registrar, so an unrelated account can no longer register someone else's DID; see the `@agentdid/evm` README for the registrar flow. `revokeAgent` also works while the registry is paused.

## 10. did:webvh adapter: `versionNumber` moved out of the metadata

If you import the did:webvh adapter module directly (`resolveDidWebvhLog` and the log helpers of `webvh/adapter`; they are not exported from the package root), read the version number from the result instead of its metadata. `DidWebvhMetadata` now holds only values that DID Core §7.3 allows in DID document metadata (strings, lists, booleans).

```diff
  const result = await resolveDidWebvhLog(log);
- result.metadata.versionNumber
+ result.versionNumber
```

## 11. did:webvh revocation empties `updateKeys`

`revokeDid` now writes the deactivation entry with `updateKeys: []`, as did:webvh v1.0 recommends: a revoked DID lists no key that could authorize a later entry. It kept the active keys before. Verification does not change, and logs revoked by an earlier release still verify.

- `getDidWebvhControllerKeys` (and `metadata.updateKeys` from the adapter module) return an empty list for a revoked DID. The key that signed the revocation is in the proof of the last log entry.
- A DID with pre-rotation in force (section 6) is revoked in two log entries, both signed by the committed key: the first ends pre-rotation, the second deactivates. The call is the same.
- The SDK depends on `didwebvh-ts` `3.1.0` exactly (was the range `~3.0.0`), so an install gets the release the SDK was tested with. `didwebvh-ts` 3.0.1, which the earlier range admits, already writes the entry this way. If your project also depends on `didwebvh-ts` with another version, npm installs both.

## 12. `FilesystemDIDDocumentSource` needs a root directory or a mapping; IPFS gateway; binary bodies

- `new FilesystemDIDDocumentSource()` throws. Pass `{ rootDirectory }` (a reference is stored as `<root>/<safe name>.json`) or `referenceToPath` / `referenceToPaths`, as before. Files written by the old default under a raw reference path are not found under the new names.
- The default IPFS gateway is `https://ipfs.io/ipfs/` only (`cloudflare-ipfs.com` is retired). Set `ipfsGateways` for others.
- `body` of `signHttpRequest` and `verifyHttpRequestSignature` is `string | Uint8Array`. Strings behave as before.
- `WebvhDIDDocumentSource` and `WebvhDIDDocumentSourceConfig` are exported from `@agentdid/sdk`.

## 13. Breaking: the `did:agent` profile is removed

- Remove `didMethod: 'agent'` and `didMethod: 'webvh'` from `create` params: there is one profile, `did:webvh`.
- Remove `network` from `new AgentIdentity({ ... })`, and the `network` argument of `AgentDidClient.createAgent(controllerSigner, params)`.
- Existing `did:agent` documents registered in a registry still resolve and verify through the registry and `documentRef` path; new ones cannot be created. Create `did:webvh` agents and re-register.
- Fixtures: if you pinned `fixtures/canonical-document-reference.json`, `expectedDocumentRef` is now `hash://sha256/6a9b500a0278d4f43280f5bc58788e14c63be092925b7bd0d165bdd49e933b94` (the document ids changed, not the canonicalization); `fixtures/interop-vectors.json` no longer has a `legacy` vector.

## 14. `exports` map and ES module entry

`@agentdid/sdk` now declares `exports`: the package root (`import` -> `dist/index.mjs`, `require` -> `dist/index.js`, types) and `./package.json`. ES module projects can `import { AgentIdentity } from '@agentdid/sdk'`; `require` keeps working and returns the same objects. Deep imports such as `@agentdid/sdk/dist/core/AgentIdentity` stop resolving: import from the package root.

## 15. Controller binding: an agent verifies only if its controller endorsed its last log entry

A did:webvh agent whose document names a `controller` other than itself verifies only if the proof of the last entry of its log was made by a key that is active under `capabilityInvocation` of the controller's document (RFC-001 §6.6 item 7). Verification fails with `controller_not_bound` otherwise, and when the controller does not resolve or the verifier does not have the agent's log (a resolver that returns only documents cannot prove the binding).

- Agents created under the SDK's local bootstrap controller are bound out of the box. A bootstrap controller created in rc.4 does not list its key under `capabilityInvocation`: add it with `addVerificationMethod(did, { signer })` (the same key can be added under a new id), then give each agent one new entry signed by that key (any `updateDidDocument`).
- Agents with an explicit controller (`webvh.controllerDid` / `controllerSigner`): the controller's published DID document must list the signing key under `capabilityInvocation`.
- Verifiers must hold the agent's log: fetched by the production resolver, or loaded with `importDidWebvhHistory`.
- Rotating the controller's key without unbinding its agents: (1) `addVerificationMethod(controllerDid, { signer: newKey })`; (2) for each agent `rotateControllerKey(agentDid, { newControllerSigner })` and then `updateDidDocument(agentDid, patch, { controllerSigner: newKey })`; (3) `rotateVerificationMethod(controllerDid, { signer: newKey })`. Retiring the old key before step 2 unbinds the agents. With pre-rotation, the committed key that signs the agent's next entry must already be listed under the controller's `capabilityInvocation`.
- `AgentDidClient` gains `resolveDidWebvhState` (the verified log, `updateKeys`, the keys that signed the last entry and the provenance) and `addVerificationMethod`.

## 16. Resolution and import of did:webvh logs

- `importDidWebvhHistory` rejects a log that does not extend the one stored in the client (an older prefix or a different history); the same log is a no-op. Import the newer log, or use a fresh client.
- did:webvh resolution through `UniversalResolverClient` has no fallback: a DID whose log cannot be fetched (or is not found) fails closed. DIDs that relied on the fallback to the pre-production in-memory resolver now need a reachable log host, or a fresh import within the cache TTL.
- A DID created or changed in the client is resolved from its local log. A test that replaced the document of such a DID through a custom resolver must use a separate verifier client holding the documents and logs it wants resolved.
- A target blocked by the SSRF policy now fails with `blocked by SSRF policy` instead of returning "not found".

## 17. Rotation, key ids and public key encodings

- `rotateVerificationMethod` removes the retired keys from every verification relationship. Documents of DIDs rotated in rc.4 still list them; run any `updateDidDocument` to republish the document without them.
- `signHttpRequest` requires `verificationMethodId`: pass `document.authentication[0]` or the id the rotation returned (the `#key-1` default named the wrong key after a rotation).
- The new key of a rotation can live in a KMS/HSM: `rotateVerificationMethod(did, { signer })`; the result's private key is then empty.
- `publicKeyMultibase` is decoded only as `z` + Base58btc(`0xed01` + key): the SDK 0.x `z`+hex form and raw keys without the multicodec prefix are rejected. Re-encode such documents.
- Ed25519 signatures with non-canonical or torsion-carrying points are rejected in both SDKs (RFC-001 §7, `fixtures/ed25519-verification-vectors.json`). A signature that is not valid hex, or an empty key id, fails verification instead of throwing or being ignored.

## 18. Breaking: payload signatures carry a domain prefix; verified handoffs sign an envelope

- `signMessage` signs `agent-did/v1/message` + a line feed + the payload, and `verifySignature` / `verifySignatureAtTime` apply the same prefix. **Payload signatures made by rc.4 do not verify in rc.5 (and rc.5 signatures do not verify in rc.4); there is no compatibility mode.** Re-sign stored payload signatures. A third-party verifier prepends the UTF-8 prefix before the Ed25519 check. HTTP request signatures are unchanged.
- Microsoft Agent Framework (`agent-did-microsoft-agent-framework`): sign handoffs with `sign_handoff(...)` instead of building `SignedHandoffMessage` by hand, passing the downstream executor id as `destination`; payloads must be JSON-serializable; add `allowed_dids` to `irreversible` edges; pass a shared `nonce_store` when several workflow instances verify the same edge. New block reasons: `destination`, `nonce`, `signed_at`, `payload`, `replay`.

## 23. Integrations sign with the agent's external signer

- `createAgent` / `create`, `rotateVerificationMethod` and `addVerificationMethod` return the `signer` you passed for the agent key as `result.signer` (non-enumerable: `JSON.stringify` and object spread skip it). The LangChain JS integration signs payloads and HTTP requests with it when present; before, an agent created with a KMS or HSM signer could not sign through the integration.
- The `rotate_key` tool refuses an agent whose key lives in an external signer: rotate it with `client.rotateVerificationMethod(did, { signer: newSigner })` and pass the result to the integration.
- `JSON.stringify(localKeySigner)` is `{"type":"LocalKeySigner"}`.

## Checklist

- [ ] Resolver endpoints no longer rely on redirects.
- [ ] Internal endpoints set `httpSecurity: { allowPrivateTargets: true }`.
- [ ] Non-Node runtimes pass their own `fetchFn`.
- [ ] Endpoints answer within 10 s with an uncompressed body of at most 1 MiB, or `httpSecurity.timeoutMs` / `maxResponseBytes` are raised.
- [ ] Processes that need more than 1000 cached documents set `maxCacheEntries`.
- [ ] Third-party signers with a lifetime above 300 s are covered by `maxSignatureLifetimeSeconds`.
- [ ] Third-party signers list the seven required components in the order of RFC-001 §6.5 item 2, with extra components after them.
- [ ] Code around `verifyHttpRequestSignature` no longer expects an `IdentityCompositionError` for an unbound `keyid`.
- [ ] Decide whether your controller DIDs should commit to recovery keys (`webvh.nextUpdateKeys`); it only helps if done before a compromise.
- [ ] Verifiers of delegations, invocations or authentication challenges pass `requiredRelationshipFor(...)` instead of the `assertionMethod` default.
- [ ] Agents that issue delegations or invoke capabilities are created with `additionalVerificationRelationships`.
- [ ] Code that reads the controller keys of a revoked did:webvh DID expects an empty list.
- [ ] Calls to `verifyHistoricalSignature` are replaced with `verifySignatureAtTime`, and `indeterminate` is handled as not accepted.
- [ ] EVM users follow `@agentdid/evm` in `edisonduran/agent-did-evm` for issues and releases.
- [ ] Direct users of the did:webvh adapter read `result.versionNumber` instead of `result.metadata.versionNumber`.
- [ ] Every `signHttpRequest` call passes `verificationMethodId`.
- [ ] Stored payload signatures are re-signed with rc.5 (the signed bytes carry the `agent-did/v1/message` prefix).
- [ ] Agents with an explicit controller are listed under the controller's `capabilityInvocation`; bootstrap controllers from rc.4 get the key added (`addVerificationMethod`).
- [ ] Verifiers hold the agent's did:webvh log (production resolver or `importDidWebvhHistory`); no code relies on a fallback for did:webvh.
- [ ] DIDs rotated in rc.4 were republished once (`updateDidDocument`) so retired keys leave the relationships.
- [ ] `FilesystemDIDDocumentSource` has a `rootDirectory` or a mapping; `create` no longer passes `didMethod` or `network`.
- [ ] ES module projects import from the package root only (no deep imports).
