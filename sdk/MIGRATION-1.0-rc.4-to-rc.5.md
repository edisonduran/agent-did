# @agentdid/sdk Migration Guide: 1.0.0-rc.4 -> 1.0.0-rc.5

Behavior changes between `1.0.0-rc.4` and `1.0.0-rc.5`. rc.5 is the last release candidate that changes the wire: payload signatures (section 18) and HTTP request signatures (section 34) made by rc.4 do not verify in rc.5. DID documents and did:webvh logs made by rc.4 stay valid (sections 31 and 32 change what new documents contain, not how old ones verify).

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
- Fixtures: if you pinned `fixtures/canonical-document-reference.json`, `expectedDocumentRef` is now `hash://sha256/8671ddc531a02613d99c027cb1328f4ffcaedcf2e7e3a6dc93df13e66fe4ac65` (the document ids changed, not the canonicalization); `fixtures/interop-vectors.json` no longer has a `legacy` vector.

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

- `signMessage` signs `agent-did/v1/message` + a line feed + the payload, and `verifySignature` / `verifySignatureAtTime` apply the same prefix. **Payload signatures made by rc.4 do not verify in rc.5 (and rc.5 signatures do not verify in rc.4); there is no compatibility mode.** Re-sign stored payload signatures. A third-party verifier prepends the UTF-8 prefix before the Ed25519 check. HTTP request signatures do not take the prefix; they change for another reason (section 34).
- Microsoft Agent Framework (`agent-did-microsoft-agent-framework`): sign handoffs with `sign_handoff(...)` instead of building `SignedHandoffMessage` by hand, passing the downstream executor id as `destination`; payloads must be JSON-serializable; add `allowed_dids` to `irreversible` edges; pass a shared `nonce_store` when several workflow instances verify the same edge. New block reasons: `destination`, `nonce`, `signed_at`, `payload`, `replay`.

## 19. Breaking: `BearerTokenHttpDIDDocumentSource` needs `allowedOrigins`; JSON-RPC and pinned connections

- `BearerTokenHttpDIDDocumentSource` requires `allowedOrigins`, the origins its credential may be sent to (`https://host`, with the port when it is not the default). A request to any other origin is refused before the token is resolved, so the source can serve as `wbaDocumentSource` or `webvhDocumentSource` (whose URLs come from the DID) without handing the token to the DID's host:

  ```ts
  new BearerTokenHttpDIDDocumentSource({ token, allowedOrigins: ['https://storage.example.com'] });
  ```

- `JsonRpcDIDDocumentSource.getByReference` throws when an endpoint is blocked by the target policy, as `HttpDIDDocumentSource` does. It returned `null` ("not found") before. It returns `null` only when every endpoint answers "not found".
- The default `fetch` opens a connection of its own for each request to a host name and no longer shares the process-wide keep-alive pool.

## 20. Breaking: HTTP signatures need a request URL in normalized form; payload signature hex is strict

- `signHttpRequest` refuses, with `HttpSignatureError`, a URL that is not already percent-encoded and normalized: spaces or non-ASCII characters (send `%20`, `%C3%A9`), an internationalized host that is not in punycode, an uppercase scheme or host, user information, a fragment, `.` or `..` path segments, an empty `?`, a `'` in the query (`%27`), or an IP host that is not in canonical form. Verification rejects such a request with the reason `url_not_normalized`. `requestUrlFormProblem(url)` returns why a URL is refused (or nothing). Build the URL from encoded parts before signing and send exactly that URL.
- A payload signature passed to `verifySignature` must be exactly 128 hex digits, without spaces or a `0x` prefix.

## 21. New: who signed an HTTP request, and allow-lists (optional)

- An accepted `verifyHttpRequestSignatureDetailed` result is `{ ok: true, did, keyId, controllers }`. `HttpSignatureRejection` gains `did_not_allowed` and `controller_not_allowed`: a `switch` that lists every reason needs the two new cases.
- A valid signature proves which DID signed, not that you should accept it. Pass `allowedDids` (the `Signature-Agent` DIDs you accept; checked before any resolution) and/or `allowedControllers` (accept agents operated by these controllers), or read `result.did` and decide yourself.

```ts
const result = await client.verifyHttpRequestSignatureDetailed({ ...request, allowedControllers: [partnerOrgDid] });
```

## 22. Resolution limits; integration tools that resolve DIDs are opt-in

- The universal resolver remembers a failed did:webvh / did:wba resolution for 5 s (`resolutionLimits.negativeCacheTtlMs`, 0 turns it off), shares one fetch between concurrent resolutions of the same DID and runs at most 16 fetches at once (`maxConcurrentFetches`). Code that retries a failing DID within 5 s gets the same error without a new request.
- New optional `resolutionLimits.allowedHosts` (on `UniversalResolverConfig` and the `useProductionResolver*` profiles): only DIDs on these hosts are fetched. Set it on verifiers that know their peers.
- LangChain JS: `expose.resolveDid` and `expose.verifySignatures` default to `false`. Set them to `true` where the agent needs them, together with `allowedHosts`.

```ts
client.useProductionResolverFromHttp({ registry, resolutionLimits: { allowedHosts: ['*.partner.example'] } });
```

## 23. Integrations sign with the agent's external signer

- `createAgent` / `create`, `rotateVerificationMethod` and `addVerificationMethod` return the `signer` you passed for the agent key as `result.signer` (non-enumerable: `JSON.stringify` and object spread skip it). The LangChain JS integration signs payloads and HTTP requests with it when present; before, an agent created with a KMS or HSM signer could not sign through the integration.
- The `rotate_key` tool refuses an agent whose key lives in an external signer: rotate it with `client.rotateVerificationMethod(did, { signer: newSigner })` and pass the result to the integration.
- `JSON.stringify(localKeySigner)` is `{"type":"LocalKeySigner"}`.

## 24. Smaller changes from the review

- Lifecycle operations of one DID run one at a time in a client; nothing to change unless you relied on parallel updates overwriting each other.
- Documents from outside the process (did:webvh logs, HTTP, JSON-RPC, files) are checked at runtime; a malformed one now fails with `... is not an Agent-DID document: ...`.
- did:wba: a host that cannot be reached or has no document fails, without the fallback resolver; a document for another DID is a `DocumentIntegrityError`.
- `InMemoryNonceStore` takes `maxEntriesPerScope` (default 10 000 per `keyid`); a client's default store follows `clock`.
- `evictCachedResolution(did)` drops a cached resolution. LangChain JS signs with the first active `assertionMethod` key.

## 25. Packaging

- `@agentdid/langchain` depends on `zod` `^4.6.7`. If your code passes zod schemas of its own to the integration, build them with zod 4 (or its `zod/v3` entry point).
- `@agentdid/sdk` no longer installs `multiformats`; import it yourself if you used it through the SDK's dependency tree.

## 26. did:wba host grammar

- The domain segment of a did:wba DID must decode to a DNS name with an optional port (`did:wba:agents.example%3A8443`). IP literals (`did:wba:127.0.0.1`), a numeric last label, and any character other than ASCII letters, digits, hyphens and dots are rejected before any request. Use a host name; for local tests, `localhost%3A<port>` still works.
- Path segments equal to `.` or `..` after decoding are rejected. Other path segments are re-encoded keeping only `A-Z a-z 0-9 - . _ ~`, so `!`, `'`, `(`, `)` and `*` are now sent percent-encoded (TypeScript sent them as they were). The host is lowercased and port 443 is dropped from the URL.


## 27. HTTP signature nonces follow a token grammar

- A `nonce` must be 1 to 256 characters of `A-Z a-z 0-9 . _ ~ + / = -` (RFC-001 §6.5 item 3). Verification rejects any other value with `params_missing`. The SDK signers send 32 hex digits, so only third-party signers that put spaces or other characters in the nonce must change.
- A custom `NonceStore` receives `<keyid> <nonce>` as before; the text before the last space is now always the `keyid`, so a store can scope per-signer quotas by it (as `InMemoryNonceStore` does with `maxEntriesPerScope`).


## 28. Bounded fetch queue in the universal resolver

- At most 64 did:webvh / did:wba fetches wait for a slot (`maxQueuedFetches`); a resolution that would wait beyond that fails at once with "too many DID fetches are waiting". Such a refusal is not remembered, so a retry fetches.
- At most 4 fetches run at once for one host name (`maxConcurrentFetchesPerHost`). A service that resolves many uncached DIDs on one host at the same time (a burst of new agents of one provider) sees the others wait; raise the limit for hosts you trust.
- The wait and the fetch together must finish within 15 s (`fetchDeadlineMs`). Keep it above the document source timeout (`httpSecurity.timeoutMs`, default 10 s), or a slow but healthy host fails at the deadline.

```ts
client.useProductionResolverFromHttp({
  registry,
  resolutionLimits: { maxConcurrentFetchesPerHost: 16, maxQueuedFetches: 256, fetchDeadlineMs: 30_000 }
});
```


## 29. An imported did:webvh log is not a fresh resolver entry

- With a resolver that fetches did:webvh logs (the production resolver), `importDidWebvhHistory` of a DID whose controller signer the client does not hold no longer caches the imported document. The next resolution fetches the host's log, and the longer of the fetched and the imported log wins.
- A verifier that imported a log and then resolved it while the log host was unreachable got the imported document for up to `cacheTtlMs`; it now gets a resolution error. Make the log host reachable, or use a resolver that does not fetch logs if the imported log is meant to be the only source.


## 30. Integrations share the SDK's sanitizer and target policy

- Integration events are sanitized by the SDK's `sanitizeObservabilityAttributes`. A redacted value is always `{"redacted": true, "length": n}`, also for sensitive headers (they were the string `"<redacted>"` in some integrations). Log parsers or alerts that matched `"<redacted>"` must match the marker.
- LangChain JS no longer exports `REDACTED_VALUE`; compare with `isRedactedMarker(value)` instead.
- The signing tools of the integrations validate the target URL with the SDK policy: the error messages are now `Unsupported protocol: …` and `Blocked request to private/reserved address: …`, and every non-global address range is refused, not only loopback and private ones.


## 31. Model and prompt commitments are optional

RFC-001 §4.3 now makes `coreModelHash` and `systemPromptHash` optional assertions by the controller.

- `CreateAgentParams.coreModel` and `systemPrompt` are optional. Omitted, the document has no `coreModelHash` / `systemPromptHash` and `metadataCommitmentSalts` has no salt for it. Existing calls that pass both produce the same documents as before.
- A `coreModelSalt` / `systemPromptSalt` without its value now throws.
- Type changes: `AgentMetadata.coreModelHash` / `systemPromptHash` and both members of `MetadataCommitmentSalts` are `string | undefined`. Code that reads them under `strict` needs a check; `verifyMetadataCommitment` accepts `undefined` and returns `false`.
- The local bootstrap controller document no longer carries placeholder commitments.
- Verifiers: do not reject a document without commitments, and do not read a matching commitment as proof of what the agent runs.

## 32. `Multikey` verification methods

RFC-001 §4.2 now requires `Multikey` for Ed25519 keys ([ADR-006](../docs/ADR-006-Wire-Alignment-rc5.md) D-8b).

- Documents created, updated or rotated by the SDK now write `"type": "Multikey"` for every key, with the same `publicKeyMultibase` value as before. Code or tests that compare the type with `Ed25519VerificationKey2020` must accept `Multikey`.
- rc.4 documents and did:webvh logs keep resolving and verifying: `Ed25519VerificationKey2020` is still read, and their signed entries are not rewritten.
- A document in which a method that carries `publicKeyMultibase` has any other type (`Ed25519VerificationKey2018`, `JsonWebKey2020`, a misspelt `multikey`, ...) is now rejected by every resolver source. Signature checks and the controller binding never take a key from such a method, and `checkDidWebvhKeyAtTime` reports `key_not_found` for it.
- Fixtures: if you pinned `fixtures/canonical-document-reference.json`, `expectedDocumentRef` is `hash://sha256/8671ddc531a02613d99c027cb1328f4ffcaedcf2e7e3a6dc93df13e66fe4ac65` (the value given in the `did:agent` section already includes this change); `fixtures/verification-relationship-vectors.json` gains `methodTypeVectors`.

## 33. Agent metadata credential (new, optional)

RFC-001 §4.4 adds the `AgentMetadataCredential` ([ADR-006](../docs/ADR-006-Wire-Alignment-rc5.md) D-8d). Nothing changes for existing code: documents, `agentMetadata` and signatures are as before.

- The controller issues it with `client.issueAgentMetadataCredential({ agentDid, signer, verificationMethodId })`, where `verificationMethodId` is an `assertionMethod` key of the controller (for the implicit bootstrap controller, `controllerDocument.assertionMethod[0]` with `new LocalKeySigner(created.controllerPrivateKey)`). Pass `agentMetadata` to share only some members, and `validUntil` to bound it.
- A relying party verifies it with `client.verifyAgentMetadataCredential(credential, { expectedAgentDid })` and reads `result.ok`, `result.reason`, `result.agentMetadata` and `result.controllers`. The metadata is the controller's assertion, not evidence of what the agent runs.

## 34. Breaking: the agent DID moves to the `Agent-DID` header

RFC-001 §6.5 ([ADR-006](../docs/ADR-006-Wire-Alignment-rc5.md) D-8a). `Signature-Agent` is a header of the IETF Web Bot Auth draft with another meaning (a key-directory URI), so Agent-DID no longer uses it.

- `signHttpRequest` returns `Agent-DID: sig1="<did>"`, a Structured Field Dictionary keyed by the signature label, instead of `Signature-Agent: <did>`, and the signature covers `"agent-did";key="sig1"` instead of `"signature-agent"`. Proxies, gateways and logging that pass or read `Signature-Agent` must pass or read `Agent-DID`.
- `verifyHttpRequestSignature` takes the DID from the `Agent-DID` member of each signature's label and never reads `Signature-Agent`. **HTTP signatures made by rc.4 do not verify in rc.5, and rc.5 signatures do not verify in rc.4; there is no compatibility mode.** Upgrade signers and verifiers together.
- New rejections: no `Agent-DID` header (`missing_headers`); a field that is not a Dictionary, or a member that is not a String or has parameters (`malformed_headers`); no member for the signature's label (`signed_component_missing`). `allowedDids` is now checked per signature, after the profile checks and still before any resolution, so a request with a wrong `Content-Digest` reports `digest_mismatch` before `did_not_allowed`.
- API: `AGENT_DID_HTTP_SIGNATURE_COMPONENTS` is removed; `agentDidHttpSignatureComponents(label)` returns the seven components, the last one `{ name: 'agent-did', key: label }`. New `AGENT_DID_HTTP_HEADER` (`'Agent-DID'`). `SignatureInput.components` is `ComponentIdentifier[]` (`string | KeyedComponent`): `parseSignatureInputHeader` returns a `KeyedComponent` for a component with a `key` parameter (the only component parameter supported; any other still throws), and `buildSignatureBase` takes the serialized Dictionary member as its value (RFC 9421 §2.1.2). Code that treats components as plain strings must handle the object form.
- Third-party signers: send `Agent-DID: <label>="<did>"` and cover `"agent-did";key="<label>"` with the signature's own label, last among the seven required components.
- Fixtures: `fixtures/http-verification-vectors.json` (84 vectors, with new `Agent-DID` cases) and `fixtures/interop-vectors.json` are regenerated, and the wire freeze is re-pinned.

## 35. Composition contract: signed Agent Cards, revoked keys, single-key retirement (new)

RFC-001 §4.2, §6.2.2, §6.6 item 3 and the [A2A Identity Composition Contract](../docs/RFC-001-A2A-Identity-Composition-Contract.md) (`[RFC]` #257).

- **Signed Agent Cards.** `signAgentCard(card, signer, keyId)` adds an A2A 1.0 §8.4 JWS (`alg` `EdDSA`, `kid` = the DID URL of an `assertionMethod` key, `typ` `JOSE`) over the JCS form of the card without `signatures`. Publish the agent DID and its keys in `capabilities.extensions` with `uri` `AGENT_DID_A2A_EXTENSION_URI`. `AgentDidClient.verifyAgentCard(card)` checks the format and every signature; `verifyIdentityComposition({ ...request, agentCard })` also checks that the request verifies and that its `keyid` is a key the card publishes. Both return `{ ok: false, reason }` with the contract reasons (`rotation_window_closed`, `emergency_revoked`, `key_purpose_violation`, `tampered`, `card_keyid_mismatch`, `format_drift`, `did_document_unresolvable`, `request_rejected`).
- **Single-key retirement.** `AgentDidClient.retireVerificationMethod(did, keyId)` retires one key and keeps the others. A planned rotation is now `addVerificationMethod` (both keys listed: the overlap) then `retireVerificationMethod` of the old key. It refuses the last `authentication` or `assertionMethod` key.
- **Emergency revocation.** `retireVerificationMethod(did, keyId, { emergency: true })` and `rotateVerificationMethod(did, { emergency: true })` also set `revoked` on the retired keys. A revoked key is `not_authorized` (`key_revoked`) in `verifySignatureAtTime` at every stated time, even with `trustedTimeNotAfter`. Use it when a key may be compromised.
- **Document format.** `VerificationMethod.revoked` is new, and a document with a revoked key ends its `@context` with the inline term `REVOKED_CONTEXT_TERM` (the published `https://agent-did.org/v1` context is immutable). `AgentDIDDocument['@context']` is now `AgentDidContextEntry[]` (a string or that term): code that treats every entry as a string must handle the object. The document guard rejects `revoked` without `deactivated`, a revoked key without the term, and the term without a revoked key. Documents without revoked keys are unchanged.
- Fixtures: `fixtures/composition-contract-vectors.json` (new, in `interop:check` and the wire freeze).

## 36. Controllers may be plain DID Core documents (breaking types)

RFC-001 §4.2.1. A did:webvh controller no longer has to be an Agent-DID document: an organization can use any DID Core `did:webvh` document as the `controller` of its agents. The binding rule (§6.6 item 7) does not change.

- **New:** `DidDocument` (a DID Core document; `AgentDIDDocument` extends it) and `VerificationRelationshipEntry`. `AgentDidClient.resolveDocument(did)` returns the DID Core document of a did:webvh DID; `resolve(did)` still returns only Agent-DID documents and now rejects a plain controller DID (`is not an Agent-DID document`). `DIDResolver.resolveDocument` is optional: a custom resolver without it keeps working, but then answers controllers with `resolve`, so they must be Agent-DID documents.
- **Breaking types:** `resolveControllerChain` returns `DidDocument[]` (it returned `AgentDIDDocument[]`), and `DidWebvhResolution.document` / `DidWebvhState.document` are `DidDocument`. The first element of a chain started at an agent is still that agent's document; cast it or check it before reading `agentMetadata`. Passing a chain element to `registerDocument` needs a cast.
- **Controller relationships:** the controller's `capabilityInvocation` (binding) and `assertionMethod` (`AgentMetadataCredential` issuer) accept relative references (`#key-1`) and embedded verification methods. Only Ed25519 `publicKeyMultibase` keys count; `publicKeyJwk` methods are ignored.
- **Fails closed:** a controller whose `controller` is a list rejects the chain (`did_resolution_failed` in the detailed results). A fetched did:webvh log whose state is not a DID Core document is a `DocumentIntegrityError` (`is not a DID document`); a state that is a DID Core document but not an Agent-DID document is no longer an integrity failure, `resolve` rejects it with a plain error.
- `verifySignature` / `verifySignatureAtTime` for a DID whose document is not an Agent-DID document fail (`did_resolution_failed`): signatures are verified for agents only.
- For other DID methods (did:wba, registry sources) controllers must still be Agent-DID documents.

## 37. did:webvh witnesses and RFC 3161 timestamps (new)

[ADR-007](../docs/ADR-007-Witnesses-and-Timestamps.md). Nothing changes for DIDs without witnesses or callers that pass no timestamp token, except the points marked below.

- **Witnesses:** `webvh: { ..., witness: { threshold, witnesses: ['did:key:z6Mk...'] } }` at creation, `client.setDidWebvhWitnesses(did, witness | null)` later. Give the client a collector, `new AgentDidClient({ collectWitnessProofs })`, that obtains the approvals of each governed entry (a witness signs with `createDidWebvhWitnessProof({ log, witnessFile, signer })`); without it, changing a witnessed DID throws before anything is stored. Publish `client.exportDidWebvhWitnessFile(did)` as `did-witness.json` next to `did.jsonl`, before the log.
- **Changed:** a log that declares witnesses used to be rejected; it now resolves when its `did-witness.json` is available and its approvals reach the thresholds, and fails closed otherwise. Only `WebvhDIDDocumentSource` fetches witness files (`getDidWitnessFileByReference`); a custom `webvhDocumentSource` must implement it to resolve witnessed DIDs.
- **Changed (types):** `DidWebvhMetadata` has `witnessThreshold` and `witnesses`; `DidWebvhResolution` / `DidWebvhState` have `witnessFile`. `importDidWebvhHistory(log, witnessFile?)`, `saveDidWebvhHistoryToFile(did, path, witnessPath?)`, `loadDidWebvhHistoryFromFile(path, witnessPath?)`, `persistDidWebvhHistoryToSource(did, ref, source, witnessRef?)` and `restoreDidWebvhHistoryFromSource(ref, source, witnessRef?)` take the witness file; the save and persist calls throw for a witnessed DID without it.
- **Timestamps:** `verifyTimestampToken(token, signatureBytes, { trustAnchors })` and `createTimestampRequest(signatureBytes)`. `verifySignatureAtTime(..., { statedTime, timestampToken, tsaTrustAnchors })` verifies the token over the decoded signature and uses `genTime + accuracy` as `trustedTimeNotAfter`; `trustedTimeNotAfter` together with a token, or a token without anchors, throws `TypeError`. A new result member `{ status: 'invalid', reason: 'timestamp_invalid', timestampRejection }` is added to `VerifySignatureAtTimeResult`; exhaustive switches on `reason` need the new case.
- **Dependencies:** `pkijs` and `asn1js` (pure JavaScript, WebCrypto) are new runtime dependencies.

## 38. Capabilities and OAuth client assertions (new)

[ADR-008](../docs/ADR-008-Delegation-OAuth-and-MCP.md), RFC-001 §6.7 and §6.8. Additive: no existing call or signature changes.

- **Delegation:** create the delegator with `additionalVerificationRelationships: ['capabilityDelegation']` and the invoker with `['capabilityInvocation']` (the SDK lists the agent key there only on request). `client.createCapability({ invocationTarget, controller, expires, allowedAction?, parentCapability?, verificationMethodId, signer })` returns the capability; `client.verifyCapabilityChain(capability, { rootControllers: { [target]: [ownerDid] } })` returns `{ ok, reason }`. The resource server decides `rootControllers`.
- **Invocation:** `identity.signHttpRequest({ ..., capability })` adds the `Agent-DID-Capability` field and covers it; the server calls `client.verifyHttpCapabilityInvocation({ ...request, rootControllers })`. `verifyHttpRequestSignatureDetailed` is unchanged and ignores the field.
- **OAuth:** `createClientAssertion({ clientId, issuer, verificationMethodId, signer })` gives the `client_assertion` of a token request (`client_assertion_type` = `CLIENT_ASSERTION_TYPE_JWT_BEARER`); `issuer` is the authorization server's issuer identifier, not its token endpoint. Publish `buildClientMetadataDocument({ clientId, clientName, didDocument })` at `clientId` (or register `buildClientJwks(document)`), and republish it after a key rotation. A server that knows Agent-DID checks assertions with `client.verifyClientAssertion({ assertion, issuer, clientId, did })`.
- **Changed (internal types):** `SignHttpRequestParams` gains `capability`. New exports are listed in `public-api.snapshot.txt`.

## 39. Agent Card signatures drop A2A 1.0 default values (wire change)

A2A 1.0 §8.4.1. `signAgentCard` and the card checks (`verifyAgentCard`, `verifyIdentityComposition`) now sign and verify the card without the members that hold their default value (`""`, `false`, `0`, `[]`, `{}`) where A2A 1.0 marks a field neither `REQUIRED` nor `optional`, for example `"required": false` in `capabilities.extensions` or `"tenant": ""` in `supportedInterfaces`. Members A2A 1.0 does not define are covered as they are.

- A card signed by rc.4 still verifies unless it contains such a member; re-sign the cards you serve after upgrading.
- Do not put members A2A 1.0 does not define in a card you sign: A2A verifiers that rebuild the card from its Protocol Buffer form drop them and the signature no longer matches.
- `agentCardSigningPayload(card)` (module `src/core/agent-card.ts`, not exported from the package root) returns the JWS payload; the shared vectors use it.

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
- [ ] Code that reads `resolveControllerChain` results or `DidWebvhState.document` as `AgentDIDDocument` checks or casts them (controllers may be plain DID Core documents).
- [ ] Code that reads the controller keys of a revoked did:webvh DID expects an empty list.
- [ ] Calls to `verifyHistoricalSignature` are replaced with `verifySignatureAtTime`, and `indeterminate` is handled as not accepted.
- [ ] Custom `webvhDocumentSource` implementations that must resolve witnessed DIDs implement `getDidWitnessFileByReference`; switches on `VerifySignatureAtTimeResult.reason` handle `timestamp_invalid`.
- [ ] EVM users follow `@agentdid/evm` in `edisonduran/agent-did-evm` for issues and releases.
- [ ] Direct users of the did:webvh adapter read `result.versionNumber` instead of `result.metadata.versionNumber`.
- [ ] Every `signHttpRequest` call passes `verificationMethodId`.
- [ ] Code that reads `@context` entries as strings handles the inline `revoked` term.
- [ ] A planned key rotation that must not break in-flight requests uses `addVerificationMethod` then `retireVerificationMethod`; a suspected compromise uses `emergency: true`.
- [ ] Stored payload signatures are re-signed with rc.5 (the signed bytes carry the `agent-did/v1/message` prefix).
- [ ] Agents with an explicit controller are listed under the controller's `capabilityInvocation`; bootstrap controllers from rc.4 get the key added (`addVerificationMethod`).
- [ ] Verifiers hold the agent's did:webvh log (production resolver or `importDidWebvhHistory`); no code relies on a fallback for did:webvh.
- [ ] DIDs rotated in rc.4 were republished once (`updateDidDocument`) so retired keys leave the relationships.
- [ ] Every `BearerTokenHttpDIDDocumentSource` lists its `allowedOrigins`.
- [ ] Code that treated a `null` from `JsonRpcDIDDocumentSource` with a blocked endpoint as "not found" handles the error.
- [ ] Code that reads `coreModelHash`, `systemPromptHash` or `metadataCommitmentSalts` handles a missing value, and no verifier policy requires the commitments.
- [ ] `FilesystemDIDDocumentSource` has a `rootDirectory` or a mapping; `create` no longer passes `didMethod` or `network`.
- [ ] ES module projects import from the package root only (no deep imports).
- [ ] Every URL passed to `signHttpRequest` is percent-encoded and normalized (`requestUrlFormProblem` returns nothing for it).
- [ ] Every HTTP verifier either passes `allowedDids` / `allowedControllers` or checks `result.did` before trusting the request.
- [ ] Agents that use the LangChain `resolve_did` / `verify_signature` tools enable them in `expose`; verifiers that know their peers set `resolutionLimits.allowedHosts`.
- [ ] HTTP signers and verifiers are upgraded together, and proxies or gateways forward `Agent-DID` (rc.4 HTTP signatures do not verify in rc.5).
- [ ] Code that used `AGENT_DID_HTTP_SIGNATURE_COMPONENTS` calls `agentDidHttpSignatureComponents(label)` and handles `KeyedComponent` entries.
- [ ] Agent Cards you serve are re-signed after the upgrade and contain only A2A 1.0 members.
