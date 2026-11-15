# agent-did-sdk Migration Guide: 1.0.0rc4 -> 1.0.0rc5

Behavior changes between `1.0.0rc4` and `1.0.0rc5`. rc5 is the last release candidate that changes the wire: payload signatures (section 18) and HTTP request signatures (section 36) made by rc4 do not verify in rc5. DID documents and did:webvh logs made by rc4 stay valid (sections 33 and 34 change what new documents contain, not how old ones verify).

All changes below tighten the defaults of the SDK's HTTP handling. Code that already passes its own `http_client`, or that only talks to public HTTPS hosts and signs with the default lifetime, needs no change.

## 1. Default HTTP client: redirects, DNS and target addresses

The default `httpx` client of the HTTP document sources (`HttpDIDDocumentSource`, `BearerTokenHttpDIDDocumentSource`, `JsonRpcDIDDocumentSource`, `WebvhDIDDocumentSource`, `AwsSigV4S3DIDDocumentSource`) now:

- **Does not follow redirects.** A `3xx` response is reported as a non-OK status. If your resolver endpoint redirects (for example `http://` to `https://`, or a moved path), point the source at the final URL.
- **Resolves the host name once and connects to the validated address.** The request is refused when the name does not resolve, or when any resolved address is not globally routable. The connection uses the address that was checked, and TLS still verifies the original host name (`sni_hostname`).
- **Rejects every non-globally-routable range.** This covers private, shared (`100.64.0.0/10`), loopback, link-local, documentation, benchmarking, multicast and reserved IPv4, and IPv6 outside global unicast space (`2000::/3`). IPv4-mapped, NAT64 and 6to4 addresses are judged by the IPv4 address they embed. The ranges are listed explicitly, so the result no longer depends on the Python version.
- **Gives each request one deadline** (`timeout_ms`, default 10 s, `DEFAULT_HTTP_TIMEOUT_MS`) that covers the lookup, the connection and the whole body. rc4 used httpx's per-operation 5 s timeouts, which a server sending the body slowly could extend indefinitely.
- **Caps the response body** (`max_response_bytes`, default 1 MiB, `DEFAULT_MAX_RESPONSE_BYTES`), whether or not the server declares a `Content-Length`. A did:webvh log grows with every entry; raise the limit if yours is larger.
- **Asks for an unencoded body** (`Accept-Encoding: identity`) and rejects a response with any other `Content-Encoding`, so the cap applies to the bytes that are parsed. Servers that compress regardless of `Accept-Encoding` fail; serve those files uncompressed or supply your own `http_client`.

The limits live in `HttpSecurityOptions`, a subclass of `HttpTargetValidationOptions` accepted wherever `http_security` is:

```python
from agent_did_sdk import HttpSecurityOptions, WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig

source = WebvhDIDDocumentSource(
    WebvhDIDDocumentSourceConfig(
        http_security=HttpSecurityOptions(timeout_ms=5_000, max_response_bytes=4 * 1024 * 1024),
    )
)
```

If you must reach an internal endpoint (a resolver inside a private network, a local test server), opt out explicitly:

```python
from agent_did_sdk import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig, HttpTargetValidationOptions

source = HttpDIDDocumentSource(
    HttpDIDDocumentSourceConfig(
        reference_to_url=lambda ref: f"http://did-resolver.internal:8080/{ref}",
        http_security=HttpTargetValidationOptions(allow_private_targets=True),
    )
)
```

An `http_client` you supply owns its own redirect, DNS and limit policy; the SDK does not wrap it.

The `UniversalResolverClient` cache is now bounded: `max_cache_entries` (default 1000, `DEFAULT_RESOLVER_MAX_CACHE_ENTRIES`; also on the `use_production_resolver*` configs). When it is full, expired entries are dropped first and then the least recently used. A process that relies on more than 1000 documents staying in the cache (for example documents registered locally with `register_document`) should raise it.

## 2. Target validation is stricter and the same in both SDKs

`validate_http_target` (Python) and `validateHttpTarget` (TypeScript) now give the same answer for the same input, verified by `fixtures/http-target-vectors.json`.

- Hosts such as `0.0.0.0`, `192.0.0.0/24` (including `192.0.0.9`, which was allowed before) and any IPv6 address outside `2000::/3`, `2001::/23`, `2001:db8::/32` and `3fff::/20` are rejected.
- `validate_http_target` now also rejects an empty host, forbidden host characters and malformed numeric hosts such as `1.2.3.4.5`. These were accepted before and failed later, at request time.

## 3. `BearerTokenHttpDIDDocumentSourceConfig.http_security` is a real field

`http_security` was an unannotated class attribute, so passing it to the constructor was silently ignored. It is now a dataclass field and takes effect:

```python
BearerTokenHttpDIDDocumentSourceConfig(
    allowed_origins=["https://storage.example.com"],  # required since rc.5, see section 19
    token="...",
    http_security=HttpTargetValidationOptions(allow_private_targets=True),
)
```

If you passed `http_security` before and relied on it being ignored, the default policy applied to you; review that value.

## 4. HTTP signature verification bounds the signature lifetime

`verify_http_request_signature` rejects a signature whose `expires - created` is greater than `max_signature_lifetime_seconds`, **300 seconds by default**.

- Signatures from the SDK's own signer use a 30 second lifetime by default, so they are unaffected.
- If another signer issues longer-lived signatures that you trust, raise the limit on the verifying side:

```python
await client.verify_http_request_signature(
    VerifyHttpRequestSignatureParams(
        method=method, url=url, headers=headers, body=body,
        max_signature_lifetime_seconds=900,
    )
)
```

## 5. HTTP signature verification enforces the component order and never raises for an unbound key

- `verify_http_request_signature` now requires the signature to cover `"@method" "@authority" "@path" "@query" "content-digest" "date" "signature-agent"` **in this order**, as RFC-001 §6.5 item 2 states; additional components may only follow. Before, any order (and any position of extra components) was accepted. Signatures from the SDK's own signer already use this order, so they are unaffected. A third-party signer that lists the components in another order must change its `Signature-Input`.
- A signed request whose `keyid` is not an `assertionMethod` key of the `Signature-Agent` DID (a fragment the document does not have, or a key listed only under `keyAgreement`) is now rejected: `verify_http_request_signature` returns `False`. In rc.4 it raised `IdentityCompositionError`. Remove any `except` clause that only handled that case; keep the check on the returned value.
- `Content-Digest` must be exactly `sha-256=:<base64>:`. A dictionary with further algorithms is rejected, as before; RFC-001 §6.5 item 1 now says so.

## 6. New: the reason of a rejected HTTP signature (optional)

`await client.verify_http_request_signature_detailed(params)` returns a `VerifyHttpRequestSignatureResult` with `ok` and, for a rejection, `reason` (`HttpSignatureRejection`). `verify_http_request_signature` is unchanged and still returns a `bool`; nothing needs to change. If you adopt the detailed method, test `result.ok`: the result object is truthy for a rejection too. See [docs/Anti-Replay-HTTP-Signatures.md](../docs/Anti-Replay-HTTP-Signatures.md) for the reasons.

## 7. New: did:webvh pre-rotation (optional)

Nothing changes for DIDs that do not use it. To be able to recover a DID after a compromise of its controller key, commit at creation to keys that will sign the next log entry, and keep their private keys offline:

```python
created = await identity.create(CreateAgentParams(
    ...,
    did_method="webvh",
    webvh=CreateDidWebvhOptions(
        domain=domain, controller_did=controller_did, controller_signer=controller_signer,
        next_update_keys=[encode_public_key_multibase(await recovery_signer.get_public_key())],
    ),
))

# After a compromise: the committed key takes the DID back and commits to the following key.
await client.rotate_controller_key(created.document.id, recovery_signer, next_update_keys=[next_recovery_key])
```

While commitments are in force the key in `controller_signer` can no longer sign log entries, so operations on such a DID (`update_did_document`, `rotate_verification_method`, `revoke_did`) need the committed key as `controller_signer`. It protects only if committed before the compromise. `DidWebvhMetadata` gains `next_key_hashes`; `client.get_did_webvh_controller_keys(did)` returns the active keys and the commitments.

## 8. New: required verification relationship per artifact kind (optional)

Nothing changes for code that verifies payloads or HTTP requests: the defaults are still `assertionMethod`, now read from `REQUIRED_RELATIONSHIP_BY_ARTIFACT`. If you verify other signed artifacts, pass the relationship RFC-001 §6.2.1.3 requires for them instead of the default:

```python
from agent_did_sdk import AgentIdentity, required_relationship_for

await AgentIdentity.verify_signature(issuer_did, payload, signature, key_id, required_relationship_for("delegation"))
```

A key listed only under `assertionMethod` is rejected for a delegation with `key_purpose_violation`. Documents created by the SDK list the agent key under `authentication` and `assertionMethod`. An agent that issues delegations (or invokes delegated capabilities) opts in at creation; the key is then also listed under those relationships, and key rotation carries them over to the new key:

```python
await identity.create(CreateAgentParams(**params, additional_verification_relationships=["capabilityDelegation"]))
```

Without the option the document is the same as before.

## 9. Breaking: `verify_historical_signature` is removed; use `verify_signature_at_time`

`verify_historical_signature` (on `AgentDidClient` and the `AgentIdentity` facade) is removed. It accepted any retired key still in the document, with no time check, so it also accepted signatures forged with a key after it was retired. Replace it with `verify_signature_at_time`, which checks the key against the DID's did:webvh log at the time the artifact states (RFC-001 §6.2.2):

```python
await client.import_did_webvh_history(did_log)  # for DIDs not created by this client
result = await client.verify_signature_at_time(did, payload, signature, key_id, stated_time=stated_time)
# result.status: "valid" | "invalid" | "indeterminate"
```

A key retired after `stated_time` gives `indeterminate`, not `valid`: the stated time is the signer's claim. Pass `trusted_time_not_after` only from evidence you trust (for example a verified RFC 3161 timestamp). Code that accepted rotated-key signatures through `verify_historical_signature` must now decide what to do with `indeterminate`; accepting it reopens the gap the new API closes.

The Microsoft Agent Framework integration made that choice: inside the TTL, `add_verified_handoff` now blocks a handoff signed with a key retired after `signed_at` (`failing_gates=["key_lifecycle"]`), where it used to accept it. After rotating its key, an upstream agent must re-sign pending handoffs with the new key.

## 10. Breaking: the EVM adapter is a separate package (`agent-did-evm`)

`agent_did_sdk.evm` and the `[evm]` extra are gone. The adapter moved, with the `AgentRegistry` contract, to [edisonduran/agent-did-evm](https://github.com/edisonduran/agent-did-evm) ([ADR-004](../docs/ADR-004-EVM-Profile-Satellite.md)) and is published as `agent-did-evm`. The classes and functions are the same:

```diff
- pip install "agent-did-sdk[evm]"
+ pip install --pre agent-did-evm
- from agent_did_sdk.evm import EvmAgentRegistry, EvmAgentRegistryAdapterConfig, Web3AgentRegistryContractClient
+ from agent_did_evm import EvmAgentRegistry, EvmAgentRegistryAdapterConfig, Web3AgentRegistryContractClient
```

`agent-did-sdk` no longer pulls `web3`, not even in `[dev]`.

`AgentRegistry` registration now requires an EIP-712 attestation from a registrar, so an unrelated account can no longer register someone else's DID; see the `agent-did-evm` README for the registrar flow. `revokeAgent` also works while the registry is paused.

## 11. did:webvh adapter: `version_number` moved out of the metadata

If you import `agent_did_sdk.webvh.adapter` directly (`resolve_did_webvh_log` and the log helpers; they are not exported from the package root), read the version number from the result instead of its metadata. `DidWebvhMetadata` now holds only values that DID Core section 7.3 allows in DID document metadata (strings, lists, booleans).

```diff
  result = await resolve_did_webvh_log(log)
- result.metadata.version_number
+ result.version_number
```

## 12. did:webvh revocation empties `updateKeys`

`revoke_did` now writes the deactivation entry with `updateKeys: []`, as did:webvh v1.0 recommends: a revoked DID lists no key that could authorize a later entry. It kept the active keys before. Verification does not change, and logs revoked by an earlier release still verify.

- `get_did_webvh_controller_keys` (and `metadata.update_keys` from the adapter module) return an empty list for a revoked DID. The key that signed the revocation is in the proof of the last log entry.
- A DID with pre-rotation in force (section 7) is revoked in two log entries, both signed by the committed key: the first ends pre-rotation, the second deactivates. The call is the same.

## 13. `FilesystemDIDDocumentSource` needs a root directory or a mapping; IPFS gateway; binary bodies

- `FilesystemDIDDocumentSource()` raises `TypeError`. Pass `FilesystemDIDDocumentSourceConfig(root_directory=...)` (a reference is stored as `<root>/<safe name>.json`) or `reference_to_path` / `reference_to_paths`, as before. Files written by the old default under a raw reference path are not found under the new names.
- The default IPFS gateway is `https://ipfs.io/ipfs/` only (`cloudflare-ipfs.com` is retired). Set `ipfs_gateways` for others.
- `body` of `SignHttpRequestParams` and `VerifyHttpRequestSignatureParams` is `str | bytes`. Strings behave as before.

## 14. Breaking: the `did:agent` profile is removed

- Remove `did_method="agent"` and `did_method="webvh"` from `CreateAgentParams`: there is one profile, `did:webvh`.
- Remove `network` from `AgentIdentityConfig`, and the `network` argument of `AgentDidClient.create_agent(controller_signer, params)`.
- Existing `did:agent` documents registered in a registry still resolve and verify through the registry and `documentRef` path; new ones cannot be created. Create `did:webvh` agents and re-register.
- Fixtures: if you pinned `fixtures/canonical-document-reference.json`, `expectedDocumentRef` is now `hash://sha256/8671ddc531a02613d99c027cb1328f4ffcaedcf2e7e3a6dc93df13e66fe4ac65`; `fixtures/interop-vectors.json` no longer has a `legacy` vector.

## 15. Controller binding: an agent verifies only if its controller endorsed its last log entry

A did:webvh agent whose document names a `controller` other than itself verifies only if the proof of the last entry of its log was made by a key that is active under `capabilityInvocation` of the controller's document (RFC-001 §6.6 item 7). Verification fails with `controller_not_bound` otherwise, and when the controller does not resolve or the verifier does not have the agent's log (a resolver that returns only documents cannot prove the binding).

- Agents created under the SDK's local bootstrap controller are bound out of the box. A bootstrap controller created in rc.4 does not list its key under `capabilityInvocation`: add it with `add_verification_method(did, signer=...)` (the same key can be added under a new id), then give each agent one new entry signed by that key (any `update_did_document`).
- Agents with an explicit controller (`webvh.controller_did` / `controller_signer`): the controller's published DID document must list the signing key under `capabilityInvocation`.
- Verifiers must hold the agent's log: fetched by the production resolver, or loaded with `import_did_webvh_history`.
- Rotating the controller's key without unbinding its agents: (1) `add_verification_method(controller_did, signer=new_key)`; (2) for each agent `rotate_controller_key(agent_did, new_controller_signer=...)` and then `update_did_document(agent_did, patch, controller_signer=new_key)`; (3) `rotate_verification_method(controller_did, signer=new_key)`. Retiring the old key before step 2 unbinds the agents. With pre-rotation, the committed key that signs the agent's next entry must already be listed under the controller's `capabilityInvocation`.
- `AgentDidClient` gains `resolveDidWebvhState` (the verified log, `updateKeys`, the keys that signed the last entry and the provenance) and `addVerificationMethod`.

## 16. Resolution and import of did:webvh logs

- `import_did_webvh_history` rejects a log that does not extend the one stored in the client (an older prefix or a different history); the same log is a no-op. Import the newer log, or use a fresh client.
- did:webvh resolution through `UniversalResolverClient` has no fallback: a DID whose log cannot be fetched (or is not found) fails closed. DIDs that relied on the fallback to the pre-production in-memory resolver now need a reachable log host, or a fresh import within the cache TTL.
- A DID created or changed in the client is resolved from its local log. A test that replaced the document of such a DID through a custom resolver must use a separate verifier client holding the documents and logs it wants resolved.
- A target blocked by the SSRF policy now fails with `blocked by SSRF policy` instead of returning "not found".

## 17. Rotation, key ids and public key encodings

- `rotate_verification_method` removes the retired keys from every verification relationship. Documents of DIDs rotated in rc.4 still list them; run any `update_did_document` to republish the document without them.
- `sign_http_request` requires `verification_method_id`: pass `document.authentication[0]` or the id the rotation returned (the `#key-1` default named the wrong key after a rotation).
- The new key of a rotation can live in a KMS/HSM: `rotate_verification_method(did, signer=...)`; the result's private key is then empty.
- `publicKeyMultibase` is decoded only as `z` + Base58btc(`0xed01` + key): the SDK 0.x `z`+hex form and raw keys without the multicodec prefix are rejected. Re-encode such documents.
- Ed25519 signatures with non-canonical or torsion-carrying points are rejected in both SDKs (RFC-001 §7, `fixtures/ed25519-verification-vectors.json`). A signature that is not valid hex, or an empty key id, fails verification instead of throwing or being ignored.

## 18. Breaking: payload signatures carry a domain prefix; verified handoffs sign an envelope

- `sign_message` signs `agent-did/v1/message` + a line feed + the payload, and `verify_signature` / `verifySignatureAtTime` apply the same prefix. **Payload signatures made by rc.4 do not verify in rc.5 (and rc.5 signatures do not verify in rc.4); there is no compatibility mode.** Re-sign stored payload signatures. A third-party verifier prepends the UTF-8 prefix before the Ed25519 check. HTTP request signatures do not take the prefix; they change for another reason (section 36).
- Microsoft Agent Framework (`agent-did-microsoft-agent-framework`): sign handoffs with `sign_handoff(...)` instead of building `SignedHandoffMessage` by hand, passing the downstream executor id as `destination`; payloads must be JSON-serializable; add `allowed_dids` to `irreversible` edges; pass a shared `nonce_store` when several workflow instances verify the same edge. New block reasons: `destination`, `nonce`, `signed_at`, `payload`, `replay`.

## 19. Breaking: `BearerTokenHttpDIDDocumentSource` needs `allowed_origins`; JSON-RPC

- `BearerTokenHttpDIDDocumentSourceConfig` requires `allowed_origins`, the origins its credential may be sent to (`https://host`, with the port when it is not the default). A request to any other origin is refused before the token is resolved, so the source can serve as `wba_document_source` or `webvh_document_source` (whose URLs come from the DID) without handing the token to the DID's host. Constructing the source without it raises `TypeError`:

  ```python
  BearerTokenHttpDIDDocumentSource(BearerTokenHttpDIDDocumentSourceConfig(
      token=token, allowed_origins=["https://storage.example.com"],
  ))
  ```

- `JsonRpcDIDDocumentSource.get_by_reference` raises when every endpoint is blocked by the target policy, as `HttpDIDDocumentSource` does. It returned `None` ("not found") before. It returns `None` only when every endpoint answers "not found".

## 20. Breaking: HTTP signatures need a request URL in normalized form; payload signature hex is strict

- `sign_http_request` refuses, with `HttpSignatureError`, a URL that is not already percent-encoded and normalized: spaces or non-ASCII characters (send `%20`, `%C3%A9`), an internationalized host that is not in punycode, an uppercase scheme or host, user information, a fragment, `.` or `..` path segments, an empty `?`, a `'` in the query (`%27`), or an IP host that is not in canonical form. Verification rejects such a request with the reason `url_not_normalized`. `request_url_form_problem(url)` returns why a URL is refused (or nothing). Build the URL from encoded parts before signing and send exactly that URL.
- A payload signature passed to `verify_signature` must be exactly 128 hex digits, without spaces or a `0x` prefix.

## 21. New: who signed an HTTP request, and allow-lists (optional)

- An accepted `verify_http_request_signature_detailed` result carries `did`, `key_id` and `controllers` (the controller chain, nearest first). `HttpSignatureRejection` gains `did_not_allowed` and `controller_not_allowed`.
- A valid signature proves which DID signed, not that you should accept it. Pass `allowed_dids` (the `Signature-Agent` DIDs you accept; checked before any resolution) and/or `allowed_controllers` (accept agents operated by these controllers), or read `result.did` and decide yourself. A2A: `verify_a2a_request(..., allowed_controllers=[...])`, or `verify_a2a_request_detailed`.

```python
result = await client.verify_http_request_signature_detailed(
    VerifyHttpRequestSignatureParams(**request, allowed_controllers=[partner_org_did])
)
```

## 22. Resolution limits; integration tools that resolve DIDs are opt-in

- The universal resolver remembers a failed did:webvh / did:wba resolution for 5 s (`ResolutionLimits.negative_cache_ttl_ms`, 0 turns it off), shares one fetch between concurrent resolutions of the same DID and runs at most 16 fetches at once (`max_concurrent_fetches`). Code that retries a failing DID within 5 s gets the same error without a new request.
- New optional `ResolutionLimits.allowed_hosts` (`UniversalResolverConfig.resolution_limits` and the `use_production_resolver*` profiles): only DIDs on these hosts are fetched. Set it on verifiers that know their peers.
- LangChain Python, CrewAI, Semantic Kernel and Microsoft Agent Framework: `expose["resolve_did"]` and `expose["verify_signatures"]` default to `False`. Set them to `True` where the agent needs them, together with `allowed_hosts`.

```python
client.use_production_resolver_from_http(ProductionHttpResolverProfileConfig(
    registry=registry, resolution_limits=ResolutionLimits(allowed_hosts=["*.partner.example"]),
))
```

## 23. Integrations sign with the agent's external signer

- `create`, `rotate_verification_method` and `add_verification_method` return the `signer` you passed for the agent key as `result.signer` (excluded from `model_dump` / `model_dump_json`). The A2A, LangChain, CrewAI, Semantic Kernel and Microsoft Agent Framework integrations sign payloads, HTTP requests and handoffs with it when present; before, an agent created with a KMS or HSM signer failed with `The seed must be exactly 32 bytes long`.
- The `rotate_key` tools refuse an agent whose key lives in an external signer: rotate it with `client.rotate_verification_method(did, signer=new_signer)` and pass the result to the integration.

## 24. Smaller changes from the review

- Lifecycle operations of one DID run one at a time in a client; nothing to change unless you relied on parallel updates overwriting each other.
- did:wba: a host that cannot be reached or has no document fails, without the fallback resolver; a document for another DID is a `DocumentIntegrityError`.
- `InMemoryNonceStore` takes `max_entries_per_scope` (default 10 000 per `keyid`); a client's default store follows `clock`.
- `evict_cached_resolution(did)` drops a cached resolution. Integrations sign with the first active `assertionMethod` key.
- Microsoft Agent Framework: an irreversible handoff older than 60 s is refused (`HANDOFF_MAX_AGE_DEFAULTS`; `max_age_seconds` lowers it, or raises it for the other classes), and handoffs signed by rc.5 pre-releases without `trust_domain` in the envelope do not verify: re-sign them with `sign_handoff`.

## 25. Packaging

- `agent-did-sdk` requires `did-webvh==1.0.1` exactly. An environment that installed another 1.0.x release of `did-webvh` gets 1.0.1.
- Python 3.13 and 3.14 are tested and listed in the classifiers.

## 26. did:wba host grammar

- The domain segment of a did:wba DID must decode to a DNS name with an optional port (`did:wba:agents.example%3A8443`). IP literals (`did:wba:127.0.0.1`), a numeric last label, and any character other than ASCII letters, digits, hyphens and dots are rejected before any request. Use a host name; for local tests, `localhost%3A<port>` still works.
- Path segments equal to `.` or `..` after decoding are rejected. Other path segments are re-encoded keeping only `A-Z a-z 0-9 - . _ ~`. The host is lowercased and port 443 is dropped from the URL.


## 27. HTTP signature nonces follow a token grammar

- A `nonce` must be 1 to 256 characters of `A-Z a-z 0-9 . _ ~ + / = -` (RFC-001 §6.5 item 3). Verification rejects any other value with `params_missing`. The SDK signers send 32 hex digits, so only third-party signers that put spaces or other characters in the nonce must change.
- A custom `NonceStore` receives `<keyid> <nonce>` as before; the text before the last space is now always the `keyid`, so a store can scope per-signer quotas by it (as `InMemoryNonceStore` does with `max_entries_per_scope`).
- Microsoft Agent Framework: `sign_handoff(nonce=...)` raises `ValueError` for a nonce outside the grammar, the verifier blocks such a message with `failing_gates=["nonce"]`, and the replay key is `<did> <nonce>` (was `<did>|<nonce>`). A shared store does not match keys written before the upgrade, so a handoff accepted just before it can be accepted once more until its maximum age passes, as after a restart with the default in-memory store; upgrade verifiers while no handoff is in flight if that matters.


## 28. Bounded fetch queue in the universal resolver

- At most 64 did:webvh / did:wba fetches wait for a slot (`max_queued_fetches`); a resolution that would wait beyond that fails at once with "too many DID fetches are waiting". Such a refusal is not remembered, so a retry fetches.
- At most 4 fetches run at once for one host name (`max_concurrent_fetches_per_host`). A service that resolves many uncached DIDs on one host at the same time (a burst of new agents of one provider) sees the others wait; raise the limit for hosts you trust.
- The wait and the fetch together must finish within 15 s (`fetch_deadline_ms`). Keep it above the document source timeout (`HttpSecurityOptions.timeout_ms`, default 10 s), or a slow but healthy host fails at the deadline.

```python
ResolutionLimits(max_concurrent_fetches_per_host=16, max_queued_fetches=256, fetch_deadline_ms=30_000)
```


## 29. An imported did:webvh log is not a fresh resolver entry

- With a resolver that fetches did:webvh logs (the production resolver), `import_did_webvh_history` of a DID whose controller signer the client does not hold no longer caches the imported document. The next resolution fetches the host's log, and the longer of the fetched and the imported log wins.
- A verifier that imported a log and then resolved it while the log host was unreachable got the imported document for up to `cache_ttl_ms`; it now gets a resolution error. Make the log host reachable, or use a resolver that does not fetch logs if the imported log is meant to be the only source.


## 30. Integrations share the SDK's sanitizer and target policy

- Integration events are sanitized by the SDK's `sanitize_observability_attributes`. A redacted value is always `{"redacted": true, "length": n}`, also for sensitive headers (they were the string `"<redacted>"` in some integrations). Log parsers or alerts that matched `"<redacted>"` must match the marker.
- CrewAI, LangChain, A2A: a sensitive field that is not a string (a dict, a list, a number) is now redacted too.
- The signing tools of the integrations validate the target URL with the SDK policy: the error messages are now `Unsupported protocol: …` and `Blocked request to private/reserved address: …`, and every non-global address range is refused, not only loopback and private ones.

## 31. CrewAI guardrail and callbacks

- `create_identity_output_guardrail` returns `(True, output)` on success (it returned `(True, None)`, which CrewAI rejects). Code that called the guardrail directly and checked `message is None` must check the first element only.
- The guardrail checks the agent's output (`TaskOutput.pydantic`, `json_dict`, or `raw` parsed as a JSON object). An agent whose final answer is not a JSON object now fails the guardrail; set `output_pydantic` (as `create_task_kwargs` does) or ask for JSON in the task.

## 32. Integration options that now take effect

- CrewAI, Semantic Kernel, Microsoft Agent Framework: with `allow_private_network_targets=True` the signing tool now signs for loopback and private targets (it returned an error from the SDK before).
- Semantic Kernel: `tool.invoke` / `tool.ainvoke` and kernel plugin calls raise `pydantic.ValidationError` for unknown arguments or oversized values.
- A2A: remove `resolve_remote_did`, `document_history` and `rotate_keys` from `expose`, and `default_request_timeout_seconds` from `AgentDidA2AConfig` (they had no effect and are now rejected). `expose.sign_requests=False`, `verify_requests=False` and `enrich_agent_card=False` now make the matching methods raise `PermissionError`. Set `AgentDidA2AConfig(allow_private_network_targets=True)` to sign for private targets, or pass `http_security` to `sign_a2a_request`.


## 33. Model and prompt commitments are optional

RFC-001 §4.3 now makes `coreModelHash` and `systemPromptHash` optional assertions by the controller.

- `CreateAgentParams.core_model` and `system_prompt` are optional. Omitted, the document has no `coreModelHash` / `systemPromptHash` and the matching field of `metadata_commitment_salts` is `None`. Existing calls that pass both produce the same documents as before.
- A `core_model_salt` / `system_prompt_salt` without its value now raises `ValueError`.
- Type changes: `AgentMetadata.core_model_hash` / `system_prompt_hash` and both fields of `MetadataCommitmentSalts` are `str | None`. `verify_metadata_commitment` accepts `None` and returns `False`.
- The local bootstrap controller document no longer carries placeholder commitments.
- Verifiers: do not reject a document without commitments, and do not read a matching commitment as proof of what the agent runs.


## 34. `Multikey` verification methods

RFC-001 §4.2 now requires `Multikey` for Ed25519 keys ([ADR-006](../docs/ADR-006-Wire-Alignment-rc5.md) D-8b).

- Documents created, updated or rotated by the SDK now write `"type": "Multikey"` for every key, with the same `publicKeyMultibase` value as before. Code or tests that compare the type with `Ed25519VerificationKey2020` must accept `Multikey`.
- rc.4 documents and did:webvh logs keep resolving and verifying: `Ed25519VerificationKey2020` is still read, and their signed entries are not rewritten.
- A document in which a method that carries `publicKeyMultibase` has any other type (`Ed25519VerificationKey2018`, `JsonWebKey2020`, a misspelt `multikey`, ...) is now rejected by every resolver source and by `AgentDIDDocument.model_validate` (`ValidationError`). Signature checks and the controller binding never take a key from such a method, and `check_did_webvh_key_at_time` reports `key_not_found` for it.
- Fixtures: if you pinned `fixtures/canonical-document-reference.json`, `expectedDocumentRef` is `hash://sha256/8671ddc531a02613d99c027cb1328f4ffcaedcf2e7e3a6dc93df13e66fe4ac65` (the value given in the `did:agent` section already includes this change); `fixtures/verification-relationship-vectors.json` gains `methodTypeVectors`.

## 35. Agent metadata credential (new, optional)

RFC-001 §4.4 adds the `AgentMetadataCredential` ([ADR-006](../docs/ADR-006-Wire-Alignment-rc5.md) D-8d). Nothing changes for existing code: documents, `agent_metadata` and signatures are as before.

- The controller issues it with `await client.issue_agent_metadata_credential(IssueAgentMetadataCredentialParams(agent_did=..., signer=..., verification_method_id=...))`, where `verification_method_id` is an `assertionMethod` key of the controller (for the implicit bootstrap controller, `controller_document.assertion_method[0]` with `LocalKeySigner(created.controller_private_key)`). Pass `agent_metadata` (JSON member names, e.g. `{"name": ..., "capabilities": [...]}`) to share only some members, and `valid_until` to bound it. The credential is a `dict`.
- A relying party verifies it with `await client.verify_agent_metadata_credential(credential, expected_agent_did=...)` and reads `result.ok`, `result.reason`, `result.agent_metadata` and `result.controllers`. The metadata is the controller's assertion, not evidence of what the agent runs.

## 36. Breaking: the agent DID moves to the `Agent-DID` header

RFC-001 §6.5 ([ADR-006](../docs/ADR-006-Wire-Alignment-rc5.md) D-8a). `Signature-Agent` is a header of the IETF Web Bot Auth draft with another meaning (a key-directory URI), so Agent-DID no longer uses it.

- `sign_http_request` returns `Agent-DID: sig1="<did>"`, a Structured Field Dictionary keyed by the signature label, instead of `Signature-Agent: <did>`, and the signature covers `"agent-did";key="sig1"` instead of `"signature-agent"`. Proxies, gateways and logging that pass or read `Signature-Agent` must pass or read `Agent-DID`.
- `verify_http_request_signature` takes the DID from the `Agent-DID` member of each signature's label and never reads `Signature-Agent`. **HTTP signatures made by rc.4 do not verify in rc.5, and rc.5 signatures do not verify in rc.4; there is no compatibility mode.** Upgrade signers and verifiers together.
- New rejections: no `Agent-DID` header (`missing_headers`); a field that is not a Dictionary, or a member that is not a String or has parameters (`malformed_headers`); no member for the signature's label (`signed_component_missing`). `allowed_dids` is now checked per signature, after the profile checks and still before any resolution, so a request with a wrong `Content-Digest` reports `digest_mismatch` before `did_not_allowed`.
- API: `AGENT_DID_HTTP_SIGNATURE_COMPONENTS` is removed; `agent_did_http_signature_components(label)` returns the seven components, the last one `KeyedComponent(name="agent-did", key=label)`. New `AGENT_DID_HTTP_HEADER` (`"Agent-DID"`). `SignatureInput.components` is `list[ComponentIdentifier]` (`str | KeyedComponent`): `parse_signature_input_header` returns a `KeyedComponent` for a component with a `key` parameter (the only component parameter supported; any other still raises `HttpSignatureError`), and `build_signature_base` takes the serialized Dictionary member as its value (RFC 9421 §2.1.2). Code that treats components as plain strings must handle the object form.
- Third-party signers: send `Agent-DID: <label>="<did>"` and cover `"agent-did";key="<label>"` with the signature's own label, last among the seven required components.
- Fixtures: `fixtures/http-verification-vectors.json` (84 vectors, with new `Agent-DID` cases) and `fixtures/interop-vectors.json` are regenerated, and the wire freeze is re-pinned.

## 37. Composition contract: signed Agent Cards, revoked keys, single-key retirement (new)

RFC-001 §4.2, §6.2.2, §6.6 item 3 and the [A2A Identity Composition Contract](../docs/RFC-001-A2A-Identity-Composition-Contract.md) (`[RFC]` #257).

- **Signed Agent Cards.** `sign_agent_card(card, signer, key_id)` adds an A2A 1.0 §8.4 JWS (`alg` `EdDSA`, `kid` = the DID URL of an `assertionMethod` key, `typ` `JOSE`) over the JCS form of the card without `signatures`. Publish the agent DID and its keys in `capabilities.extensions` with `uri` `AGENT_DID_A2A_EXTENSION_URI`. `AgentDidClient.verify_agent_card(card)` checks the format and every signature; `verify_identity_composition(VerifyIdentityCompositionParams(..., agent_card=card))` also checks that the request verifies and that its `keyid` is a key the card publishes. Both return a result with `ok` and `reason` with the contract reasons (`rotation_window_closed`, `emergency_revoked`, `key_purpose_violation`, `tampered`, `card_keyid_mismatch`, `format_drift`, `did_document_unresolvable`, `request_rejected`).
- **Single-key retirement.** `AgentDidClient.retire_verification_method(did, key_id)` retires one key and keeps the others. A planned rotation is now `add_verification_method` (both keys listed: the overlap) then `retire_verification_method` of the old key. It refuses the last `authentication` or `assertionMethod` key.
- **Emergency revocation.** `retire_verification_method(did, key_id, emergency=True)` and `rotate_verification_method(did, emergency=True)` also set `revoked` on the retired keys. A revoked key is `not_authorized` (`key_revoked`) in `verify_signature_at_time` at every stated time, even with `trusted_time_not_after`. Use it when a key may be compromised.
- **Document format.** `VerificationMethod.revoked` is new, and a document with a revoked key ends its `@context` with the inline term `REVOKED_CONTEXT_TERM` (the published `https://agent-did.org/v1` context is immutable). `AgentDIDDocument.context` is now `list[str | dict[str, Any]]` (a string or that term): code that treats every entry as a string must handle the object. The `AgentDIDDocument` model rejects `revoked` without `deactivated`, a revoked key without the term, and the term without a revoked key. Documents without revoked keys are unchanged.
- Fixtures: `fixtures/composition-contract-vectors.json` (new, in `interop:check` and the wire freeze).

## 38. Controllers may be plain DID Core documents (breaking types)

RFC-001 §4.2.1. A did:webvh controller no longer has to be an Agent-DID document: an organization can use any DID Core `did:webvh` document as the `controller` of its agents. The binding rule (§6.6 item 7) does not change.

- **New:** `DidDocument` (a DID Core document, extra members kept), `DidCoreVerificationMethod` and `AnyDidDocument` (`DidDocument | AgentDIDDocument`), exported from `agent_did_sdk`. `AgentDidClient.resolve_document(did)` returns the document of a did:webvh DID: an `AgentDIDDocument` for an agent, a `DidDocument` otherwise. `resolve(did)` still returns only Agent-DID documents and now raises `ValueError` for a plain controller DID (`is not an Agent-DID document`). A resolver may implement `resolve_document`; without it controllers are answered with `resolve`, so they must be Agent-DID documents.
- **Breaking types:** `resolve_controller_chain` returns `list[AnyDidDocument]` (it returned `list[AgentDIDDocument]`), and `DidWebvhResolution.document` / `DidWebvhState.document` are `AnyDidDocument`. The first element of a chain started at an agent is still that agent's `AgentDIDDocument`; check `isinstance` before reading `agent_metadata`.
- **Controller relationships:** the controller's `capabilityInvocation` (binding) and `assertionMethod` (`AgentMetadataCredential` issuer) accept relative references (`#key-1`) and embedded verification methods. Only Ed25519 `publicKeyMultibase` keys count; `publicKeyJwk` methods are ignored.
- **Fails closed:** a controller whose `controller` is a list rejects the chain (`did_resolution_failed` in the detailed results). A fetched did:webvh log whose state is not a DID Core document is a `DocumentIntegrityError` (`is not a DID document`); a state that is a DID Core document but not an Agent-DID document is no longer an integrity failure, `resolve` raises a plain `ValueError`.
- `verify_signature` / `verify_signature_at_time` for a DID whose document is not an Agent-DID document fail (`did_resolution_failed`): signatures are verified for agents only.
- For other DID methods (did:wba, registry sources) controllers must still be Agent-DID documents.

## Checklist

- [ ] Resolver endpoints no longer rely on redirects.
- [ ] Internal endpoints set `http_security=HttpTargetValidationOptions(allow_private_targets=True)`.
- [ ] Any `http_security` passed to the Bearer source is the policy you want, now that it takes effect.
- [ ] Endpoints answer within 10 s with an uncompressed body of at most 1 MiB, or `HttpSecurityOptions(timeout_ms=..., max_response_bytes=...)` raises the limits.
- [ ] Processes that need more than 1000 cached documents set `max_cache_entries`.
- [ ] Third-party signers with a lifetime above 300 s are covered by `max_signature_lifetime_seconds`.
- [ ] Third-party signers list the seven required components in the order of RFC-001 §6.5 item 2, with extra components after them.
- [ ] Code around `verify_http_request_signature` no longer expects an `IdentityCompositionError` for an unbound `keyid`.
- [ ] Decide whether your controller DIDs should commit to recovery keys (`next_update_keys`); it only helps if done before a compromise.
- [ ] Verifiers of delegations, invocations or authentication challenges pass `required_relationship_for(...)` instead of the `assertionMethod` default.
- [ ] Agents that issue delegations or invoke capabilities are created with `additional_verification_relationships`.
- [ ] Code that reads the controller keys of a revoked did:webvh DID expects an empty list.
- [ ] Calls to `verify_historical_signature` are replaced with `verify_signature_at_time`, and `indeterminate` is handled as not accepted.
- [ ] Code that imports `agent_did_sdk.evm` installs `agent-did-evm` and imports `agent_did_evm` instead.
- [ ] Direct users of the did:webvh adapter read `result.version_number` instead of `result.metadata.version_number`.
- [ ] Every `sign_http_request` call passes `verification_method_id`.
- [ ] Code that reads `context` entries as strings handles the inline `revoked` term.
- [ ] A planned key rotation that must not break in-flight requests uses `add_verification_method` then `retire_verification_method`; a suspected compromise uses `emergency=True`.
- [ ] Stored payload signatures are re-signed with rc.5 (the signed bytes carry the `agent-did/v1/message` prefix).
- [ ] Agents with an explicit controller are listed under the controller's `capabilityInvocation`; bootstrap controllers from rc.4 get the key added (`add_verification_method`).
- [ ] Verifiers hold the agent's did:webvh log (production resolver or `import_did_webvh_history`); no code relies on a fallback for did:webvh.
- [ ] DIDs rotated in rc.4 were republished once (`update_did_document`) so retired keys leave the relationships.
- [ ] `FilesystemDIDDocumentSource` has a `root_directory` or a mapping; `create` no longer passes `did_method` or `network`.
- [ ] Microsoft Agent Framework handoffs are signed with `sign_handoff` and edges that move irreversible actions set `allowed_dids`.
- [ ] Every `BearerTokenHttpDIDDocumentSourceConfig` lists its `allowed_origins`.
- [ ] Code that treated a `None` from `JsonRpcDIDDocumentSource` with blocked endpoints as "not found" handles the error.
- [ ] Every URL passed to `sign_http_request` is percent-encoded and normalized (`request_url_form_problem` returns nothing for it).
- [ ] Every HTTP verifier either passes `allowed_dids` / `allowed_controllers` or checks `result.did` before trusting the request.
- [ ] Agents that use the `resolve_did` / `verify_signature` tools enable them in `expose`; verifiers that know their peers set `ResolutionLimits.allowed_hosts`.
- [ ] Code that reads `core_model_hash`, `system_prompt_hash` or `metadata_commitment_salts` handles `None`, and no verifier policy requires the commitments.
- [ ] HTTP signers and verifiers are upgraded together, and proxies or gateways forward `Agent-DID` (rc4 HTTP signatures do not verify in rc5).
- [ ] Code that used `AGENT_DID_HTTP_SIGNATURE_COMPONENTS` calls `agent_did_http_signature_components(label)` and handles `KeyedComponent` entries.
- [ ] Code that reads `resolve_controller_chain` results or `DidWebvhState.document` as `AgentDIDDocument` checks `isinstance` (controllers may be plain DID Core documents).
