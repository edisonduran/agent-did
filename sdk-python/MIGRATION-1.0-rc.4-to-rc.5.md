# agent-did-sdk Migration Guide: 1.0.0rc4 -> 1.0.0rc5

Behavior changes between `1.0.0rc4` and `1.0.0rc5`. There are no wire-format changes and no public API removals: DID documents, DID logs, hash URIs and signature bases are unchanged, and documents or signatures produced by rc4 stay valid.

All changes below tighten the defaults of the SDK's HTTP handling. Code that already passes its own `http_client`, or that only talks to public HTTPS hosts and signs with the default lifetime, needs no change.

## 1. Default HTTP client: redirects, DNS and target addresses

The default `httpx` client of the HTTP document sources (`HttpDIDDocumentSource`, `BearerTokenHttpDIDDocumentSource`, `JsonRpcDIDDocumentSource`, `WebvhDIDDocumentSource`, `AwsSigV4S3DIDDocumentSource`) now:

- **Does not follow redirects.** A `3xx` response is reported as a non-OK status. If your resolver endpoint redirects (for example `http://` to `https://`, or a moved path), point the source at the final URL.
- **Resolves the host name once and connects to the validated address.** The request is refused when the name does not resolve, or when any resolved address is not globally routable. The connection uses the address that was checked, and TLS still verifies the original host name (`sni_hostname`).
- **Rejects every non-globally-routable range.** This covers private, shared (`100.64.0.0/10`), loopback, link-local, documentation, benchmarking, multicast and reserved IPv4, and IPv6 outside global unicast space (`2000::/3`). IPv4-mapped, NAT64 and 6to4 addresses are judged by the IPv4 address they embed. The ranges are listed explicitly, so the result no longer depends on the Python version.

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

An `http_client` you supply owns its own redirect and DNS policy; the SDK does not wrap it.

## 2. Target validation is stricter and the same in both SDKs

`validate_http_target` (Python) and `validateHttpTarget` (TypeScript) now give the same answer for the same input, verified by `fixtures/http-target-vectors.json`.

- Hosts such as `0.0.0.0`, `192.0.0.0/24` (including `192.0.0.9`, which was allowed before) and any IPv6 address outside `2000::/3`, `2001::/23`, `2001:db8::/32` and `3fff::/20` are rejected.
- `validate_http_target` now also rejects an empty host, forbidden host characters and malformed numeric hosts such as `1.2.3.4.5`. These were accepted before and failed later, at request time.

## 3. `BearerTokenHttpDIDDocumentSourceConfig.http_security` is a real field

`http_security` was an unannotated class attribute, so passing it to the constructor was silently ignored. It is now a dataclass field and takes effect:

```python
BearerTokenHttpDIDDocumentSourceConfig(
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

## 9. EVM profile (`agent_did_sdk.evm`)

`AgentRegistry` registration now requires an EIP-712 attestation from a registrar, so an unrelated account can no longer register someone else's DID. The EVM profile is deferred outside core 1.0; see the `@agentdid/evm` README for the registrar flow. `revokeAgent` also works while the registry is paused.

## Checklist

- [ ] Resolver endpoints no longer rely on redirects.
- [ ] Internal endpoints set `http_security=HttpTargetValidationOptions(allow_private_targets=True)`.
- [ ] Any `http_security` passed to the Bearer source is the policy you want, now that it takes effect.
- [ ] Third-party signers with a lifetime above 300 s are covered by `max_signature_lifetime_seconds`.
- [ ] Third-party signers list the seven required components in the order of RFC-001 §6.5 item 2, with extra components after them.
- [ ] Code around `verify_http_request_signature` no longer expects an `IdentityCompositionError` for an unbound `keyid`.
- [ ] Decide whether your controller DIDs should commit to recovery keys (`next_update_keys`); it only helps if done before a compromise.
- [ ] Verifiers of delegations, invocations or authentication challenges pass `required_relationship_for(...)` instead of the `assertionMethod` default.
- [ ] Agents that issue delegations or invoke capabilities are created with `additional_verification_relationships`.
