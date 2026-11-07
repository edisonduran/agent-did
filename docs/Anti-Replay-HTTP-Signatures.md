# HTTP Message Signatures and Anti-Replay

Agent-DID signs HTTP requests with [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures. This page describes the Agent-DID profile and how verifiers prevent replay. The normative text is RFC-001 §6.5.

> Applies to `1.0.0-rc.3` and later (unchanged in `1.0.0-rc.4`). The `1.0.0-rc.2` and earlier releases used an `X-Request-Nonce` header and a different signature base; see the rc.2 → rc.3 migration guides.

## The Agent-DID profile

| | Value |
|---|---|
| Covered components | `"@method" "@authority" "@path" "@query" "content-digest" "date" "signature-agent"`, in this order |
| Signature parameters | `created`, `expires`, `nonce`, `keyid`, `alg="ed25519"`, `tag="agent-did"` |
| `keyid` | A verification method of the `Signature-Agent` DID, for example `did:webvh:…#key-1`; it must be listed under `assertionMethod` |
| `Content-Digest` | RFC 9530, `sha-256` |
| Label | `sig1` when signing; verifiers accept any label |

Example (line breaks added):

```http
Signature-Agent: did:webvh:QmScid…:agents.example.com:support-bot
Date: Tue, 03 Nov 2026 10:00:00 GMT
Content-Digest: sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:
Signature-Input: sig1=("@method" "@authority" "@path" "@query" "content-digest" "date" "signature-agent")
  ;created=1793872800;expires=1793872830;nonce="5b0f…";keyid="did:webvh:QmScid…#key-1"
  ;alg="ed25519";tag="agent-did"
Signature: sig1=:…:
```

The signature base follows RFC 9421 §2.5 exactly. The SDKs reproduce the RFC's Appendix B.2.6 (Ed25519) signature byte for byte, and CI cross-checks the profile in both directions against an independent implementation (`http-message-signatures` on npm and on PyPI).

## Signing

```typescript
const headers = await agentIdentity.signHttpRequest({
  method: 'POST',
  url: 'https://api.example.com/v1/action',
  body: '{"action":"approve"}',
  agentPrivateKey: myKey, // or signer: an AgentSigner (KMS/HSM)
  agentDid: myDid,
  expiresInSeconds: 60 // optional, default: 30
});
// Signature-Agent, Date, Content-Digest, Signature-Input, Signature
```

```python
headers = await identity.sign_http_request(SignHttpRequestParams(
    method="POST",
    url="https://api.example.com/v1/action",
    body='{"action":"approve"}',
    agent_private_key=my_key,
    agent_did=my_did,
    expires_in_seconds=60,
))
```

## Verifying

`verifyHttpRequestSignature` / `verify_http_request_signature` returns `true` only when all of the following hold:

1. `Signature-Input` and `Signature` parse as RFC 8941 dictionaries, and some label carries the full profile: every covered component above, `tag="agent-did"`, `alg="ed25519"`, `created`, `expires`, `nonce`, and a `keyid` under the `Signature-Agent` DID.
2. `created` is within `maxCreatedSkewSeconds` of now (default 300 s), `expires >= created`, `expires - created` is at most `maxSignatureLifetimeSeconds` (default 300 s), and `now <= expires`.
3. `Content-Digest` matches the body.
4. The signature verifies over the base rebuilt from the received request, with `@signature-params` re-serialized from the parsed `Signature-Input`, using an active `assertionMethod` key of a DID whose controller chain is active.
5. The `(keyid, nonce)` pair has not been seen before. It is then recorded until `expires`.

The nonce is recorded only after the signature verifies, so forged requests cannot consume other clients' nonces.

## Why a request was rejected

`verifyHttpRequestSignature` / `verify_http_request_signature` return a boolean. To log or answer with the reason, call `verifyHttpRequestSignatureDetailed` / `verify_http_request_signature_detailed` on an `AgentDidClient`; it returns `{ ok: true }` or `{ ok: false, reason }` (Python: `result.ok`, `result.reason`). Always test `result.ok`: the result object is truthy for a rejection too.

```typescript
const result = await client.verifyHttpRequestSignatureDetailed({ method, url, body, headers });
if (!result.ok) {
  log.warn({ reason: result.reason }, 'rejected agent request');
  return respond(401);
}
```

| `reason` | Meaning |
|---|---|
| `missing_headers` | `Signature`, `Signature-Input` or `Signature-Agent` is absent |
| `malformed_headers` | the signature headers do not parse, or no signature has a matching label |
| `digest_mismatch` | `Content-Digest` is absent, or is not exactly the SHA-256 of the body |
| `tag_mismatch` | `tag` is not `agent-did` (for example another profile's signature) |
| `alg_unsupported` | `alg` is not `ed25519` |
| `params_missing` | `created`, `expires`, `nonce` or `keyid` is absent or has the wrong type |
| `keyid_not_bound` | `keyid` is not a key of the `Signature-Agent` DID |
| `components_missing` / `components_order` | a required covered component is absent / the required components are not first and in order |
| `created_skew` | `created` is further from now than the allowed skew |
| `expires_before_created` | `expires` is earlier than `created` |
| `lifetime_exceeded` | `expires - created` is above the lifetime cap |
| `expired` | now is after `expires` |
| `signed_component_missing` | a covered component has no value in the request (for example no `Date`) |
| `did_resolution_failed` | the `Signature-Agent` DID has no active verification chain: unknown, revoked, deactivated, inactive controller or a resolver failure. The SDK does not tell an outage from a revocation |
| `keyid_not_authorized` | `keyid` is not an `assertionMethod` key of the DID document |
| `signature_invalid` | the signature does not verify, or the key is no longer active |
| `nonce_replayed` | the `(keyid, nonce)` pair was already seen |

When a request carries several signatures, the reason is the one of the first signature with `tag="agent-did"`. The reasons are part of the shared vectors (`fixtures/http-verification-vectors.json`), so both SDKs report the same reason for the same request. Do not return the reason to the caller of your API: it tells an attacker which rule to work around. Log it.

## Replay protection: `NonceStore`

Step 5 uses a `NonceStore`.

> **WARNING: the default store is per process.** By default it is a process-wide `InMemoryNonceStore`, which is correct only for a single verifier instance (and is lost on restart). With replicas, serverless functions or Kubernetes, a replayed request is accepted by any instance that has not seen its nonce. Pass a shared store, as below, before you run more than one instance.

The in-memory store refuses new nonces when full rather than evicting live ones.

When several instances verify requests for the same agents, pass a shared store. Tested reference implementations for Redis are in [`sdk/examples/redis-nonce-store.js`](../sdk/examples/redis-nonce-store.js) and [`sdk-python/examples/redis_nonce_store.py`](../sdk-python/examples/redis_nonce_store.py). Copy them into your service; they are not part of the SDK packages, so the SDKs have no Redis dependency.

```typescript
const { createClient } = require('redis');
const { createRedisNonceStore } = require('./redis-nonce-store');

const redis = createClient({ url: process.env.REDIS_URL });
await redis.connect();

await client.verifyHttpRequestSignature({ method, url, body, headers, nonceStore: createRedisNonceStore(redis) });
```

```python
import redis.asyncio as redis

nonce_store = RedisNonceStore(redis.from_url(os.environ["REDIS_URL"]))
await client.verify_http_request_signature(VerifyHttpRequestSignatureParams(
    method=method, url=url, body=body, headers=headers, nonce_store=nonce_store,
))
```

Any shared store must meet the `NonceStore` contract. The reference implementations have tests for each point, and you can run the same checks against your own store:

- **Atomic.** `checkAndStore` is one conditional write (`SET key value NX EXAT ...`), never a read followed by a write. Of concurrent submissions of one key exactly one resolves `true`.
- **Keeps the key through the second `expires` inclusive.** The verifier accepts a request while `now <= expires`, and Redis `EXAT t` removes the key at the start of second `t`, so the expiry is `expires + 1`. With `EXAT expires`, a request replayed in the last second of its life is accepted.
- **Fails closed.** If the store is unreachable, `checkAndStore` rejects, `verifyHttpRequestSignature` rejects with it, and the request must be refused. Never accept a request because the store is down.

## Recommended expiration windows

| Use case | `expiresInSeconds` |
|---|---|
| Real-time API calls | 30 (default) |
| Webhook callbacks | 60 |
| Batch operations | 300 |
| Cross-region calls (high latency) | 120 |

Shorter windows keep the nonce store small. `maxCreatedSkewSeconds` (default 300) bounds clock drift between signer and verifier; it is checked independently of `expires`. `maxSignatureLifetimeSeconds` (default 300) caps `expires - created`, which bounds how long a nonce is retained.

## Relation to Web Bot Auth

The IETF *web-bot-auth* drafts also sign requests with RFC 9421 and use a `Signature-Agent` header. The two profiles are distinct:

- *web-bot-auth* identifies the agent through a key directory URL and uses `tag="web-bot-auth"`;
- Agent-DID identifies the agent by its DID, resolves the key from the DID document, and uses `tag="agent-did"`.

The different `tag` values keep a signature made for one profile from being accepted by the other. An agent can carry both signatures on the same request under different labels.
