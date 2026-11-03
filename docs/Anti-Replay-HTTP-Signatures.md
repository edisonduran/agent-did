# HTTP Message Signatures and Anti-Replay

Agent-DID signs HTTP requests with [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures. This page describes the Agent-DID profile and how verifiers prevent replay. The normative text is RFC-001 §6.5.

> Applies to the `1.0.0-rc.3` train (`main`). The `1.0.0-rc.2` and earlier releases used an `X-Request-Nonce` header and a different signature base; see the rc.2 → rc.3 migration guides.

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
2. `created` is within `maxCreatedSkewSeconds` of now (default 300 s), `expires >= created`, and `now <= expires`.
3. `Content-Digest` matches the body.
4. The signature verifies over the base rebuilt from the received request, with `@signature-params` re-serialized from the parsed `Signature-Input`, using an active `assertionMethod` key of a DID whose controller chain is active.
5. The `(keyid, nonce)` pair has not been seen before. It is then recorded until `expires`.

The nonce is recorded only after the signature verifies, so forged requests cannot consume other clients' nonces.

## Replay protection: `NonceStore`

Step 5 uses a `NonceStore`. By default it is a process-wide `InMemoryNonceStore`, which is correct for a single verifier instance. It refuses new nonces when full rather than evicting live ones.

When several instances verify requests for the same agents, pass a shared store:

```typescript
import { createClient } from 'redis';
import { NonceStore } from '@agentdid/sdk';

const redis = createClient();
await redis.connect();

const redisNonceStore: NonceStore = {
  async checkAndStore(key, expiresAt) {
    // Atomic: set only if absent, expire at the signature's `expires`.
    return (await redis.set(`agent-did:nonce:${key}`, '1', { NX: true, EXAT: expiresAt })) === 'OK';
  }
};

await AgentIdentity.verifyHttpRequestSignature({ method, url, body, headers, nonceStore: redisNonceStore });
```

```python
import redis.asyncio as redis

class RedisNonceStore:
    def __init__(self, client: redis.Redis) -> None:
        self._client = client

    async def check_and_store(self, key: str, expires_at: int) -> bool:
        return bool(await self._client.set(f"agent-did:nonce:{key}", 1, nx=True, exat=expires_at))

await AgentIdentity.verify_http_request_signature(VerifyHttpRequestSignatureParams(
    method=method, url=url, body=body, headers=headers, nonce_store=RedisNonceStore(redis.Redis()),
))
```

## Recommended expiration windows

| Use case | `expiresInSeconds` |
|---|---|
| Real-time API calls | 30 (default) |
| Webhook callbacks | 60 |
| Batch operations | 300 |
| Cross-region calls (high latency) | 120 |

Shorter windows keep the nonce store small. `maxCreatedSkewSeconds` (default 300) bounds clock drift between signer and verifier; it is checked independently of `expires`.

## Relation to Web Bot Auth

The IETF *web-bot-auth* drafts also sign requests with RFC 9421 and use a `Signature-Agent` header. The two profiles are distinct:

- *web-bot-auth* identifies the agent through a key directory URL and uses `tag="web-bot-auth"`;
- Agent-DID identifies the agent by its DID, resolves the key from the DID document, and uses `tag="agent-did"`.

The different `tag` values keep a signature made for one profile from being accepted by the other. An agent can carry both signatures on the same request under different labels.
