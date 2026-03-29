# Anti-Replay Protection for HTTP Signatures

## Overview

Starting with SDK v0.2.0, all HTTP request signatures include **anti-replay** protection via two mechanisms:

1. **`x-request-nonce`** — A unique 128-bit random hex string included in every signed request
2. **`expires`** — A Unix timestamp after which the signature is no longer valid (default: 30 seconds)

## Signer Side (SDK)

```typescript
// TypeScript
const headers = await agentIdentity.signHttpRequest({
  method: 'POST',
  url: 'https://api.example.com/v1/action',
  body: '{"action":"approve"}',
  agentPrivateKey: myKey,
  agentDid: myDid,
  expiresInSeconds: 60 // optional, default: 30
});
// headers now includes 'X-Request-Nonce' and Signature-Input has 'expires=' param
```

```python
# Python
headers = await identity.sign_http_request(SignHttpRequestParams(
    method="POST",
    url="https://api.example.com/v1/action",
    body='{"action":"approve"}',
    agent_private_key=my_key,
    agent_did=my_did,
    expires_in_seconds=60,  # optional, default: 30
))
```

## Verifier Side (Server Guidance)

Servers **MUST** implement the following to fully leverage anti-replay protection:

### 1. Validate Expiration

The SDK verifier already rejects signatures where `now > expires`. Servers calling `verifyHttpRequestSignature()` get this for free.

### 2. Maintain a Nonce Cache

To prevent replay attacks within the valid window, servers **MUST**:

- Extract the `X-Request-Nonce` header value
- Check if the nonce has been seen before within the expiration window
- **Reject** the request if the nonce is a duplicate
- Store the nonce with its associated `expires` timestamp
- Periodically purge nonces whose `expires` timestamp is in the past

#### Example Implementation (Pseudocode)

```
nonce_cache = {}  # Map<nonce_string, expires_timestamp>

function validate_request(headers):
    nonce = headers["X-Request-Nonce"]
    expires = parse_expires_from_signature_input(headers["Signature-Input"])
    
    # 1. Check expiration
    if now() > expires:
        return REJECT("signature expired")
    
    # 2. Check nonce uniqueness
    if nonce in nonce_cache:
        return REJECT("duplicate nonce — possible replay")
    
    # 3. Verify cryptographic signature
    if not verify_http_request_signature(headers, ...):
        return REJECT("invalid signature")
    
    # 4. Store nonce
    nonce_cache[nonce] = expires
    
    # 5. Periodically clean expired nonces
    purge_expired_nonces(nonce_cache)
    
    return ACCEPT
```

### 3. Recommended Expiration Windows

| Use Case | Recommended `expiresInSeconds` |
|---|---|
| Real-time API calls | 30 (default) |
| Webhook callbacks | 60 |
| Batch operations | 300 |
| Cross-region calls (high latency) | 120 |

### 4. Clock Skew

The `maxCreatedSkewSeconds` parameter (default: 300s) handles clock drift between signer and verifier. This is separate from `expires` — even if the creation timestamp is within skew tolerance, the signature is rejected if `expires` is in the past.

## Covered Components

The following components are now **required** in the signature base:

- `@request-target` — HTTP method + path
- `host` — Target hostname
- `date` — Request date header
- `content-digest` — SHA-256 body digest
- `x-request-nonce` — Unique replay-prevention token

Signatures missing `x-request-nonce` in their covered components will be rejected by the verifier.
