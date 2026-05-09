# @agentdid/sdk Migration Guide: 0.x -> 1.0

This guide is for adopters moving from any pre-`1.0.0` release of `@agentdid/sdk` to the co-versioned `1.0.0` release train.

## What Changed

- `did:webvh` is now the default DID emission and verification profile.
- Local `did:webvh` bootstrap is the default developer path; hosted publication of `did.jsonl` remains a separate deployment step.
- Signature and HTTP verification enforce `assertionMethod` by default.
- Verification resolves the controller chain and rejects inactive or unresolvable states.
- The EVM registry adapter remains available only as an explicit compatibility profile. It is outside the core `1.0.0` release promise.

## Before and After

### 1. Default identity creation

Typical `0.x` compatibility-style code, especially when legacy `did:agent` or on-chain assumptions were still common:

```ts
const result = await identity.create({
  name: 'SupportBot-X',
  coreModel: 'gpt-4o-mini',
  systemPrompt: 'You are a helpful assistant',
  didMethod: 'agent',
});
```

`1.0.0` default web-native path:

```ts
const result = await identity.create({
  name: 'SupportBot-X',
  coreModel: 'gpt-4o-mini',
  systemPrompt: 'You are a helpful assistant',
  // didMethod defaults to 'webvh'
});
```

### 2. Hosted `did:webvh` publication

If you are publishing a hosted `did:webvh` instead of relying on local bootstrap defaults, make the `webvh` options explicit:

```ts
const result = await identity.create({
  name: 'SupportBot-X',
  coreModel: 'gpt-4o-mini',
  systemPrompt: 'You are a helpful assistant',
  webvh: {
    domain: 'agents.example.com',
    controllerDid: 'did:webvh:example.com:org:root',
    pathSegments: ['agents', 'supportbot-x'],
  },
});
```

### 3. Keeping the compatibility profile on purpose

If you still need the deferred EVM/on-chain profile, keep it explicit in code and deployment docs:

```ts
AgentIdentity.setRegistry(evmRegistry);

const result = await identity.create({
  name: 'SupportBot-X',
  coreModel: 'gpt-4o-mini',
  systemPrompt: 'You are a helpful assistant',
  didMethod: 'agent',
});
```

## Behavior Changes to Audit

- Default DID shape: tests and snapshots should now expect `did:webvh` identifiers unless `didMethod: 'agent'` is set explicitly.
- Key-purpose enforcement: payload and HTTP signing keys must be listed under `assertionMethod`. Keys that exist only under `keyAgreement` now fail with `key_purpose_violation`.
- Controller-chain verification: `verifySignature` and `verifyHttpRequestSignature` now resolve the canonical controller chain and reject inactive or unresolvable paths.
- Hosting boundary: `create()` proves the local lifecycle first. Production hosting uses the history export/persistence APIs and the resolver configuration surface.
- Scope boundary: core `1.0.0` no longer assumes a public testnet, on-chain registry deployment, or EVM-based revocation path.

## Upgrade Checklist

- Remove any code, docs, or tests that assume chain-backed registration is the default.
- Update snapshots and downstream assertions for `did:webvh` output.
- Ensure your signing keys are published under `assertionMethod`.
- If you publish `did:webvh` histories, pass explicit `webvh` options or persist exported history after creation.
- If you truly need EVM, fence it behind explicit registry wiring and `didMethod: 'agent'`.

## References

- [../docs/DEPRECATION-POLICY.md](../docs/DEPRECATION-POLICY.md)
- [../docs/RELEASE-1.0-CRITERIA.md](../docs/RELEASE-1.0-CRITERIA.md)
- [../CHANGELOG.md](../CHANGELOG.md)