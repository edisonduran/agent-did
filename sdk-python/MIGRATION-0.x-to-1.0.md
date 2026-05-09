# agent-did-sdk Migration Guide: 0.x -> 1.0

This guide is for adopters moving from any pre-`1.0.0` release of `agent-did-sdk` to the co-versioned `1.0.0` release train.

## What Changed

- `did:webvh` is now the default DID emission and verification profile.
- Local `did:webvh` bootstrap is the default developer path; hosted publication of `did.jsonl` remains a separate deployment step.
- Signature and HTTP verification enforce `assertionMethod` by default.
- Verification resolves the controller chain and rejects inactive or unresolvable states.
- The EVM registry adapter remains available only as an explicit compatibility profile. It is outside the core `1.0.0` release promise.

## Before and After

### 1. Default identity creation

Typical `0.x` compatibility-style code, especially when legacy `did:agent` or on-chain assumptions were still common:

```python
result = await identity.create(CreateAgentParams(
    name="SupportBot-X",
    core_model="gpt-4o-mini",
    system_prompt="You are a helpful assistant",
    did_method="agent",
))
```

`1.0.0` default web-native path:

```python
result = await identity.create(CreateAgentParams(
    name="SupportBot-X",
    core_model="gpt-4o-mini",
    system_prompt="You are a helpful assistant",
    # did_method defaults to "webvh"
))
```

### 2. Hosted `did:webvh` publication

If you are publishing a hosted `did:webvh` instead of relying on local bootstrap defaults, make the `webvh` options explicit:

```python
from agent_did_sdk import CreateAgentParams, CreateDidWebvhOptions

result = await identity.create(CreateAgentParams(
    name="SupportBot-X",
    core_model="gpt-4o-mini",
    system_prompt="You are a helpful assistant",
    webvh=CreateDidWebvhOptions(
        domain="agents.example.com",
        controller_did="did:webvh:example.com:org:root",
        path_segments=["agents", "supportbot-x"],
    ),
))
```

### 3. Keeping the compatibility profile on purpose

If you still need the deferred EVM/on-chain profile, keep it explicit in code and deployment docs:

```python
AgentIdentity.set_registry(evm_registry)

result = await identity.create(CreateAgentParams(
    name="SupportBot-X",
    core_model="gpt-4o-mini",
    system_prompt="You are a helpful assistant",
    did_method="agent",
))
```

## Behavior Changes to Audit

- Default DID shape: tests and snapshots should now expect `did:webvh` identifiers unless `did_method="agent"` is set explicitly.
- Key-purpose enforcement: payload and HTTP signing keys must be listed under `assertionMethod`. Keys that exist only under `keyAgreement` now fail with `key_purpose_violation`.
- Controller-chain verification: `verify_signature` and `verify_http_request_signature` now resolve the canonical controller chain and reject inactive or unresolvable paths.
- Hosting boundary: `create()` proves the local lifecycle first. Production hosting uses the history export/persistence APIs and the resolver configuration surface.
- Scope boundary: core `1.0.0` no longer assumes a public testnet, on-chain registry deployment, or EVM-based revocation path.

## Upgrade Checklist

- Remove any code, docs, or tests that assume chain-backed registration is the default.
- Update snapshots and downstream assertions for `did:webvh` output.
- Ensure your signing keys are published under `assertionMethod`.
- If you publish `did:webvh` histories, pass explicit `webvh` options or persist exported history after creation.
- If you truly need EVM, fence it behind explicit registry wiring and `did_method="agent"`.

## References

- [../docs/DEPRECATION-POLICY.md](../docs/DEPRECATION-POLICY.md)
- [../docs/RELEASE-1.0-CRITERIA.md](../docs/RELEASE-1.0-CRITERIA.md)
- [../CHANGELOG.md](../CHANGELOG.md)