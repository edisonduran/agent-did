# agent-did-sdk (Python)

Python SDK for the **Agent-DID Specification (RFC-001)** — create, sign, resolve, verify and revoke Agent-DIDs.

Functional parity with the TypeScript SDK (`@agentdid/sdk`), with a dedicated Python CI pipeline and shared interoperability fixtures.

Formal parity tracking is documented in `../docs/F2-01-TS-Python-Parity-Matrix.md`.

> **Release-candidate note:** The repository is frozen for the `1.0.0-rc.5` release train and RFC-001 is now treated as Stable text. Final `v1.0.0` publication still depends on the remaining gates in [../docs/RELEASE-1.0-CRITERIA.md](../docs/RELEASE-1.0-CRITERIA.md).
>
> **Moving from `0.x`?** See [MIGRATION-0.x-to-1.0.md](MIGRATION-0.x-to-1.0.md). Coming from `1.0.0rc3`? The breaking changes in `1.0.0rc5` are listed in [MIGRATION-1.0-rc.3-to-rc.5.md](MIGRATION-1.0-rc.3-to-rc.5.md); from `1.0.0rc2`, see [MIGRATION-1.0-rc.2-to-rc.3.md](MIGRATION-1.0-rc.2-to-rc.3.md) first.

Pythonic surface conventions apply:

- constructor config uses `controller_signer` (an Ed25519 `AgentSigner`)
- instance methods use `snake_case`
- lifecycle-wide operations such as revoke/update/rotate/resolve remain class methods on `AgentIdentity`

## Installation

```bash
pip install agent-did-sdk==1.0.0rc5
```

For development:

```bash
pip install -e ".[dev]"
```

RFC 3161 timestamp tokens (`verify_timestamp_token`, `create_timestamp_request` and the `timestamp_token` option of `verify_signature_at_time`) need the optional extra, which adds `rfc3161-client` (no Windows ARM64 wheel):

```bash
pip install "agent-did-sdk[timestamps]==1.0.0rc5"
```

The optional EVM registry adapter is a separate package, `agent-did-evm`, maintained in [edisonduran/agent-did-evm](https://github.com/edisonduran/agent-did-evm). Up to `1.0.0rc4` it shipped here as `agent_did_sdk.evm` (extra `[evm]`).

### Platform support

| Platform | Status |
|---|---|
| Linux glibc x86_64 and aarch64 (for example Debian, Ubuntu and the `python:*-slim` images) | Supported |
| macOS arm64 | Supported |
| Windows x86_64 | Supported |
| Alpine Linux (musl) | **Does not install** |
| Windows ARM64 | **Does not install** |

Since `1.0.0rc3` the SDK depends on [`did-webvh`](https://pypi.org/project/did-webvh/), the did:webvh v1.0 reference implementation, which requires the native `aries-askar` library. `aries-askar` publishes wheels for Linux glibc (x86_64, aarch64), macOS and Windows x86_64 only, and no source distribution, so `pip install agent-did-sdk` fails on Alpine and Windows ARM64. The limit comes from that upstream dependency; the SDK's own dependencies have wheels there. On containers, use a glibc-based image such as `python:3.12-slim`.

The [`CI — Python Platform Support`](../.github/workflows/ci-python-platforms.yml) workflow checks this table every night: it installs the SDK and runs a smoke test on each supported platform, and requires the install to fail on the other two because of `aries-askar`, so the table is updated as soon as that changes.

## Quick Start

```python
import asyncio
from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryAgentRegistry,
    LocalKeySigner,
)

async def main():
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))

    result = await identity.create(CreateAgentParams(
        name="MyAgent",
        core_model="gpt-4-turbo",
        system_prompt="You are a helpful assistant.",
        capabilities=["search", "code-execution"],
    ))

    print(f"Agent DID: {result.document.id}")
    print(f"Private Key: {result.agent_private_key}")

    # Sign a message
    signature = await identity.sign_message("Hello, World!", result.agent_private_key)

    # Verify
    is_valid = await AgentIdentity.verify_signature(
        result.document.id, "Hello, World!", signature
    )
    print(f"Valid: {is_valid}")

asyncio.run(main())
```

This quickstart validates the local signing lifecycle first. By default the SDK follows the canonical `did:webvh` path and bootstraps the local controller side for you; hosted publication of `did.jsonl` is a separate deployment concern.

Since `1.0.0rc3`, `did:webvh` DIDs are did:webvh v1.0 DIDs: the `did.jsonl` log has a self-certifying SCID and every entry is signed by the controller key, through the DIF reference implementation `did-webvh`. CI runs the pinned DIF `didwebvh-test-suite` vectors against the SDK's did:webvh layer. See [MIGRATION-1.0-rc.2-to-rc.3.md](MIGRATION-1.0-rc.2-to-rc.3.md) for the explicit profile's `controller_signer` and for re-issuing older DIDs.

An agent's controller does not have to be an Agent-DID document: any DID Core `did:webvh` document works, for example your organization's DID created with another did:webvh tool (RFC-001 §4.2.1). Pass it as `CreateDidWebvhOptions.controller_did` with a `controller_signer` whose key the controller lists under `capabilityInvocation`. `resolve_document(did)` returns such a document; `resolve(did)` returns Agent-DID documents only.

## Features

| Feature | API | Status |
|---|---|---|
| Create Agent-DID document | `identity.create(params)` | ✅ |
| Sign messages (Ed25519) | `identity.sign_message(payload, key)` | ✅ |
| Sign HTTP requests (RFC 9421) | `identity.sign_http_request(params)` | ✅ |
| Verify message signatures | `AgentIdentity.verify_signature(did, payload, sig)` | ✅ |
| Enforce key purpose binding | `assert_key_purpose(key_id, did_doc, purpose)` | ✅ |
| Verify HTTP signatures (RFC 9421, replay protection via `NonceStore`; the default store is per process, pass a shared one when several instances verify) | `AgentIdentity.verify_http_request_signature(params)` | ✅ |
| Verify HTTP signatures, with the reason of a rejection | `client.verify_http_request_signature_detailed(params)` | ✅ |
| Resolve DID → document | `AgentIdentity.resolve(did)` | ✅ |
| Revoke DID | `AgentIdentity.revoke_did(did)` | ✅ |
| Update document | `AgentIdentity.update_did_document(did, patch)` | ✅ |
| Rotate verification keys | `AgentIdentity.rotate_verification_method(did)` (`emergency=True` also revokes the old keys) | ✅ |
| Retire or revoke one key | `client.retire_verification_method(did, key_id, emergency=...)` | ✅ |
| Signed A2A Agent Cards (composition contract) | `sign_agent_card(card, signer, key_id)`, `client.verify_agent_card(card)`, `client.verify_identity_composition(params)` | ✅ |
| Document history/audit | `AgentIdentity.get_document_history(did)` + `AgentIdentity.export_did_webvh_history(did)` + `AgentIdentity.import_did_webvh_history(log)` + `AgentIdentity.save_did_webvh_history_to_file(did, path)` + `AgentIdentity.load_did_webvh_history_from_file(path)` + `AgentIdentity.persist_did_webvh_history_to_source(did, ref, source)` + `AgentIdentity.restore_did_webvh_history_from_source(ref, source)` | ✅ |
| Filesystem storage adapter | `FilesystemDIDDocumentSource` | ✅ |
| Remote HTTP storage adapter | `HttpDIDDocumentSource` (`store_by_reference`, `get_did_log_by_reference`, `store_did_log_by_reference`) | ✅ |
| Authenticated HTTP gateway adapter | `BearerTokenHttpDIDDocumentSource` | ✅ |
| Presigned/object-storage adapter | `PresignedHttpDIDDocumentSource` | ✅ |
| S3-compatible object-store adapter | `S3CompatibleDIDDocumentSource` | ✅ |
| AWS SigV4 S3 adapter | `AwsSigV4S3DIDDocumentSource` | ✅ |
| Universal resolver (HTTP/RPC/IPFS) | `UniversalResolverClient` | ✅ |
| Agent metadata credential (VC 2.0, `eddsa-jcs-2022`, RFC-001 §4.4; the controller signs, verification checks issuer, binding and proof) | `client.issue_agent_metadata_credential(params)` / `client.verify_agent_metadata_credential(credential)` | ✅ |
| Capabilities: delegation and HTTP invocation (RFC-001 §6.7; no per-capability revocation, keep `expires` short) | `client.create_capability(...)`, `client.verify_capability_chain(capability, root_controllers=...)`, `SignHttpRequestParams(capability=...)`, `client.verify_http_capability_invocation(params)` | ✅ |
| OAuth client assertion with the DID key (`private_key_jwt`, RFC-001 §6.8; the SDK runs no OAuth flow) | `create_client_assertion(...)`, `build_client_jwks(document)`, `build_client_metadata_document(...)`, `client.verify_client_assertion(...)` | ✅ |

By default, `verify_signature` and HTTP signature verification require the signing key to be listed under `assertionMethod` in the DID document. Passing a key that exists only under another relationship, including `keyAgreement`, raises `IdentityCompositionError` with reason `key_purpose_violation`.

## Modules

| Module | Description |
|--------|-------------|
| `core.types` | Pydantic models for RFC-001 (AgentDIDDocument, etc.) |
| `core.identity` | `AgentIdentity` — main class for DID lifecycle |
| `core.time_utils` | ISO-8601 ↔ Unix timestamp utilities |
| `crypto.hash` | SHA-256 hashing with `hash://` URI format |
| `crypto.data_integrity` | `eddsa-jcs-2022` Data Integrity proofs (W3C `vc-di-eddsa` vectors in CI) |
| `core.agent_metadata_credential` | `AgentMetadataCredential` profile (RFC-001 §4.4) |
| `core.capability` | Capabilities: form, chain and attenuation checks, `Agent-DID-Capability` field (RFC-001 §6.7) |
| `core.oauth_client` | OAuth client assertion, JWKS and Client ID Metadata Document (RFC-001 §6.8) |
| `registry.*` | Agent registry (in-memory) |
| `resolver.*` | DID resolver (in-memory, filesystem source, HTTP source, bearer/authenticated HTTP source, presigned/object-storage source, S3-compatible source, AWS SigV4 S3 source, JSON-RPC source, universal) |

## Optional EVM Registry Integration

The core SDK has no EVM dependency. The optional adapter `agent-did-evm` (`import agent_did_evm`) is maintained with the on-chain `AgentRegistry` contract in [edisonduran/agent-did-evm](https://github.com/edisonduran/agent-did-evm); see its README for the wiring.

See full example: `examples/evm_registry_wiring.py`

## Production Resolver

Configure a production-grade resolver with failover and caching:

```python
from agent_did_sdk import AgentIdentity, ProductionHttpResolverProfileConfig

AgentIdentity.use_production_resolver_from_http(
    ProductionHttpResolverProfileConfig(
        registry=evm_registry,  # optional when using the EVM compatibility profile
        cache_ttl_ms=60_000,
        ipfs_gateways=["https://gateway.pinata.cloud", "https://ipfs.io"],
        on_resolution_event=lambda event: print("Resolution:", event.stage),
    )
)
```

Minimal `did:wba` example: `examples/did_wba_resolution.py`

A did:webvh log imported with `import_did_webvh_history` is a copy, not an authority. With a resolver that fetches logs (the production resolver), the next resolution fetches the host's log at once and the longer of the two wins; if the host cannot be reached, the resolution fails closed. The imported log is used as is only when the resolver does not fetch logs (the in-memory default); then nothing tells an older copy (for example one from before a revocation) from the current log, so import logs only from a source you trust to be current.

### did:webvh witnesses and RFC 3161 timestamps

Witnesses ([ADR-007](../docs/ADR-007-Witnesses-and-Timestamps.md)): create with `CreateDidWebvhOptions(..., witness=DidWebvhWitnessConfig(threshold=2, witnesses=["did:key:z6Mk...", "did:key:z6Mk..."]))`, change with `client.set_did_webvh_witnesses(did, rule_or_None)`, and give the client `AgentDidClientOptions(collect_witness_proofs=...)`, an async function that returns each witness's approval (a witness signs with `create_did_webvh_witness_proof`). Publish `client.export_did_webvh_witness_file(did)` as `did-witness.json` before `did.jsonl`. The production resolver fetches it and fails closed when the approvals do not reach a threshold. Watchers are not supported.

Timestamps: `verify_signature_at_time(..., stated_time=..., timestamp_token=tsr, tsa_trust_anchors=[tsa_root_pem])` verifies an RFC 3161 token over the raw signature bytes and uses `genTime + accuracy` as trusted time evidence; a token that does not verify gives `reason="timestamp_invalid"` and `timestamp_rejection`. `create_timestamp_request(signature_bytes)` builds the request; sending it to a TSA is up to you. Revocation of TSA certificates is not checked.

## Testing

Canonical local workflow:

```bash
cd sdk-python
python -m pip install -e ".[dev]"
ruff check src/ tests/ scripts/
mypy --strict src/
pytest --cov=agent_did_sdk --cov-fail-under=85 -q
```

Repository-level convenience wrappers are also available from the repo root:

```bash
npm run python:test
npm run python:conformance
```

These `npm` commands are only monorepo shortcuts. The canonical Python commands remain the native `python`, `pytest`, `ruff`, and `mypy` commands shown above.

For end-to-end web-native publication and hosted DID history flows, see the examples under `examples/` that exercise `did:webvh`, writable document sources, and external smoke targets.

```bash
cd sdk-python
pip install -e ".[dev]"
pytest --cov
```

RFC-001 Python conformance:

```bash
cd sdk-python
python scripts/conformance_rfc001.py
```

Operational smokes:

```bash
cd sdk-python
python scripts/rpc_resolver_smoke.py
python scripts/resolver_ha_smoke.py
python scripts/revocation_policy_smoke.py
python scripts/e2e_smoke.py
```

## Maintainer Release to PyPI

The repository includes `.github/workflows/publish-python-sdk.yml` for PyPI Trusted Publishing.

Before the first release, create the `agent-did-sdk` project on PyPI and, optionally, TestPyPI, then register GitHub Trusted Publishers for:

- repository: `edisonduran/agent-did`
- workflow file: `.github/workflows/publish-python-sdk.yml`
- workflow trigger: tag `sdk-python-vX.Y.Z` for PyPI, `workflow_dispatch` for TestPyPI or manual PyPI release

If you want GitHub environment approvals, add matching environments later and bind them in both GitHub and PyPI Trusted Publishing settings.

Release preparation:

```bash
cd sdk-python
python -m pip install -e ".[dev]"
python -m build
python -m twine check dist/*
```

Release flow:

- bump `version` in `pyproject.toml`
- run the workflow manually with `repository=testpypi` to validate the package on TestPyPI
- publish to PyPI by pushing a tag named `sdk-python-vX.Y.Z`
- alternatively, run the workflow manually from `main` with `repository=pypi`

## License

[Apache-2.0](../LICENSE) — see root LICENSE.
