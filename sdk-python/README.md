# agent-did-sdk (Python)

Python SDK for the **Agent-DID Specification (RFC-001)** — create, sign, resolve, verify and revoke Agent-DIDs.

Functional parity with the TypeScript SDK (`@agentdid/sdk`), with a dedicated Python CI pipeline and shared interoperability fixtures.

Formal parity tracking is documented in `../docs/F2-01-TS-Python-Parity-Matrix.md`.

> **Public Review note:** Agent-DID is pre-1.0 and the RFC is still under community review. See [../docs/DEPRECATION-POLICY.md](../docs/DEPRECATION-POLICY.md) for compatibility and breaking-change expectations during this phase.

Pythonic surface conventions apply:

- constructor config uses `signer_address`
- instance methods use `snake_case`
- lifecycle-wide operations such as revoke/update/rotate/resolve remain class methods on `AgentIdentity`

## Installation

```bash
pip install agent-did-sdk
```

For development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
import asyncio
from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryAgentRegistry,
)

async def main():
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0xYourWalletAddress"))

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

## Features

| Feature | API | Status |
|---|---|---|
| Create Agent-DID document | `identity.create(params)` | ✅ |
| Sign messages (Ed25519) | `identity.sign_message(payload, key)` | ✅ |
| Sign HTTP requests (Bot Auth) | `identity.sign_http_request(params)` | ✅ |
| Verify message signatures | `AgentIdentity.verify_signature(did, payload, sig)` | ✅ |
| Enforce key purpose binding | `assert_key_purpose(key_id, did_doc, purpose)` | ✅ |
| Verify HTTP signatures | `AgentIdentity.verify_http_request_signature(params)` | ✅ |
| Resolve DID → document | `AgentIdentity.resolve(did)` | ✅ |
| Revoke DID | `AgentIdentity.revoke_did(did)` | ✅ |
| Update document | `AgentIdentity.update_did_document(did, patch)` | ✅ |
| Rotate verification keys | `AgentIdentity.rotate_verification_method(did)` | ✅ |
| Document history/audit | `AgentIdentity.get_document_history(did)` + `AgentIdentity.export_did_webvh_history(did)` + `AgentIdentity.import_did_webvh_history(log)` + `AgentIdentity.save_did_webvh_history_to_file(did, path)` + `AgentIdentity.load_did_webvh_history_from_file(path)` + `AgentIdentity.persist_did_webvh_history_to_source(did, ref, source)` + `AgentIdentity.restore_did_webvh_history_from_source(ref, source)` | ✅ |
| Filesystem storage adapter | `FilesystemDIDDocumentSource` | ✅ |
| Remote HTTP storage adapter | `HttpDIDDocumentSource` (`store_by_reference`, `get_did_log_by_reference`, `store_did_log_by_reference`) | ✅ |
| Authenticated HTTP gateway adapter | `BearerTokenHttpDIDDocumentSource` | ✅ |
| Presigned/object-storage adapter | `PresignedHttpDIDDocumentSource` | ✅ |
| S3-compatible object-store adapter | `S3CompatibleDIDDocumentSource` | ✅ |
| AWS SigV4 S3 adapter | `AwsSigV4S3DIDDocumentSource` | ✅ |
| EVM registry adapter | `EvmAgentRegistry` + `Web3AgentRegistryContractClient` | ✅ |
| Universal resolver (HTTP/RPC/IPFS) | `UniversalResolverClient` | ✅ |

By default, `verify_signature` and HTTP signature verification require the signing key to be listed under `assertionMethod` in the DID document. Passing a key that exists only under another relationship, including `keyAgreement`, raises `IdentityCompositionError` with reason `key_purpose_violation`.

## Modules

| Module | Description |
|--------|-------------|
| `core.types` | Pydantic models for RFC-001 (AgentDIDDocument, etc.) |
| `core.identity` | `AgentIdentity` — main class for DID lifecycle |
| `core.time_utils` | ISO-8601 ↔ Unix timestamp utilities |
| `crypto.hash` | SHA-256 hashing with `hash://` URI format |
| `registry.*` | Agent registry (in-memory, EVM adapter, Web3 client) |
| `resolver.*` | DID resolver (in-memory, filesystem source, HTTP source, bearer/authenticated HTTP source, presigned/object-storage source, S3-compatible source, AWS SigV4 S3 source, JSON-RPC source, universal) |

## Optional EVM Registry Integration

If a deployment explicitly needs the deferred EVM profile, connect the SDK to a real on-chain `AgentRegistry` contract:

```python
from web3 import HTTPProvider, Web3

from agent_did_sdk import AgentIdentity, EvmAgentRegistry, Web3AgentRegistryContractClient
from agent_did_sdk.registry.evm_types import EvmAgentRegistryAdapterConfig

provider = Web3(HTTPProvider("http://127.0.0.1:8545"))
contract = provider.eth.contract(address=REGISTRY_ADDRESS, abi=ABI)

registry = EvmAgentRegistry(
    EvmAgentRegistryAdapterConfig(
        contract_client=Web3AgentRegistryContractClient(contract),
        await_transaction_confirmation=True,
    )
)

AgentIdentity.set_registry(registry)
```

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
cd contracts
npm ci

cd ../sdk-python
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
