# agent-did-sdk (Python)

Python SDK for the **Agent-DID Specification (RFC-001)** — create, sign, resolve, verify and revoke Agent-DIDs.

Full feature parity with the TypeScript SDK (`@agent-did/sdk`).

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
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams

async def main():
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

## Modules

| Module | Description |
|--------|-------------|
| `core.types` | Pydantic models for RFC-001 (AgentDIDDocument, etc.) |
| `core.identity` | `AgentIdentity` — main class for DID lifecycle |
| `core.time_utils` | ISO-8601 ↔ Unix timestamp utilities |
| `crypto.hash` | SHA-256 hashing with `hash://` URI format |
| `registry.*` | Agent registry (in-memory, EVM adapter, Web3 client) |
| `resolver.*` | DID resolver (in-memory, HTTP source, JSON-RPC source, universal) |

## Testing

```bash
cd sdk-python
pip install -e ".[dev]"
pytest --cov
```

## License

MIT
