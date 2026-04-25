# Quickstart

This guide gets you from install to a signed outbound HTTP request in a couple of minutes.

The examples below are intentionally local and self-contained. They use an in-memory registry so you can prove the end-to-end flow without deploying a contract or a resolver.

## Node.js (TypeScript SDK)

Install:

```bash
npm install @agentdid/sdk ethers
```

Save this as `quickstart.js` and run `node quickstart.js`:

```js
const { AgentIdentity, InMemoryAgentRegistry } = require('@agentdid/sdk');
const { ethers } = require('ethers');

const main = async () => {
  AgentIdentity.setRegistry(new InMemoryAgentRegistry());

  const wallet = ethers.Wallet.createRandom();
  const identity = new AgentIdentity({ signer: wallet, network: 'polygon' });

  const created = await identity.create({
    name: 'quickstart-bot',
    coreModel: 'gpt-4.1-mini',
    systemPrompt: 'Sign outbound API requests.'
  });

  const headers = await identity.signHttpRequest({
    method: 'POST',
    url: 'https://api.example.com/tasks',
    body: '{"taskId":7}',
    agentPrivateKey: created.agentPrivateKey,
    agentDid: created.document.id
  });

  const ok = await AgentIdentity.verifyHttpRequestSignature({
    method: 'POST',
    url: 'https://api.example.com/tasks',
    body: '{"taskId":7}',
    headers
  });

  console.log({ did: created.document.id, ok, headerNames: Object.keys(headers).sort() });
};

void main();
```

## Python

Install:

```bash
pip install agent-did-sdk
```

Save this as `quickstart.py` and run `python quickstart.py`:

```python
import asyncio
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, SignHttpRequestParams, VerifyHttpRequestSignatureParams

async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9292929292929292929292929292929292929292"))

    created = await identity.create(CreateAgentParams(
        name="quickstart-bot",
        core_model="gpt-4.1-mini",
        system_prompt="Sign outbound API requests.",
    ))

    headers = await identity.sign_http_request(SignHttpRequestParams(
        method="POST",
        url="https://api.example.com/tasks",
        body='{"taskId":7}',
        agent_private_key=created.agent_private_key,
        agent_did=created.document.id,
    ))

    ok = await AgentIdentity.verify_http_request_signature(VerifyHttpRequestSignatureParams(
        method="POST",
        url="https://api.example.com/tasks",
        body='{"taskId":7}',
        headers=headers,
    ))

    print({"did": created.document.id, "ok": ok, "header_names": sorted(headers.keys())})

asyncio.run(main())
```

## What You Just Proved

After the example runs successfully, you have demonstrated that Agent-DID can:

- create a new agent identity
- sign an outbound HTTP request with the agent's key material
- verify that signature using the DID as the trust anchor

## Next Steps

- Read [docs/RFC-001-Agent-DID-Specification.md](docs/RFC-001-Agent-DID-Specification.md) for the normative model.
- Read [docs/Anti-Replay-HTTP-Signatures.md](docs/Anti-Replay-HTTP-Signatures.md) before deploying signed HTTP calls in production.
- Read [docs/DEPRECATION-POLICY.md](docs/DEPRECATION-POLICY.md) for pre-1.0 compatibility expectations.