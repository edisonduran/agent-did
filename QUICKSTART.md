# Quickstart

This guide gets you from install to a signed outbound HTTP request in a couple of minutes.

The canonical RFC-001 v0.3 deployment pattern starts from a `did:webvh` identity chain, for example:

- controller/root: `did:webvh:{SCID}:example.com:organizations:acme-support`
- agent: `did:webvh:{SCID}:example.com:agents:quickstart-bot`

`{SCID}` is the self-certifying identifier that did:webvh v1.0 derives from each DID's genesis log entry; the SDK computes it when it creates the DID.

The examples below are intentionally local and self-contained. They use an in-memory registry so you can prove the end-to-end signing flow before wiring a hosted `did:webvh` publication and resolver path. For this local flow, the SDK bootstraps the controller side for you instead of asking you to stand up hosted DID history first.

If you want a live browser walkthrough before wiring code, open [Agent-DID in Action](https://edisonduran.github.io/agent-did-in-action/): real signed handoffs, live tamper detection, and the published `@agentdid/sdk` running in the browser.

## Node.js (TypeScript SDK, local signing flow)

Install (requires Node.js 22.12+):

```bash
npm install @agentdid/sdk@next
```

`@next` selects the newest release candidate (currently `1.0.0-rc.4`). Pin the version in production: the `0.x` releases do not interoperate with the release candidates.

Save this as `quickstart.js` and run `node quickstart.js`:

```js
const { AgentIdentity, InMemoryAgentRegistry, LocalKeySigner } = require('@agentdid/sdk');

const main = async () => {
  AgentIdentity.setRegistry(new InMemoryAgentRegistry());

  const [controllerSigner] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner });

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

  console.log({
    did: created.document.id,
    controller: created.document.controller,
    ok,
    headerNames: Object.keys(headers).sort()
  });
};

void main();
```

This snippet proves the current local SDK signing flow. The SDK auto-bootstraps a local controller root for this path; hosted `did:webvh` publication is a separate deployment concern from this minimal example.

## Python (local signing flow)

Install:

```bash
pip install agent-did-sdk==1.0.0rc4
```

Pinning `1.0.0rc4` selects the release candidate; without it pip installs the pre-RC `0.1.0`, whose DIDs and HTTP signatures do not interoperate with `1.0.0rc4`. The SDK needs a glibc Linux, macOS or Windows x86_64 environment (no Alpine or Windows ARM64; see [sdk-python/MIGRATION-1.0-rc.2-to-rc.3.md](sdk-python/MIGRATION-1.0-rc.2-to-rc.3.md)).

Save this as `quickstart.py` and run `python quickstart.py`:

```python
import asyncio
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner, SignHttpRequestParams, VerifyHttpRequestSignatureParams

async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))

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

This snippet likewise validates the local SDK lifecycle first. Treat `did:webvh` publication and controller-chain hosting as the next deployment step, not as something this minimal example automates yet.

## What You Just Proved

After the example runs successfully, you have demonstrated that Agent-DID can:

- create a new agent identity
- sign an outbound HTTP request with the agent's key material
- verify that signature using the DID as the trust anchor

This quickstart validates the local signing lifecycle. For the canonical deployment model introduced in RFC-001 v0.3, publish the resulting agent/controller relationship under `did:webvh` with a resolvable controller chain and hosted/verifiable history.

## Next Steps

- Read [docs/RFC-001-Agent-DID-Specification.md](docs/RFC-001-Agent-DID-Specification.md) first if you want the canonical `did:webvh` pattern rather than the minimal local flow.
- Open [Agent-DID in Action](https://edisonduran.github.io/agent-did-in-action/) for the live browser demo gallery.
- **Production warning:** `verifyHttpRequestSignature` / `verify_http_request_signature` remember nonces in an **in-memory, per-process** store by default. With more than one verifier instance (replicas, serverless functions, Kubernetes) a replayed request is accepted by any instance that has not seen it. Pass a shared `nonceStore` / `nonce_store` (Redis example in [docs/Anti-Replay-HTTP-Signatures.md](docs/Anti-Replay-HTTP-Signatures.md)) before you deploy.
- Read [docs/Anti-Replay-HTTP-Signatures.md](docs/Anti-Replay-HTTP-Signatures.md) before deploying signed HTTP calls in production.
- Read [docs/DEPRECATION-POLICY.md](docs/DEPRECATION-POLICY.md) for pre-1.0 compatibility expectations.