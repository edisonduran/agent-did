# F1-03 - LangChain `did:wba` Demo Walkthrough

## Objective

Provide a short, canonical walkthrough for the integrated `did:wba` demos shipped in both LangChain packages.

This document is intentionally operational: it explains what the demos prove, how to run them, and what success looks like.

---

## What The Integrated Demo Proves

The integrated `did:wba` demo is meant to show that Agent-DID can act as an identity layer inside the LangChain host surface without requiring:

- external model credentials,
- blockchain access,
- a live public resolver,
- or ad hoc mock code outside the shipped package examples.

In both TypeScript and Python, the demo validates the same four claims in one flow:

1. the active runtime identity can be represented as `did:wba`,
2. a remote counterparty `did:wba` document can be resolved over HTTPS,
3. the LangChain host can exercise Agent-DID tools in a reproducible local run,
4. the resulting outbound HTTP signature is verifiable against the active DID document.

---

## JavaScript Walkthrough

Demo file:

- `integrations/langchain/examples/agentDidLangChain.didWbaDemo.example.js`

Run it locally:

```bash
cd integrations/langchain
node examples/agentDidLangChain.didWbaDemo.example.js
```

Expected outcome:

- `activeDid` equals `did:wba:agents.example:profiles:weather-bot`
- `partnerDid` equals `did:wba:agents.example:partners:dispatch-router`
- `httpSignatureVerified` is `true`
- `signedHeaderNames` includes `Signature`, `Signature-Input`, `Agent-DID`, `Date`, and `Content-Digest`
- `resolutionEvents` includes a resolved event for both the partner DID and the active DID

What is happening internally:

1. a local Agent-DID runtime is created,
2. that runtime document is projected into a `did:wba` shape,
3. a second `did:wba` document acts as the remote counterparty,
4. a mock HTTPS resolver serves both documents,
5. `createAgent(...)` runs with a LangChain fake model,
6. the agent uses Agent-DID tools to inspect identity, resolve the remote DID and sign an HTTP request,
7. the signature is verified with the SDK.

---

## Python Walkthrough

Demo file:

- `integrations/langchain-python/examples/agent_did_langchain_did_wba_demo.py`

Run it locally:

```bash
cd integrations/langchain-python
python examples/agent_did_langchain_did_wba_demo.py
```

Expected outcome:

- `active_did` equals `did:wba:agents.example:profiles:weather-bot`
- `partner_did` equals `did:wba:agents.example:partners:dispatch-router`
- `http_signature_verified` is `true`
- `signed_header_names` includes `Signature`, `Signature-Input`, `Agent-DID`, `Date`, and `Content-Digest`
- `resolution_events` includes a resolved event for both the partner DID and the active DID

What is happening internally:

1. a local runtime identity is constructed directly as a `did:wba` document,
2. a second `did:wba` document acts as the remote counterparty,
3. `httpx.MockTransport` provides the HTTPS resolution layer,
4. `create_agent(...)` runs with a fake chat model,
5. the agent uses Agent-DID tools to inspect identity, resolve the remote DID and sign an HTTP request,
6. the signature is verified with the SDK.

---

## Cross-Package Smoke

The repository also ships a cross-package smoke path that executes both demos from CI and validates their JSON outputs:

```bash
npm run smoke:langchain-didwba
```

This smoke is the operational gate for Historia 3 at the demo level: it proves the two shipped demos remain executable and semantically aligned.

---

## Success Criteria

Historia 3 is considered operationally credible when all of the following remain true at the same time:

1. both demos still execute without external credentials,
2. both demos still emit the expected resolved DIDs,
3. both demos still verify the signed HTTP request successfully,
4. the parity matrix and LangChain review checklist still describe the demos correctly,
5. the CI smoke path remains green.
