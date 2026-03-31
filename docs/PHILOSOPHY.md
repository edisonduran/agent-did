# Agent-DID — Design Philosophy

**Document type:** Conceptual foundation and vision  
**Version:** 1.0  
**Date:** 2026-03-22

---

## The Core Problem

AI is no longer just a tool that humans use — it is becoming an actor that makes decisions, negotiates, executes code, signs operations, and delegates tasks to other agents. This transition raises a question the industry still lacks a clear answer for:

> **How does a system know who the agent talking to it really is?**

Not who created it. Not which platform it runs on. But *which specific agent*, at this moment, with this behavior, executing these actions.

OAuth delegates this question to a centralized provider. MCP leaves it out of scope by design. Federated systems solve it for humans, not for autonomous machines. The result is a trust architecture that starts to break down once agents begin acting autonomously and at scale.

Agent-DID exists to answer that question.

---

## The Five Principles

### 1. Identity is a first-class citizen of the AI stack

An agent's identity is not a credential bolted on at the end. It is the foundation on which trust between autonomous systems is built. Without cryptographically verifiable identity, there is no real audit trail, no algorithmic accountability, no revocation system that works when something goes wrong.

Agent-DID treats identity as a structural component of the agent — as fundamental as the model that drives it or the prompt that guides it.

### 2. Flexible by design, not by accident

Not every system needs blockchain. Not every system can avoid it. Agent-DID's philosophy rejects the imposition of a single trust-anchoring mechanism:

- An agent in a high-frequency financial environment needs EVM immutability and on-chain cryptographic traceability.
- An agent on a rapid-prototyping platform needs zero friction — no gas fees, no wallets.
- An agent in a regulated environment needs verifiable credentials compatible with compliance frameworks.

The same standard — and the same SDK surface — is designed to work across all three cases. The developer chooses their anchoring mechanism based on their real needs, not on the tool's limitations.

### 3. Meet the developer where they are

A standard that requires learning a new paradigm before writing the first useful line of code has a structural adoption problem. Agent-DID integrates into the frameworks developers already use — LangChain, CrewAI, Semantic Kernel, Microsoft Agent Framework — and gives them verifiable identity without requiring them to abandon their workflow.

The abstraction does the heavy lifting. The developer gets the benefit.

### 4. Open standards over proprietary lock-in

Agent-DID is built on W3C DID Core and the Verifiable Credentials data model. It does not define a new identity format — it extends existing identity standards with the AI-specific metadata agents need: base model hash, system prompt hash, declared capabilities, evolution lifecycle.

This choice is not philosophical by convenience — it is philosophical by conviction. An identity ecosystem for AI agents only has value if it is interoperable. A proprietary identity format creates dependency where interoperability is needed.

### 5. Verifiability without accidental complexity

Identity cryptography is complex. Agent developers should not have to be. The gap between "this is cryptographically correct" and "this is usable in production" is where most decentralized identity projects fail.

Agent-DID closes that gap with two mechanisms:
- **Framework abstractions** that inject identity into the agent's execution chain without extra developer code.
- **Ed25519 by default** — a fast, compact, and widely trusted cryptographic primitive for high-frequency signing environments, with no confusing options or misconfigurable parameters.

---

## The Vision

The Agentic Web — the ecosystem where AI agents act, negotiate, and collaborate at internet scale — needs an identity layer that is to agents what HTTPS was to browsers: invisible when it works, critical when it fails.

Agent-DID aspires to be that layer. Not the only protocol, but the reference standard that proves verifiable identity for agents is possible, affordable, and compatible with the frameworks that already exist.

The project does not compete with ANP, A2A, or MCP. It complements their ecosystem with the piece they all assume but none provide: **the cryptographic proof of who you are when you are an autonomous agent**.

---

## Relationship with the Ecosystem

| Protocol / Standard | Role | Relationship with Agent-DID |
|---|---|---|
| **W3C DID Core** | Decentralized identity format | Foundation — Agent-DID extends it |
| **W3C Verifiable Credentials** | Verifiable credentials | Adopted for compliance certifications |
| **did:wba (ANP)** | Web-based anchoring without blockchain | Supported method — complementary |
| **did:ethr / did:key** | Standard DID methods | Resolvable via `UniversalResolverClient` |
| **MCP (Anthropic)** | Tool integration for LLMs | Agent-DID provides the identity layer MCP does not define |
| **Google A2A** | Agent-to-agent communication | Agent-DID provides verifiable identity for A2A actors |
| **LangChain / CrewAI / SK / MAF** | Orchestration frameworks | Natively integrated — Agent-DID injects into their execution lifecycle |

---

## What Agent-DID Is Not

- **Not an orchestration framework.** It does not replace LangChain or CrewAI. It integrates with them.
- **Not a payment system.** Although it is compatible with ERC-4337 for agent wallets, payment management is out of scope.
- **Not a blockchain mandate.** The EVM registry is an option, not a requirement. `did:wba` and `did:web` are equally valid.
- **Not a centralized platform.** There is no Agent-DID server to connect to. The protocol and SDKs are the primary interface.

---

*This document is the conceptual foundation of the project. All technical documents, design decisions, and roadmap priorities should be derivable from the principles expressed here.*
