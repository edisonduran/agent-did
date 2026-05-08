# Agent-DID — Design Philosophy

**Document type:** Conceptual foundation and vision  
**Version:** 1.1  
**Date:** 2026-05-06

---

## The Core Problem

AI is no longer just a tool that humans use — it is becoming an actor that makes decisions, negotiates, executes code, signs operations, and delegates tasks to other agents. This transition raises a question the industry still lacks a clear answer for:

> **How does a system know who the agent talking to it really is?**

Not who created it. Not which platform it runs on. But *which specific agent*, at this moment, with this behavior, executing these actions.

OAuth delegates this question to a centralized provider. MCP leaves it out of scope by design. Federated systems solve it for humans, not for autonomous machines. The result is a trust architecture that starts to break down once agents begin acting autonomously and at scale.

Agent-DID exists to answer that question. In RFC-001 v0.3, it does so as an application pattern on top of `did:webvh`, not as a standalone DID method.

---

## The Five Principles

### 1. Identity is a first-class citizen of the AI stack

An agent's identity is not a credential bolted on at the end. It is the foundation on which trust between autonomous systems is built. Without cryptographically verifiable identity, there is no real audit trail, no algorithmic accountability, no revocation system that works when something goes wrong.

Agent-DID treats identity as a structural component of the agent — as fundamental as the model that drives it or the prompt that guides it.

That said, identity is the floor, not the whole trust story. Knowing which agent signed a call is not the same as proving that the call was made for the right reason. Agent-DID intentionally focuses on the identity/delegation layer; richer decision provenance belongs in adjacent tracing or signed execution-receipt layers.

### 2. Method-aligned by design, flexible by deployment profile

Not every system needs blockchain. Some do. Agent-DID's updated philosophy is to stop treating every DID method as equally primary and instead choose one canonical starting point: `did:webvh`.

That default matters because it gives the project a single reference story: domain-bound identity, verifiable history, and recursive controller validation up to an organizational root.

Flexibility still exists, but it now lives in the deployment profile:

- Most deployments should use `did:webvh` as the default agent and controller pattern.
- Transport and publication can vary across web-hosted delivery, mirrored content stores, and resolver topologies.
- EVM/on-chain anchoring is not part of the core 1.0 path; it can be reconsidered later only if a concrete deployment need justifies the additional operational surface.

The developer still chooses the operational profile that matches reality, but the project no longer asks every adopter to choose the fundamental DID story from scratch.

### 3. Meet the developer where they are

A standard that requires learning a new paradigm before writing the first useful line of code has a structural adoption problem. Agent-DID integrates into the frameworks developers already use — LangChain, CrewAI, Semantic Kernel, Microsoft Agent Framework — and gives them verifiable identity without requiring them to abandon their workflow.

The abstraction does the heavy lifting. The developer gets the benefit.

### 4. Open standards over proprietary lock-in

Agent-DID is built on W3C DID Core and the Verifiable Credentials data model. It does not define a new DID method or identity format — it extends existing identity standards with the AI-specific metadata agents need: base model hash, system prompt hash, declared capabilities, evolution lifecycle.

This choice is not philosophical by convenience — it is philosophical by conviction. An identity ecosystem for AI agents only has value if it is interoperable. A proprietary identity format creates dependency where interoperability is needed.

### 5. Verifiability without accidental complexity

Identity cryptography is complex. Agent developers should not have to be. The gap between "this is cryptographically correct" and "this is usable in production" is where most decentralized identity projects fail.

Agent-DID closes that gap with two mechanisms:
- **Framework abstractions** that inject identity into the agent's execution chain without extra developer code.
- **Ed25519 by default** — a fast, compact, and widely trusted cryptographic primitive for high-frequency signing environments, with no confusing options or misconfigurable parameters.

That simplicity still has to be precise: a valid key is not automatically valid for every action. Agent-DID verification binds keys to their DID verification relationship, so signing flows use signing-capable purposes such as `assertionMethod` and never accept `keyAgreement` as a shortcut.

It also has to be scoped honestly: Agent-DID can prove who signed and whether that signer was authorized, but it does not claim to prove that the model's internal reasoning was correct. When systems need that stronger audit surface, the right companion is a stable execution receipt or trace attestation, not mandatory raw chain-of-thought capture.

---

## The Vision

The Agentic Web — the ecosystem where AI agents act, negotiate, and collaborate at internet scale — needs an identity layer that is to agents what HTTPS was to browsers: invisible when it works, critical when it fails.

Agent-DID aspires to be that layer. Not the only protocol, but the reference application pattern that proves verifiable identity for agents is possible, affordable, and compatible with the frameworks that already exist.

The project does not compete with ANP, A2A, or MCP. It complements their ecosystem with the piece they all assume but none provide: **the cryptographic proof of who you are when you are an autonomous agent**.

---

## Relationship with the Ecosystem

| Protocol / Standard | Role | Relationship with Agent-DID |
|---|---|---|
| **W3C DID Core** | Decentralized identity format | Foundation — Agent-DID extends it |
| **did:webvh** | Web-native DID with verifiable history | Canonical reference base for Agent-DID agent/controller identity |
| **W3C Verifiable Credentials** | Verifiable credentials | Adopted for compliance certifications |
| **did:web / did:wba / did:ethr / did:key** | Other DID methods and deployment surfaces | Compatibility profiles where they preserve the composition and verification semantics of Agent-DID |
| **MCP (Anthropic)** | Tool integration for LLMs | Agent-DID provides the identity layer MCP does not define |
| **Google A2A** | Agent-to-agent communication | Agent-DID provides verifiable identity for A2A actors |
| **LangChain / CrewAI / SK / MAF** | Orchestration frameworks | Natively integrated — Agent-DID injects into their execution lifecycle |

---

## What Agent-DID Is Not

- **Not an orchestration framework.** It does not replace LangChain or CrewAI. It integrates with them.
- **Not a payment system.** Although it is compatible with ERC-4337 for agent wallets, payment management is out of scope.
- **Not a blockchain mandate.** `did:webvh` is the recommended default. EVM/on-chain work is deferred outside core 1.0, while other DID methods remain compatibility profiles.
- **Not a centralized platform.** There is no Agent-DID server to connect to. The protocol and SDKs are the primary interface.

---

*This document is the conceptual foundation of the project. All technical documents, design decisions, and roadmap priorities should be derivable from the principles expressed here.*
