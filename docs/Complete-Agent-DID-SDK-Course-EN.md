# Complete Course: Agent-DID SDK — From Zero to Expert

**Project Author:** Edison Munoz  
**Instructor:** GitHub Copilot (Claude Opus 4.6)  
**Format:** Interactive modules, one-on-one  
**Level:** Deep — each technology explained from scratch  
**Target Audience:** Mixed (developers, Web3/blockchain community, AI/ML community)  
**Estimated Duration:** ~10 hours (7 modules + exercises)

---

## General Index

| Module | Title | Duration | Key Technologies |
|---|---|---|---|
| **1** | The Problem: Why Do AI Agents Need Identity? | 45 min | Digital identity, autonomous agents, threat model |
| **2** | Decentralized Identity: W3C DID from Scratch | 60 min | W3C DID Core 1.0, JSON-LD, DID Methods, resolution |
| **3** | Applied Cryptography: Ed25519, SHA-256 and Digital Signatures | 75 min | Ed25519, elliptic curves, hashing, HTTP signatures (RFC 9421) |
| **4** | RFC-001: The Agent-DID Specification | 60 min | DID Document, agent metadata, hybrid architecture |
| **5** | SDK Core: `AgentIdentity` — Line by Line | 90 min | TypeScript, creation, signing, verification, lifecycle |
| **6** | Resolvers and Registry: From Local to Production | 90 min | InMemory, HTTP, JSON-RPC, IPFS, cache TTL, failover, EVM |
| **7** | Smart Contract, Security and Community Preparation | 75 min | Solidity, Hardhat, delegated revocation, conformance, presenting |

---

## Module 1 — The Problem: Why Do AI Agents Need Identity?

### Learning Objectives

- Understand the concept of "autonomous agent" in the current AI context
- Identify trust, traceability and security problems without identity
- Understand the vision behind Agent-DID and its positioning in the ecosystem
- Understand what a DID is, a digital signature, non-repudiation, the controller and key protection
- Know how to answer the most common questions from technical and non-technical audiences

---

### 1.1 What Is an AI Agent?

We're not talking about a chatbot that answers questions. We're talking about **software that acts autonomously**: it makes decisions, executes actions and communicates with other systems without direct human intervention.

#### The Autonomy Spectrum

```
Level 0: Chatbot                 → Answers questions, doesn't act
Level 1: Assistant with tools    → Calls APIs when you ask (Copilot, ChatGPT with plugins)
Level 2: Semi-autonomous agent   → Plans steps and executes tasks (LangChain agents)
Level 3: Autonomous agent        → Acts alone: calls APIs, executes code, makes decisions
Level 4: Multi-agent             → Multiple agents coordinate with each other (CrewAI, Microsoft Agent Framework)
Level 5: Economic agent          → Handles money, signs contracts, operates in markets
```

The industry is accelerating from Level 1 to Level 3-4 **right now**. Google launched the A2A (Agent-to-Agent) protocol. OpenAI has agents that browse the web. Anthropic has agents that use complete computers.

**The key point:** these agents are already acting in the real world — calling production APIs, accessing sensitive data, making decisions that affect people and organizations.

---

### 1.2 The Identity Problem: Who Is This Agent?

Imagine this real scenario:

> A technical support agent from your company calls a payments API and authorizes a $5,000 refund.

Questions that **nobody can answer today**:

| Question | Who answers? |
|---|---|
| Who authorized this agent? | Nobody knows for certain |
| What base model does it use? Has it changed? | There's no verifiable record |
| Was it this specific agent or a copy? | Impossible to distinguish |
| Is it compromised? | There's no mechanism to know |
| Who is responsible if something goes wrong? | Ambiguous |

#### The Current World: API Keys and OAuth

Today agents authenticate with **API keys** or **OAuth tokens**. This works for services, but has fundamental problems for autonomous agents:

```
API Key / OAuth Token:
  ✗ Identifies the APPLICATION, not the specific agent
  ✗ Says nothing about the model, version or capabilities
  ✗ If leaked, there's no granular revocation (you revoke everything)
  ✗ No cryptographic traceability of actions
  ✗ Depends on a central provider (Google, Auth0, etc.)
  ✗ Doesn't work cross-organization without prior agreements

DID (Agent-DID):
  ✓ Identifies the SPECIFIC agent with a unique identity
  ✓ Declares model, prompt, version and capabilities (verifiable)
  ✓ Granular and immediate revocation
  ✓ Every action cryptographically signed = non-repudiation
  ✓ Doesn't depend on any central provider
  ✓ Works cross-organization without prior configuration
```

#### Analogy: The Passport

- An **API key** is like a **gym membership card** — it lets you into THAT gym, but doesn't say who you really are.
- A **DID** is like a **passport** — it says who you are, who issued it, when it was issued, and can be verified by anyone in any country without calling the issuer.

Agent-DID creates **passports for AI agents**.

---

### 1.3 Fundamental Concepts: DID, Digital Signature and Non-Repudiation

Before continuing, we need to define three concepts that will appear throughout the ENTIRE course.

#### What Does DID Mean?

**DID = Decentralized Identifier**

Broken down:
- **Identifier:** a unique name that identifies something. Just as an ID number identifies a person, a DID identifies an agent.
- **Decentralized:** that identifier **doesn't depend on a company or government** to exist or to be verified. You create it, you control it.

Format:

```
did:agent:polygon:0x1234...abcd

did          → standard prefix (says "this is a DID")
agent        → the "method" (says "this DID follows Agent-DID rules")
polygon      → the blockchain network where it was anchored
0x1234...    → the agent's unique identifier (a cryptographic hash)
```

**Analogy:** if an ID card is a *centralized* identifier (the government issues and controls it), a DID is as if YOU could create your own ID card, and anyone could verify it without calling the government — using mathematics.

#### What Is a Digital Signature?

It's a **64-byte numerical value** that proves two things:
1. **Who signed** — only the holder of the private key could have generated it
2. **What was signed** — if someone changes the message, the signature no longer matches

The agent has TWO keys (generated when the identity is created):

```
PRIVATE Key (secret):
  → Only the agent has it
  → NEVER shared, NEVER leaves the agent
  → Used to SIGN

PUBLIC Key (shareable):
  → Mathematically derived from the private key
  → Listed in the DID Document, visible to everyone
  → Used to VERIFY signatures

Key property:
  → From the private you can calculate the public
  → From the public you CANNOT calculate the private (irreversible)
```

The complete process:

```
SIGN (done by the agent):
  ┌─────────────────────┐
  │ Original message:    │    ┌──────────────┐
  │ "approve:ticket:123" │───▶│              │
  └─────────────────────┘    │  Algorithm    │    ┌──────────────────┐
                              │  Ed25519      │───▶│ Signature: 64B   │
  ┌─────────────────────┐    │  .sign()      │    │ "9a8b7c6d..."    │
  │ Agent's PRIVATE key  │───▶│              │    └──────────────────┘
  └─────────────────────┘    └──────────────┘
  
  The agent sends: the message + the signature + its DID


VERIFY (done by the receiver):
  ┌─────────────────────┐
  │ Received message:    │    ┌──────────────┐
  │ "approve:ticket:123" │───▶│              │
  └─────────────────────┘    │  Algorithm    │    ┌───────────────┐
                              │  Ed25519      │───▶│ Result:       │
  ┌─────────────────────┐    │  .verify()    │    │ TRUE or FALSE │
  │ Received signature:  │───▶│              │    └───────────────┘
  │ "9a8b7c6d..."        │    │              │
  └─────────────────────┘    │              │
                              │              │
  ┌─────────────────────┐    │              │
  │ PUBLIC Key           │───▶│              │
  │ (from DID Document)  │    └──────────────┘
  └─────────────────────┘

  If TRUE → "This signature was made with the private key corresponding
             to that public key. The message was not altered."
             
  If FALSE → "The signature doesn't match. Either the message was altered,
              or it wasn't signed by that agent."
```

**Who verifies?** Anyone who has the message, the signature and the agent's public key (obtained by resolving its DID). You don't need permission, you don't need an account, you don't need to call anyone. It's **public and independent** verification.

#### What Does "Non-Repudiation" Mean?

**Non-repudiation** = **you cannot deny that you did something**.

If you sign a check with your handwritten signature, you can't later say "I didn't sign that" — your signature binds you. If an agent signs a message with its private key, it can't later say "I didn't send that" — the cryptographic signature binds it mathematically.

**Important:** the signature **travels with the message**. It's not automatically stored in a central location. When the agent sends a signed message, the receiver gets the message, the signature and the DID.

What **IS** stored on blockchain is:
- That the agent **exists** (was registered)
- Its **document reference** (hash)
- Whether it's **revoked** or not
- The **change history** of its identity

Individual signed messages are NOT stored on blockchain. If you wanted to store every action, that would be an application decision (storing signatures in a log, database, etc.). The SDK provides the **ability to sign**, but doesn't impose where signatures are stored.

---

### 1.4 Why Decentralized?

#### The Problem of Centralized Identity

```
Centralized identity (Auth0, Firebase, etc.):
  • One provider controls all identities
  • If the provider goes down → ALL agents lose identity
  • If they change APIs → you have to migrate
  • Cross-organization = commercial agreements + custom integrations
  • The provider can revoke your identity unilaterally
  • Lock-in: your identity is not portable

Decentralized identity (DID):
  • You control your own keys — self-sovereign
  • No single point of failure
  • The standard is open (W3C) — anyone can implement
  • Cross-organization = verify signature with public key (no agreements)
  • Only you (or your delegate) can revoke
  • Portable: take your identity to any platform
```

#### "Doesn't depend on any central provider" — So what is it verified against?

**It's verified against mathematics.** This is the fundamental difference:

```
OAuth (centralized):
  1. Agent sends token to server
  2. Server calls Google/Auth0: "Is this token valid?"
  3. Google/Auth0 responds: "yes" or "no"
  → If Google goes down, you CANNOT verify anything

Agent-DID (decentralized):
  1. Agent signs a message with its PRIVATE key
  2. Receiver obtains the agent's PUBLIC key (from the DID Document)
  3. Receiver executes ONE MATHEMATICAL OPERATION:
     → ed25519.verify(signature, message, publicKey) = true/false
  → Calls nobody. Depends on nobody. Mathematics don't go down.
```

**But where do I get the public key?** From the **DID Document**, obtained through **resolution**:

```
Step 1: I have the agent's DID → did:agent:polygon:0xABC...
Step 2: I query the registry (blockchain) → gives me the document reference
Step 3: I fetch the document (HTTP, IPFS, JSON-RPC) → get the complete JSON-LD
Step 4: From the document I extract the public key (verificationMethod)
Step 5: With that public key I verify the signature → true/false
```

**"But isn't blockchain a central provider?"** — No, because blockchain is a distributed network of thousands of nodes. Anyone can run a node. Data is public and immutable. There's no company that controls it (on public chains like Ethereum, Polygon).

#### "Works cross-organization without prior configuration" — What does that mean?

```
WITH OAUTH (companies wanting to connect their agents):
  1. Company A contacts Company B
  2. They negotiate an integration agreement
  3. Company B creates client credentials for Company A
  4. Company A configures client_id and client_secret
  5. Both agree on scopes and permissions
  6. They configure the authorization server
  7. They test the integration
  → Weeks of work for each pair of organizations

WITH AGENT-DID:
  1. Agent A has its DID: did:agent:polygon:0xAAA...
  2. Agent B has its DID: did:agent:polygon:0xBBB...
  3. Agent A sends a signed message to Agent B
  4. Agent B verifies the signature using A's DID
     → Resolves the DID → gets public key → verifies → done
  → They didn't know each other. No prior agreement. No configuration.
```

It's like a passport: you don't need a bilateral agreement between two countries for an officer to verify your passport. The standard is universal.

#### When IS Centralized Better?

Let's be honest — not everything needs decentralization. If your agents operate only within your company, a centralized system can work. **Agent-DID shines when:**

1. Agents operate **cross-organization** (my agent talks to your agent)
2. **Independent verification** is needed (a third party verifies without calling the issuer)
3. There are **immutable audit** requirements (regulation, compliance)
4. **Provider autonomy** is desired (not depending on Auth0/Google/Microsoft)
5. **Granular revocation** at the individual agent level is needed

---

### 1.5 The Agent-DID Thesis: The Four Fundamental Ideas

#### Idea 1: Persistent Identity

> The agent's DID **doesn't change** even if you change the model, prompt, version or keys.

This is crucial. If an agent starts with GPT-4 and later migrates to Claude, its identity persists. The version history is traced. It's like renewing a passport — you're the same person, just updated.

#### Idea 2: Intellectual Property Protection

> System prompts and models are protected with **cryptographic hashes** — the hash is published, NEVER the content.

You can prove that your agent uses a certain model without revealing which one. You can prove the prompt hasn't changed without publishing the prompt. This is fundamental for companies that invest thousands of hours in fine-tuning and prompt engineering.

#### Idea 3: Immediate Revocation

> If an agent is compromised, it's revoked instantly. All subsequent verification fails.

There's no "grace period" or "stale cache". The revocation state is queried on blockchain — if it's revoked, it's revoked, period.

#### Idea 4: Complete Traceability

> Every change to the agent's identity is recorded: creation, update, key rotation, revocation.

This creates a **cryptographically verifiable audit trail** — these aren't manipulable application logs, they're hashes anchored on blockchain.

---

### 1.6 Identity vs. Authorization: Who Controls What the Agent Does?

This is a fundamental piece. **Agent-DID does NOT control what an agent can do.** Agent-DID answers the question **"WHO is this agent?"**, not **"WHAT can it do?"**

They're two different layers:

```
┌─────────────────────────────────────────────────────────┐
│  LAYER 1: IDENTITY (Agent-DID)                          │
│  Question: "Who are you?"                                │
│  Answer: "I am did:agent:polygon:0xABC, controlled       │
│           by did:ethr:0xEdison, with capabilities         │
│           ['read:kb', 'write:ticket']"                   │
│  → The agent PROVES who it is with its signature         │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 2: AUTHORIZATION (the receiving service)          │
│  Question: "Do I allow you to do this?"                  │
│  Answer: "I verify your identity → Ok, you're SupportBot │
│           → I checked your capabilities → You have       │
│           'write:ticket' → ALLOWED"                      │
│  → The SERVICE decides whether to authorize based on     │
│    the identity                                          │
└─────────────────────────────────────────────────────────┘
```

#### Complete Flow: Who Permits or Denies Actions

```
1. Agent wants to call a payments API
   
2. Agent signs the HTTP request with its private key
   → Attaches headers: Signature, Signature-Agent (its DID), Date, Content-Digest

3. Payments API RECEIVES the request
   
4. Payments API VERIFIES:
   a) Is the signature valid? → Resolves DID, gets public key, verifies
   b) Is the DID active (not revoked)? → Queries registry
   c) Does this agent have permission? → The API decides according to ITS OWN rules:
      - Can check the DID Document's "capabilities"
      - Can have a list of authorized DIDs
      - Can apply any internal policy
   
5. If everything passes → ALLOWS the action
   If anything fails → DENIES the action
```

**Analogy:** when you show your passport in a country:
- The passport **proves who you are** (identity — Agent-DID)
- The immigration officer **decides whether to let you in** (authorization — the receiving service)
- The passport doesn't give you automatic access — it just proves your identity

Agent-DID is the **passport**. The access decision is made by whoever receives the request.

---

### 1.7 The Controller: Who Governs the Agent?

The **controller** is the **person or organization that governs the agent**. It's the "owner" in the sense of responsibility.

```
                    Controller (human/organization)
                    Edison Munoz
                    did:ethr:0xEdison...
                           │
                           │ "I created and govern these agents"
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
          Agent A      Agent B      Agent C
          SupportBot   SalesBot     AnalyticsBot
          did:agent:    did:agent:   did:agent:
          polygon:      polygon:     polygon:
          0xAAA         0xBBB        0xCCC
```

#### What Is the Controller For?

1. **Responsibility:** if the agent does something wrong, the controller is responsible
2. **Traceability:** "Who created this agent?" → the controller
3. **Governance:** conceptually, the controller defines the agent's policies
4. **Audit:** a regulator asks "who operates this agent?" → the controller

#### Controller vs Owner — They're Different Concepts

```
Controller (DID Document field):
  → HIGH-LEVEL identity: "Edison Munoz governs this agent"
  → It's a DID (did:ethr:0xEdison)
  → Conceptual: responsibility and governance
  → Can be verified in the document

Owner (smart contract field):
  → OPERATIONAL identity: "this EVM address can modify the registry"
  → It's an Ethereum address (0xEdison)
  → Practical: who can call contract functions
  → Verified on the blockchain

In most cases, controller and owner are THE SAME PERSON,
but conceptually they're different layers.
```

---

### 1.8 Architecture: What Goes on Blockchain and What Doesn't

This point generates a lot of confusion. The public key **does NOT go directly on blockchain**:

```
┌─────────────────────────────────────────────────────────────┐
│                    ON BLOCKCHAIN (on-chain)                   │
│                                                              │
│  • DID:           "did:agent:polygon:0xABC..."               │
│  • Controller:    "did:ethr:0xEdison..."                     │
│  • DocumentRef:   "hash://sha256/7f8a9b..."  ← a HASH       │
│  • Revoked:       yes / no                                   │
│  • Owner:         0xEdison (EVM address)                     │
│                                                              │
│  ⚠ Does NOT contain: public keys, metadata, capabilities    │
│  ⚠ It's MINIMAL on purpose — to save gas (cost)             │
└─────────────────────────────────────────────────────────────┘
                          │
                          │  documentRef points to ───▶
                          │
┌─────────────────────────────────────────────────────────────┐
│                    OFF BLOCKCHAIN (off-chain)                 │
│                                                              │
│  The complete DID Document (JSON-LD):                        │
│  • Public keys (verificationMethod)          ← HERE they are │
│  • Name, version, capabilities                               │
│  • Model and prompt hashes                                   │
│  • Compliance certifications                                 │
│  • Timestamps                                                │
│                                                              │
│  Stored in: HTTP server, IPFS, or any source                 │
└─────────────────────────────────────────────────────────────┘
```

Resolution always has two steps:
1. **Go to blockchain** → get the `documentRef` (document hash/URI)
2. **Go to the off-chain source** → get the complete document with public keys

#### On Which Blockchain?

The DID contains the network: `did:agent:polygon:0xABC` → the verifier knows to look on Polygon.

```
On Polygon:   did:agent:polygon:0x1234...abcd
On Ethereum:  did:agent:ethereum:0x1234...abcd
On Arbitrum:  did:agent:arbitrum:0x1234...abcd
On Base:      did:agent:base:0x1234...abcd
```

**Why Polygon as default?** Because registering an agent on Ethereum mainnet costs ~$5-20 USD in gas. On Polygon it costs fractions of a cent. For a system with thousands of agents, that matters.

**In practice**, a project would choose ONE main network and all its agents would be registered there.

#### Is Blockchain Necessary?

**No, technically not.** The SDK is designed with abstracted interfaces. The `AgentRegistry` is an interface — anything that implements its 5 methods can be the backend:

```
Possible Registry implementations:
│
├── InMemoryAgentRegistry     → In-memory Map (already implemented — testing)
├── EvmAgentRegistry          → EVM Blockchain (already implemented — production)
├── PostgresAgentRegistry     → SQL Database (possible future)
├── RedisAgentRegistry        → Distributed cache (possible future)
├── HttpApiAgentRegistry      → Centralized REST API (possible future)
```

| Property | With blockchain | Without blockchain (e.g., database) |
|---|---|---|
| Immutability | Records cannot be altered | An admin could modify the DB |
| Decentralization | Thousands of nodes verify | Depends on who operates the DB |
| Transparency | Anyone can audit | Only those with access |
| Availability | The network doesn't go down easily | A server can go down |
| Cost | Each write costs gas | Free writes |
| Speed | Seconds to minutes | Milliseconds |

**Conclusion:** blockchain is not *necessary* for the SDK to work, but it's *recommended* for trust, immutability and real decentralization. Without blockchain, you lose the decentralization guarantees but everything else keeps working.

---

### 1.9 Private Key Protection

If the private key is what gives the agent identity, how is it protected?

**The SDK generates the private key and returns it to the creator.** The SDK **does NOT store** the private key. It only generates and delivers it. After that, **it's the operator's responsibility to protect it**.

#### Protection Levels (from least to most secure)

```
Level 1: Environment variable (minimum acceptable)
  → process.env.AGENT_PRIVATE_KEY
  → Risk: if the server is compromised, it's exposed
  → Acceptable for: development, demos, testing

Level 2: Encrypted file on disk
  → Encrypted with a master key
  → Risk: if they get the master key, it's compromised
  → Acceptable for: basic production

Level 3: Secrets Manager (recommended for production)
  → AWS Secrets Manager, Azure Key Vault, Google Secret Manager
  → The key never exists on disk
  → Acceptable for: serious production

Level 4: HSM (Hardware Security Module) (ideal)
  → The private key lives inside a physical chip
  → NEVER leaves the hardware — not even software can extract it
  → The HSM signs directly: "give me the message, I'll sign inside"
  → Used by: banks, governments, critical infrastructure

Level 5: Secure Enclave / TEE (Trusted Execution Environment)
  → Similar to HSM but in isolated software (Intel SGX, ARM TrustZone)
  → The operating system cannot see the key
  → Emerging for AI agents in the cloud
```

#### Protections Already Built into the Design

```
1. THE PRIVATE KEY IS NEVER TRANSMITTED OVER THE NETWORK
   → Generated locally, used locally
   → Only SIGNATURES are transmitted (which don't reveal the key)
   
2. IMMEDIATE REVOCATION
   → If you suspect the key leaked → revoke the DID
   → All subsequent verification fails
   
3. KEY ROTATION
   → You can generate a new key without changing the DID
   → The previous key stops being valid for authentication
   
4. REVOCATION DELEGATES
   → If your main key is compromised, a delegate can revoke
   → Configured preventively
   
5. Ed25519 IS RESISTANT TO SIDE-CHANNEL ATTACKS
   → The algorithm is designed not to leak information
   → Even if someone measures execution time, they can't derive the key
```

---

### 1.10 Risk Scenarios: What Happens Without Identity?

These aren't hypothetical scenarios — they're real risks that increase with every deployed agent:

#### Scenario 1: Compromised Agent

An attacker modifies the system prompt of a sales agent. The agent starts offering unauthorized 90% discounts.

- **Without Agent-DID:** nobody detects that the prompt changed, because nobody can verify the `systemPromptHash`.
- **With Agent-DID:** the hash doesn't match → detected immediately.

#### Scenario 2: Impersonation

Someone clones your customer service agent and deploys it on a phishing site. Users believe they're talking to your official agent.

- **Without Agent-DID:** there's no way to distinguish original from copy.
- **With Agent-DID:** the legitimate agent signs with its private key. The clone can't sign with that key → verification fails.

#### Scenario 3: Inter-Agent Attack

In a multi-agent system (CrewAI, Microsoft Agent Framework), a malicious agent impersonates the "coordinator agent" and sends false instructions to the others.

- **Without Agent-DID:** agents trust any message that arrives through the channel.
- **With Agent-DID:** every message is signed → agents verify the sender's identity before acting.

#### Scenario 4: Regulatory Audit

A financial regulator asks: "This agent that processed transactions last month — what model was it using? Who controlled it? When was the last update?"

- **Without Agent-DID:** you only have application logs, easily manipulable.
- **With Agent-DID:** the version history is anchored on blockchain with immutable hashes.

---

### 1.11 Positioning in the Ecosystem

```
┌─────────────────────────────────────────────────────────────────┐
│                    STANDARDS WE USE                               │
│                                                                  │
│  W3C DID Core 1.0          → Identity foundation                │
│  W3C Verifiable Credentials → Compliance certifications          │
│  RFC 8032 (Ed25519)         → Digital signature algorithm        │
│  RFC 9421 (HTTP Signatures) → HTTP request authentication        │
│  EVM / Solidity             → On-chain anchor + revocation       │
│  IPFS                       → Decentralized storage              │
│  JSON-LD                    → Interoperable semantic format      │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                    WHAT AGENT-DID ADDS                            │
│                                                                  │
│  agentMetadata              → Name, version, capabilities       │
│  coreModelHash              → Base model hash                    │
│  systemPromptHash           → System prompt hash                 │
│  memberOf                   → Agent fleet reference              │
│  Revocation delegation      → Enterprise governance              │
│  Document history           → Version traceability               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**We're not inventing from scratch.** We take mature and proven standards, and extend them for the specific case of AI agents. This design decision provides credibility and reduces risk.

---

### 1.12 Module 1 Mind Map

```
         AGENT                              RECEIVER (API/Service/Other agent)
         ═════                              ════════════════════════════════════
         
    ┌─ Has PRIVATE key                  
    │  (secret, never leaves)                 
    │                                        
    ├─ Has its DID                          
    │  did:agent:polygon:0xABC               
    │                                        
    │  Its identity is registered:
    │  • On-chain: DID + ref + revoked
    │  • Off-chain: complete document
    │                                        
    │  ACTION: wants to send                 
    │  "approve:ticket:123"                  
    │                                        
    ├─ Signs the message ─────────────────────▶ Receives: message + signature + DID
    │  with PRIVATE key                       │
    │                                         │
    │                                         ├─ Resolves DID → gets PUBLIC key
    │                                         │  (queries blockchain + off-chain document)
    │                                         │
    │                                         ├─ Verifies: Is DID revoked?
    │                                         │  → If yes → REJECT
    │                                         │
    │                                         ├─ Verifies signature with PUBLIC key
    │                                         │  → If FALSE → REJECT
    │                                         │
    │                                         ├─ Decides: Does it have permission?
    │                                         │  (according to its own rules)
    │                                         │  → If not → REJECT
    │                                         │
    │                                         └─ EXECUTES the requested action
    │
    └─ Done. Non-repudiation: cannot deny
       that it signed that message.
```

---

### Module 1 Summary

| Concept | Key Learning |
|---|---|
| AI Agent | Software that acts autonomously — not a chatbot |
| DID | Decentralized Identifier — identifier you create and control |
| Digital signature | 64 bytes that prove who signed and that the message wasn't altered |
| Non-repudiation | You can't deny you signed something — mathematics binds you |
| Controller | The person/organization that governs and is responsible for the agent |
| Controller vs Owner | Controller = governance (DID Document); Owner = operational control (contract) |
| Identity problem | Without verifiable identity: impersonation, compromise, non-traceability |
| API Key vs DID | API key identifies the app; DID identifies the agent with cryptographic signature |
| Decentralization | Self-sovereign, no single point of failure, verification against mathematics |
| Identity vs Authorization | Agent-DID proves WHO the agent is; the service decides WHAT it can do |
| On-chain vs Off-chain | Minimum on blockchain (anchor + revocation); complete document outside |
| Blockchain necessary? | Not technically, but yes for decentralization and immutability guarantees |
| Key protection | SDK generates but doesn't store; operator protects (env → secrets → HSM) |
| Agent-DID thesis | Persistent identity + IP protection + immediate revocation + traceability |

---

### Module 1 Exercises

1. **Draw a scenario** where an AI agent without identity causes a security problem in your context
2. **List 3 concrete differences** between an API key and a DID
3. **Identify 2 real-world use cases** where Agent-DID would solve a problem (outside of those mentioned in this module)
4. **Challenging community question:** someone tells you "Why do I need blockchain if I already have OAuth?" — how do you respond in 30 seconds?
5. **Explain** in your own words what the "controller" is and why it's different from the "owner"
6. **Trace the complete flow:** an agent sends a signed message → a service receives it → verifies it → decides whether to authorize

---

### Talking Points for the Community

For technical audience (developers):
- "AI agents are the new security perimeter — and they don't have a passport"
- "We're not replacing OAuth; we're complementing it with verifiable identity at the agent level"
- "Verification is purely mathematical — ed25519.verify() doesn't call any server"

For Web3/blockchain audience:
- "Agent-DID extends W3C DID Core 1.0 with AI agent-specific metadata"
- "Only the minimum goes on-chain: DID, controller reference, document hash, revocation state"
- "Blockchain-agnostic by design — any EVM chain works, default Polygon for costs"

For AI/ML audience:
- "Agent-DID is to the agent what the SSL certificate is to the server — verifiable identity"
- "SHA-256 hashes protect the model and prompt IP without exposing sensitive data"
- "Persistent identity: if you migrate from GPT-4 to Claude, the agent remains the same"

For general/executive audience:
- "Who sent this message? Who authorized this transaction? Today nobody can answer that with certainty for AI agents. Agent-DID can."
- "It's a digital passport for agents — persistent, verifiable, revocable"

---

### Sample Answers and Evaluation — Module 1

#### Exercise 1: Security scenario — **8/10** ✅

> "A company is buying bonds based on an agent's financial analysis. An attacker intercepts the communication and modifies the response by altering the recommendation, causing the company to lose money. With Agent-DID, the digital signature ensures that any modification to the message would be detected."

**Excellent.** A realistic scenario with a concrete attack (interception + modification) and a clear explanation of how Agent-DID prevents it.

**Minor nuance:** It should be noted that the interception doesn't just "modify the recommendation" — the goal is more precise. With Agent-DID, the attacker can't modify the message because the signature would be invalidated. And the attacker can't re-sign because they don't have the private key.

---

#### Exercise 2: API Key vs DID differences — **8/10** ✅

> 1. API Key identifies the application; DID identifies the specific agent
> 2. API Key has no cryptographic traceability; DID has verifiable signing
> 3. API Key can be revoked at the application level; DID supports granular per-agent revocation

**Three solid, precise differences.** Well-structured and each captures a distinct dimension (scope, cryptography, revocation).

**To strengthen for the community:** Add concrete examples to each point. For example: "If an API key is shared by 50 agents and is leaked, you revoke ALL 50. With DID, you revoke only the compromised one — the other 49 keep operating."

---

#### Exercise 3: Real-world use cases — **8/10** ✅

> 1. Medical agents that access patient records. Each medical agent would have its own verifiable identity, ensuring data privacy and auditability.
> 2. Agents managing IoT devices in smart factories. Each agent could be verified before sending commands to physical machinery.

**Two excellent use cases**, both outside the examples in the module (financial, support). They demonstrate capacity to extrapolate the concept to different sectors.

**To enhance:** The medical case is particularly powerful because medical regulations (HIPAA, GDPR) already demand strong auditability — Agent-DID satisfies that requirement natively.

---

#### Exercise 4: "Why blockchain if I have OAuth?" — **7/10** ✅

> "OAuth identifies the application; Agent-DID identifies the agent. The DID is mathematical, decentralized and persistent. It's a complement, not a replacement."

**Correct and concise.** The "complement, not replacement" framing is key — avoids confrontation.

**To improve:** Lacked a killer example. Enhanced version: "OAuth identifies the application; Agent-DID identifies each specific agent. If your support agent is compromised, with OAuth you revoke the entire system. With Agent-DID, you revoke only that agent. And you can prove which exact agent did each action — with OAuth you can't."

---

#### Exercise 5: Controller vs Owner — **8/10** ✅

> "The controller is the person or entity responsible for the agent — like the CEO. The owner is the operational role with blockchain privileges — like the DevOps engineer. If the engineer leaves, ownership transfers, but the company (controller) stays the same."

**Excellent analogy** with CEO vs DevOps. Captures perfectly the separation between governance responsibility and operational control.

**Technical nuance:** The controller is identified by a DID (`did:ethr:0x...`) while the owner is an Ethereum address (`0x...`). They're not just different concepts — they live in different layers (off-chain vs on-chain).

---

#### Exercise 6: Complete signing/verification flow — **7/10** ✅

The student traced the flow correctly with a diagram showing: Agent signs → sends message + signature + DID → Service resolves DID → gets public key → verifies signature → checks revocation → authorizes/denies.

**Good:** All critical steps present and in the right order.

**Improvement:** The diagram should show the revocation check BEFORE the signature verification (that's the order in the code — cheaper check first). Also lacked the specific step of obtaining the `documentRef` from blockchain before fetching the full document.

---

#### Module 1 Evaluation Summary

| Exercise | Score | Level |
|----------|-------|-------|
| 1. Security scenario | 8/10 | ✅ Good |
| 2. API Key vs DID | 8/10 | ✅ Good |
| 3. Real-world use cases | 8/10 | ✅ Good |
| 4. OAuth response | 7/10 | ✅ Correct, could improve |
| 5. Controller vs Owner | 8/10 | ✅ Good |
| 6. Complete flow | 7/10 | ✅ Correct, could improve |
| **Average** | **7.8/10** | **✅ Approved** |



## Module 2 — Decentralized Identity: W3C DID from Scratch

### Learning Objectives
- Understand what a DID and a DID Document are according to the W3C standard
- Comprehend each component of a DID Document and its function
- Know the existing DID Methods and why `did:agent` is needed
- Understand JSON-LD, DID resolution and Verifiable Credentials
- Know how to explain to the community why a new DID Method was designed

---

### 2.1 The Origin: Where Does W3C DID Come From?

The **W3C** (World Wide Web Consortium) is the organization that creates web standards. The same group that created HTML, CSS and XML. In July 2022, they published the **DID Core 1.0 Recommendation** — the standard for Decentralized Identifiers.

**Why did they create it?** Because identity on the internet always depended on third parties:

| Decade | Identity Model | Problem |
|--------|---------------------|----------|
| 1990s-2000s | Email + password on each site | Hundreds of accounts, no portability |
| 2000s-2010s | "Login with Google/Facebook" (OAuth) | Your identity depends on Google/Facebook |
| 2010s-2020s | X.509 Certificates (SSL/TLS) | Requires centralized Certificate Authorities (CAs) |
| 2020s forward | **DID** | You control your identity, without intermediaries |

The W3C saw that identity always had a central point of failure: if Google closes your account, you lose access to everything. If a CA is compromised, millions of certificates are in doubt.

The question was: **Can we create an identifier that nobody can take away from you, that you control, and that anyone can verify?**

The answer was the DID standard.

**Key fact for the community**: Our SDK implements W3C DID Core 1.0 — it's not a proprietary invention, it's a standard backed by the same organization that created the web.

---

### 2.2 Anatomy of a DID: Breaking Down the String

A DID is a text string with a specific structure:

```
did:agent:polygon:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18
│   │     │       │
│   │     │       └── 4. The specific identifier (Ethereum address)
│   │     └────────── 3. The sub-network (Polygon, an EVM-compatible blockchain)
│   └──────────────── 2. The method (agent = our DID Method)
└──────────────────── 1. The scheme (always "did:")
```

**Part by part:**

1. **`did:`** — The URI scheme. Just as `https:` indicates "this is a web URL", `did:` indicates "this is a decentralized identifier". It's constant, always starts this way.

2. **`agent`** — The DID Method. Defines *how* this DID is created, resolved and managed. Each method has its own rules. `agent` is ours.

3. **`polygon`** — The sub-network. Indicates on which blockchain the identity is anchored. Could be `mainnet`, `polygon`, `arbitrum`, etc.

4. **`0x742d35Cc...`** — The method-specific identifier. In our case, it's an Ethereum wallet address derived from the agent's keys.

**Comparison with other DIDs:**

```
did:web:example.com:agents:trading-bot
    │   └── web domain (depends on DNS)
    └── web method

did:ethr:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18
    │    └── Ethereum address
    └── Ethereum method

did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
    │   └── encoded public key
    └── ephemeral method (no blockchain)

did:agent:polygon:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18
    │      │       └── derived address
    │      └── sub-network
    └── our method
```

**Fundamental property:** A DID is **persistent** and **resolvable**. Unlike a URL that can stop working if the server goes down, a DID anchored on blockchain exists as long as the blockchain exists.

---

### 2.3 What Is a DID Document? The Agent's "Digital Passport"

If the DID is the **passport number**, the DID Document is the **complete passport** with all the information.

A DID Document is a JSON-LD object that contains everything you need to interact cryptographically with the subject identified by the DID. Here is the **actual DID Document** generated by our SDK:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://agent-did.org/v1"
  ],
  "id": "did:agent:polygon:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
  "controller": "did:web:acme-corp.com",
  "verificationMethod": [
    {
      "id": "did:agent:polygon:0x742d35Cc...#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:agent:polygon:0x742d35Cc...",
      "publicKeyMultibase": "z3a5b7c9d..."
    }
  ],
  "authentication": [
    "did:agent:polygon:0x742d35Cc...#key-1"
  ],
  "agentMetadata": {
    "name": "TradingBot-v3",
    "version": "3.2.1",
    "modelHash": "hash://sha256/a1b2c3d4...",
    "promptHash": "hash://sha256/e5f6g7h8...",
    "capabilities": ["trading", "analysis", "reporting"],
    "framework": "langchain",
    "provider": "acme-corp.com"
  },
  "complianceCertifications": [
    {
      "standard": "SOC2",
      "auditor": "did:web:auditor-firm.com",
      "validUntil": "2027-01-01T00:00:00Z"
    }
  ],
  "created": "2026-03-02T10:30:00Z",
  "updated": "2026-03-02T10:30:00Z"
}
```

Let's break down **each field**:

| Field | What it is | Analogy |
|-------|--------|----------|
| `@context` | JSON-LD vocabularies that define the meaning of the fields | The document's "language" |
| `id` | The agent's DID (immutable) | Passport number |
| `controller` | Who has authority over this identity | The country that issued the passport |
| `verificationMethod` | List of public keys for verifying signatures | Photo and biometric data |
| `authentication` | Which verification methods are valid for authentication | Security seals |
| `agentMetadata` | AI agent-specific information (our extension) | Profession, skills |
| `complianceCertifications` | Compliance certifications | Visas and permits |
| `created` / `updated` | Creation and last modification timestamps | Issue date and renewal |

---

### 2.4 JSON-LD — The Shared Meaning System

**JSON-LD = JSON for Linking Data**.

**Why not plain JSON?** Imagine two companies create AI agents. Both use JSON:

```json
// Company A
{ "name": "TradingBot", "key": "abc123..." }

// Company B
{ "nombre": "BotDeTrading", "clave": "abc123..." }
```

`name` and `nombre` mean the same thing, but a machine doesn't know that. JSON-LD solves this with **contexts**:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "verificationMethod": [...]
}
```

The `@context` is like a shared dictionary. When you see `"@context": "https://www.w3.org/ns/did/v1"`, it means: "The fields in this JSON are defined according to the official W3C DID version 1 vocabulary".

**International restaurant analogy:**

| Without JSON-LD | With JSON-LD |
|-------------|-------------|
| Each restaurant invents names for its dishes | Everyone uses a menu with a universal code |
| "Pad Thai" vs "Thai stir-fried noodles" | Code: `THAI-001` = Pad Thai in every restaurant |
| Confusion and ambiguity | Clarity and compatibility |

**In our SDK we use two contexts:**

```json
"@context": [
  "https://www.w3.org/ns/did/v1",        // Standard W3C vocabulary
  "https://agent-did.org/v1"              // Our extensions for AI agents
]
```

The first defines standard fields (`id`, `controller`, `verificationMethod`). The second defines our extensions (`agentMetadata`, `complianceCertifications`).

---

### 2.5 `verificationMethod` and `authentication` — The Keys to the Kingdom

This is the cryptographic heart of the DID Document.

#### `verificationMethod` — The List of Public Keys

```json
"verificationMethod": [
  {
    "id": "did:agent:polygon:0x742d35Cc...#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:agent:polygon:0x742d35Cc...",
    "publicKeyMultibase": "z3a5b7c9d..."
  }
]
```

Breakdown:

- **`id`**: Unique identifier for this key. Note the format `<DID>#key-1` — the `#` separates the DID from the fragment that identifies the specific key.

- **`type`**: `Ed25519VerificationKey2020` — indicates it's an Ed25519 key. This tells the verifier which algorithm to use to validate signatures. Ed25519 was chosen because:
  - 64-byte signatures (compact)
  - Fast verification (important when an agent verifies thousands of signatures)
  - Resistant to side-channel attacks
  - Deterministic (same input always produces the same signature)

- **`controller`**: Who controls this key (normally the DID itself).

- **`publicKeyMultibase`**: The public key encoded in Multibase format conforming to the W3C standard. The SDK uses the `z` prefix (Base58btc) with the Ed25519 multicodec (`0xed01`), producing values like `z6Mk...`. This is fully compatible with the DID Core specification and the `did:key` format.

#### `authentication` — Access Control

```json
"authentication": [
  "did:agent:polygon:0x742d35Cc...#key-1"
]
```

This says: "Key `#key-1` is valid for authentication". A DID Document could have multiple keys with different purposes:

```json
"verificationMethod": [
  { "id": "...#key-1", ... },    // Key for signing messages
  { "id": "...#key-2", ... },    // Key for signing transactions
  { "id": "...#recovery", ... }  // Recovery key
],
"authentication": ["...#key-1"],       // Only key-1 can authenticate
"assertionMethod": ["...#key-2"],       // Only key-2 can make assertions
"capabilityDelegation": ["...#recovery"] // Only recovery can delegate
```

**House keys analogy:**

| Key | Purpose | DID Equivalent |
|-------|-----------|-----------------|
| Main key | Open the front door | `authentication` |
| Mailbox key | Only access mail | `assertionMethod` |
| Building master key | Emergency access | `capabilityDelegation` |

---

### 2.6 DID Resolution — How Is the DID Document Obtained?

**Resolution** is the process of transforming a DID into its DID Document. It's analogous to how DNS transforms a domain into an IP:

```
DNS:     "google.com"  → DNS Resolver → 142.250.80.46
DID:     "did:agent:polygon:0x742d..." → DID Resolver → { DID Document JSON }
```

But with a crucial difference: **there is no central DNS server**. Each DID Method defines its own resolution mechanism.

#### Resolution flow diagram:

```
Someone wants to verify the agent
          │
          ▼
  ┌───────────────┐
  │ Has the DID:   │
  │ did:agent:...  │
  └───────┬───────┘
          │
          ▼
  ┌───────────────────┐
  │ What method is it? │
  │ → "agent"          │
  └───────┬───────────┘
          │
          ▼
  ┌─────────────────────────┐
  │ Resolve did:agent        │
  │ 1. Go to the blockchain  │
  │ 2. Look up the record    │
  │ 3. Get documentRef       │
  │ 4. Fetch the document    │
  └───────┬─────────────────┘
          │
          ▼
  ┌────────────────────┐
  │ DID Document JSON  │
  │ (with keys, meta)  │
  └────────────────────┘
```

#### The 4 Types of Resolution in Our SDK:

| Type | Source | Speed | Decentralization | Use |
|------|--------|-----------|-------------------|-----|
| **InMemory** | `Map` in memory | Lightning fast | None | Tests, development |
| **HTTP** | Web server (URL) | Fast | Partial (depends on server) | Simple production |
| **JSON-RPC** | RPC 2.0 service | Fast | Partial | Microservices |
| **Blockchain + IPFS** | On-chain ref + IPFS | Moderate | Full | Complete production |

The SDK's `UniversalResolverClient` combines all sources with automatic failover: if the primary source fails, it tries the next one.

---

### 2.7 Existing DID Methods — The Complete Landscape

There are more than 100 DID Methods registered at W3C. The most relevant:

#### `did:web` — The Pragmatic One

```
did:web:example.com:agents:trading-bot
```

- **How it works**: The DID Document is hosted at a URL derived from the DID
  - `did:web:example.com` → `https://example.com/.well-known/did.json`
- **Advantage**: Easy to implement (you only need a web server)
- **Disadvantage**: If the domain expires or the server goes down, the identity disappears. Depends on DNS (centralized).

#### `did:ethr` — The Decentralized Ethereum One

```
did:ethr:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18
```

- **How it works**: Uses the ERC-1056 registry on Ethereum
- **Advantage**: Fully decentralized, immutable
- **Disadvantage**: Has no concept of AI agent metadata. Gas fees on Ethereum mainnet are expensive.

#### `did:key` — The Ephemeral One

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

- **How it works**: The DID Document can be mathematically reconstructed from the public key encoded in the identifier itself.
- **Advantage**: Requires no network or blockchain. Instant resolution. Perfect for testing.
- **Disadvantage**: Cannot be revoked. Cannot rotate keys. No metadata.

#### `did:ion` — Microsoft's

```
did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w
```

- **How it works**: Uses the Sidetree network on Bitcoin
- **Advantage**: Backed by Microsoft, scalable
- **Disadvantage**: High complexity, slow resolution, no AI extensions

#### `did:agent` — Ours

```
did:agent:polygon:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18
```

- **How it works**: Minimal on-chain registration (smart contract) + complete off-chain document
- **Advantages**:
  - AI agent metadata (model, prompt, capabilities, framework)
  - Intellectual property protection hashes
  - Fleets (agent groupings)
  - Compliance certifications
  - Low gas fees (Polygon)
  - Flexible resolution (HTTP, IPFS, JSON-RPC)

---

### 2.8 Why Create a New DID Method? — `did:agent`

This is probably **the most important question** you'll be asked in the community. Here's the complete answer.

#### What Existing Methods DON'T Have:

| AI Agent Need | `did:web` | `did:ethr` | `did:key` | `did:agent` |
|-------------------------|-----------|------------|-----------|-------------|
| Persistent identity | Depends on DNS | Yes | Ephemeral | Yes |
| Model/prompt metadata | No | No | No | Yes |
| IP protection (hashes) | No | No | No | Yes |
| Fleet management | No | No | No | Yes |
| Compliance certifications | No | No | No | Yes |
| On-chain revocation | No | Yes | No | Yes |
| Low gas fees | N/A | No (ETH expensive) | N/A | Yes (Polygon) |
| Flexible resolution | HTTP only | Blockchain only | Derivation only | HTTP + IPFS + RPC |

#### Example with Real SDK Code — Creating an Agent:

```typescript
import { AgentIdentity } from '@agent-did/sdk';

const agent = await AgentIdentity.create({
  name: "TradingBot-v3",
  version: "3.2.1",
  model: "gpt-4-turbo",
  capabilities: ["trading", "analysis"],
  framework: "langchain",
  provider: "acme-corp.com",
  controller: "did:web:acme-corp.com"
});

// The generated DID:
console.log(agent.did);
// → "did:agent:polygon:0x742d35Cc..."
```

Try doing this with `did:ethr` or `did:web` — there's no field for `model`, `capabilities`, or `framework`. You'd have to invent your own structure, losing interoperability.

---

### 2.9 Verifiable Credentials — The Connection

DIDs don't live alone — they're the foundation of a larger ecosystem. **Verifiable Credentials** (VCs) are digitally verifiable certificates:

```
┌─────────────────────────────────────────────┐
│            Verifiable Credential             │
│                                              │
│  Issuer:   did:web:auditor-firm.com         │
│  Subject:  did:agent:polygon:0x742d...      │
│  Claim:    "This agent complies with SOC2"  │
│  Signature: <auditor's digital signature>   │
│  Valid:    until 2027-01-01                  │
│                                              │
└─────────────────────────────────────────────┘
```

**The complete flow:**

1. An agent has its DID → `did:agent:polygon:0x742d...`
2. An auditor verifies the agent complies with SOC2
3. The auditor issues a VC signed with their own DID → `did:web:auditor-firm.com`
4. The VC can be included in the agent's DID Document (`complianceCertifications` field)
5. Anyone can verify:
   - That the auditor signed the certification (verifying the signature with the auditor's public key)
   - That the certification hasn't been modified
   - That it's still valid

**Analogy:** A DID is your identity card. A VC is a university degree that someone (the university) issued to you and that's signed with their official seal.

In our SDK, the `complianceCertifications` field of the DID Document is where these credentials are stored.

---

### 2.10 Module 2 Frequently Asked Questions

#### Q: What is an EVM?

**EVM = Ethereum Virtual Machine**.

It's the "global computer" that executes code on Ethereum-compatible blockchains.

| Concept | Analogy |
|----------|----------|
| Your computer | Executes programs (.exe, .app) |
| EVM | Executes **smart contracts** (programs in Solidity) |

When we say a blockchain is **"EVM-compatible"**, it means it can execute the same Ethereum code. This includes: Ethereum (the original, expensive in gas fees), **Polygon** (which our SDK uses, fast and cheap), Arbitrum, Optimism, BNB Chain, Avalanche, etc.

The advantage: our `AgentRegistry.sol` works on **any** EVM-compatible blockchain without changing a single line of code. That's why the SDK class is called `EvmAgentRegistry` — it doesn't say "EthereumAgentRegistry" or "PolygonAgentRegistry", because it works on all of them.

```
Your Solidity code → Compiled to bytecode → The EVM executes it
                                               (on Ethereum, Polygon, or any EVM network)
```

#### Q: What does "protects IP" (intellectual property) mean?

**IP = Intellectual Property**, not IP address.

Imagine you train an AI model for 6 months. You don't want to publish the complete model, but you do want to **prove** that your agent uses that specific model. The hash solves this:

```
Your model (secret)  →  SHA-256  →  "a1b2c3d4..."  (public in the DID Document)
```

- The hash **doesn't reveal** the model's content (it's irreversible)
- But it **does prove** which model the agent uses
- If someone says "I trained that model first", you can prove with the blockchain timestamp that you published the hash first

It's like registering a work with a notary: you don't publish the entire novel, but there's a record that it existed on that date.

#### Q: How does the SDK encode publicKeyMultibase?

The SDK follows the **Multibase** + **Multicodec** standard per W3C DID Core:

1. Take the 32-byte Ed25519 public key
2. Prepend the Ed25519 multicodec prefix: `0xed01` (2 bytes)
3. Encode in Base58btc
4. Prepend the multibase character `z`

The result is a value like `z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`, which is interoperable with `did:key`, Veramo, SpruceID and other DID implementations.

```typescript
// Internally the SDK uses:
import { encodePublicKeyMultibase, decodePublicKeyMultibase } from '@agentdid/sdk';

const multibase = encodePublicKeyMultibase(publicKeyBytes);  // → "z6Mk..."
const publicKey = decodePublicKeyMultibase(multibase);        // → Uint8Array(32)
```

**Historical note:** Versions prior to v0.2.0 used `z` + hexadecimal without multicodec. This was corrected in Sprint 1 to fully comply with the standard.

#### Q: Is Cloudflare an IPFS?

Not exactly. **IPFS** (InterPlanetary File System) is a decentralized **protocol/network** where files are identified by their **content** (hash), not by their location. **Cloudflare** is a web infrastructure company that offers an **IPFS gateway** — an entry point:

```
IPFS Network (decentralized, many nodes)
     ↑
     │  IPFS protocol
     │
Cloudflare Gateway (bridge)  ←── Your browser (normal HTTP)
     │
     └── https://cloudflare-ipfs.com/ipfs/QmHash...
```

| Concept | Analogy |
|----------|----------|
| IPFS | The international postal system |
| IPFS Node | A post office |
| Cloudflare Gateway | A forwarding service that translates your regular letter to the postal system |

You can access IPFS **directly** (by installing a node) or **through a gateway** like Cloudflare that translates HTTP → IPFS. In our SDK, the `HttpDIDDocumentSource` can resolve IPFS URLs through gateways without the user needing a local node.

#### Q: What is an ABI?

**ABI = Application Binary Interface**.

It's the **instruction manual** for communicating with a smart contract. When you compile a Solidity contract:

```
AgentRegistry.sol  →  Solidity Compiler  →  1. Bytecode (the executable program)
                                               2. ABI (the function manual)
```

The ABI is a JSON file that describes what functions the contract has, what parameters each one receives, what it returns and what events it emits.

Real example from our `AgentRegistry`:

```json
{
  "name": "registerAgent",
  "type": "function",
  "inputs": [
    { "name": "agentDid", "type": "string" },
    { "name": "documentRef", "type": "string" }
  ],
  "outputs": []
}
```

**What's it for?** When from TypeScript you want to call the smart contract, ethers.js needs the ABI:

```typescript
// Without ABI: ethers doesn't know what functions exist
const contract = new Contract(address, ???);

// With ABI: ethers knows exactly how to call each function
const contract = new Contract(address, ABI);
contract.registerAgent("did:agent:abc", "https://..."); // ✅
```

In our SDK, the ABI is in `sdk/examples/abi/` and it's what allows `EthersAgentRegistryContractClient` to communicate with the contract deployed on blockchain.

**Analogy:** If the smart contract is a restaurant, the ABI is the **menu** — it tells you what you can order and what ingredients each dish needs.

---

### Module 2 Exercises

**Exercise 1**: Given the following DID, identify and explain each component:
```
did:agent:polygon:0xABCDEF1234567890ABCDEF1234567890ABCDEF12
```
Separate: scheme, method, sub-network, specific identifier. Why is Polygon used?

**Exercise 2**: Compare `did:ethr`, `did:web` and `did:agent` in a table. For each one indicate:
- Does it require blockchain?
- Does it support AI agent metadata?
- Can it be revoked?
- What happens if the server/domain disappears?

**Exercise 3**: Explain the DID resolution flow in your own words. Starting from a DID string, what steps occur until you obtain the DID Document?

**Exercise 4**: A skeptic tells you: "Why create another DID Method if there are already more than 100? This is reinventing the wheel." Write a 3-4 sentence response that convinces them.

**Exercise 5**: Explain in your own words:
- What is JSON-LD and why is it used instead of plain JSON?
- What's the difference between `verificationMethod` and `authentication`?

**Exercise 6**: What is an EVM, what is an ABI, and how are both related in the context of our SDK?

---

### Talking Points for the Community

- "We didn't invent a DID Method on a whim — no existing method has the extensions that AI agents need: model metadata, IP protection hashes, compliance certifications"
- "We're 100% compatible with W3C DID Core 1.0. We extend the standard with our own `@context`, we don't replace it"
- "JSON-LD guarantees semantic interoperability — any universal resolver can read our DID Documents"
- "The hybrid on-chain/off-chain design keeps costs low: only the essentials go on blockchain, the complete document lives on HTTP or IPFS"
- "Our contract is EVM-compatible: it works on Ethereum, Polygon, Arbitrum or any EVM chain without changes"
- "The smart contract ABI is public — any implementation in any language can interact with our registry"

---

### Sample Answers and Evaluation — Module 2

#### Exercise 1: Field classification — **8/10** ✅

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",   // → W3C standard ✅
    "https://agent-did.org/v1"         // → Agent-DID extension ✅
  ],
  "id": "did:agent:polygon:0x1234...abcd",              // → W3C standard ✅
  "controller": "did:ethr:0xCreatorWalletAddress",       // → W3C standard ✅
  "created": "2026-02-22T14:00:00Z",                    // → W3C standard ✅
  "updated": "2026-02-22T14:00:00Z",                    // → W3C standard ✅

  "agentMetadata": {                                     // → Agent-DID extension ✅
    "name": "SupportBot-X",
    "description": "Level 1 technical support agent",
    "version": "1.0.0",
    "coreModelHash": "hash://sha256/...",
    "systemPromptHash": "hash://sha256/...",
    "capabilities": ["read:kb", "write:ticket"],
    "memberOf": "did:fleet:0xCorporateSupportFleet"
  },

  "complianceCertifications": [                          // → Agent-DID extension ⚠️
    {
      "type": "VerifiableCredential",
      "issuer": "did:auditor:0xTrustCorp",
      "credentialSubject": "SOC2-AI-Compliance",
      "proofHash": "ipfs://Qm..."
    }
  ],

  "verificationMethod": [                               // → W3C standard ✅
    {
      "id": "did:agent:polygon:0x1234...abcd#key-1",    // → W3C standard ✅
      "type": "Ed25519VerificationKey2020",              // → W3C standard ✅
      "controller": "did:ethr:0xCreatorWalletAddress",   // → W3C standard ✅
      "publicKeyMultibase": "z6Mkf5rGR9o8...",           // → W3C standard ✅
      "blockchainAccountId": "eip155:1:0x..."            // → W3C ecosystem ⚠️
    }
  ],

  "authentication": [                                   // → W3C standard ✅
    "did:agent:polygon:0x1234...abcd#key-1"              // → W3C standard ✅
  ]
}
```

**Points for improvement:**
- `complianceCertifications`: Verifiable Credentials are a separate W3C standard, but the **field** `complianceCertifications` within the DID Document is 100% our extension. W3C DID Core doesn't define that field. What's W3C is the *concept* of VC, not its location within the document.
- `blockchainAccountId`: It's not in DID Core 1.0 directly, but in the *DID Specification Registries* (companion W3C document). More precise to say "W3C ecosystem" than "W3C core".

---

#### Exercise 2: `did:agent` differentiators — **8/10** ✅

Student's answer:
1. It's decentralized, doesn't depend on a single entity or domain
2. Contains metadata that we can only identify or give semantics related to AI agents
3. Compliance certifications
4. Declared capabilities
5. Hash of the model and prompt that protects IP
6. Delegated revocation

**Evaluation:** 3 were requested, 6 were listed (more is better). Points 2-6 are correct and precise.

**Point to improve:** Point 1 ("It's decentralized") only applies vs `did:web`. `did:ethr` is also decentralized and doesn't depend on domains. Before the Web3 community, if you say "did:agent is decentralized and did:ethr isn't", they'll correct you immediately. Better formulation: *"did:agent combines the decentralization of did:ethr with the richness of metadata that no other method offers."*

---

#### Exercise 3: Explain `@context` in JSON-LD — **7/10** ✅

> "It's used to give semantic context to each field in the JSON, avoids ambiguities"

**Correct but incomplete.** Captures the essence (semantic context + avoid ambiguity). What was missing:

- **Interoperability**: `@context` allows different implementations, in different languages, from different companies, to interpret the fields exactly the same way. It's not just avoiding ambiguity — it's guaranteeing that a TypeScript SDK and a Python implementation read the same field with the same meaning.
- **Linked vocabularies**: Each URL in `@context` points to a vocabulary that formally defines each field (name, type, relationships). It's a public contract of meaning.

**Ideal community answer (30 sec):**
> "`@context` is the shared dictionary that guarantees that when I say `verificationMethod`, any implementation in the world interprets exactly the same thing. Without it, everyone would invent their own field names and we'd lose interoperability."

---

#### Exercise 4: DID resolution flow diagram — **9/10** 🌟

The diagram correctly shows:
1. Agent sends its DID to the App
2. App gets the off-chain document address from the On-chain Document
3. Reads the off-chain document via IPFS, HTTP or JSON-RPC
4. Validates with message, hash, public key
5. Grants permissions

**Excellent:** Demonstrates clear understanding of the hybrid on-chain/off-chain architecture. The flow is precise.

**Subtle point to refine:** Step 5 "Grants permissions" is a logical consequence, but technically it's not part of **resolution**. Resolution ends when you get the DID Document (steps 3-4). What follows is **authorization** — a separate process that uses verified identity as input. Remember from Module 1: identity ≠ authorization.

---

#### Exercise 5: "Why don't you use `did:ethr`?" in 30 seconds — **7/10** ✅

> "Because we need to store extended information focused on cryptographic identification for AI agents that did:ethr doesn't provide"

**Correct in content, improvable in impact.** Sounds technically valid but doesn't "hook" the audience.

**Improved version:**
> "did:ethr gives you a decentralized identity with a public key — and that's where it ends. We need to know what model the agent uses, what capabilities it has, who its controller is, and protect the intellectual property of the prompt with verifiable hashes. None of that exists in did:ethr, that's why we created did:agent as an extension of the W3C standard."

**Technique for 30-second answers:** Structure "Yes, but + concrete example":
- "Yes, did:ethr is excellent for general identity..."
- "...but when an AI agent needs to declare its model, capabilities and compliance certifications, did:ethr has nowhere to put that information."

---

#### Exercise 6: Key rotation and `authentication` — **9/10** 🌟

> "No. Only the keys that are enabled for authentication are verified, only those are used for cryptographic verification"

**Excellent.** Fundamental concept well understood.

**Additional technical nuance:** Signatures made with the old key are still *mathematically valid* — the cryptography doesn't change. What changes is that the verifier doesn't have access to the old key because the current DID Document only shows the new one. That's why `getDocumentHistory()` exists in the SDK — it allows viewing previous versions to verify historical signatures. Analogy: if you change your house lock, the old key still "works" physically, but it no longer opens that door.

---

#### Module 2 Evaluation Summary

| Exercise | Score | Level |
|-----------|-----------|-------|
| 1. Field classification | 8/10 | ✅ Solid |
| 2. did:agent differentiators | 8/10 | ✅ Solid |
| 3. Explain @context | 7/10 | ✅ Correct, lacked depth |
| 4. Resolution diagram | 9/10 | 🌟 Excellent |
| 5. "Why not did:ethr?" response | 7/10 | ✅ Improvable in impact |
| 6. Key rotation | 9/10 | 🌟 Excellent |
| **Average** | **8.0/10** | **✅ Approved** |

**Progress vs Module 1**: Improvement from 7.8 to 8.0. Strongest point: architectural comprehension (excellent diagram). Main area for improvement: persuasive communication — the technical knowledge is there, but community responses need concrete examples that "hook" the audience.


## Module 3 — Applied Cryptography: Ed25519, SHA-256 and Digital Signatures

### Learning Objectives
- Understand public key (asymmetric) cryptography and why it's fundamental
- Know Ed25519: properties, advantages, operation
- Understand hashing (SHA-256) and its role in metadata protection
- Comprehend HTTP signatures (RFC 9421) and their application in Bot Auth
- Know how to explain to the community each cryptographic decision in the SDK

---

### 3.1 What Is Cryptography and Why Does It Matter Here?

**Cryptography** comes from Greek: *kryptós* (hidden) + *graphein* (to write). Literally, "hidden writing".

But in our SDK, cryptography is not used to **hide** messages (that's encryption). It's used for two specific things:

| Function | What does it do? | Where is it used in the SDK? |
|---------|-------------|--------------------------|
| **Digital signatures** | Prove that a message came from a specific agent | `signMessage()`, `signHttpRequest()` |
| **Hashing** | Generate a unique "fingerprint" of data | `hashPayload()`, `generateAgentMetadataHash()` |

When the agent signs a message, it's not encrypting anything (the message remains readable). What it's doing is **stamping its seal** — a seal that only it can create, but that anyone can verify.

---

### 3.2 Symmetric vs Asymmetric Cryptography — The Foundation of Everything

There are two families of cryptography. Understanding the difference is crucial:

#### Symmetric Cryptography (ONE key)

```
                    same key
Alice ──── [encrypt] ──────────── [decrypt] ──── Bob
                    "secret123"
```

- One single key for encrypting and decrypting
- Classic example: password on a ZIP file
- **Problem**: How do you pass the key to Bob without someone intercepting it?

#### Asymmetric Cryptography (TWO keys) — The One We Use

```
              private key              public key
              (only Alice)               (everyone)
                   │                          │
Alice ──── [sign with private] ──────── [verify with public] ──── Bob
```

- **Private key**: secret, only the agent has it. 32 bytes in Ed25519.
- **Public key**: shared with everyone (it's in the DID Document). 32 bytes in Ed25519.
- **Magic property**: what you sign with the private key can only be verified with the corresponding public key. It is **mathematically impossible** to derive the private from the public.

**Lock analogy:**
- The **public key** is an open padlock that you give to everyone
- The **private key** is the key that only you have
- Anyone can close the padlock (encrypt/verify), but only you can open it (decrypt/sign)

**Why asymmetric for the SDK?** Because the agent needs to sign messages without sharing any secret with the verifier. The verifier obtains the public key from the DID Document (which is public) and that's all they need to verify any signature.

---

### 3.3 Ed25519 — The Algorithm We Chose (and Why)

**Ed25519** is a digital signature algorithm based on the **elliptic curve Curve25519**, defined in standard **RFC 8032 (EdDSA)**. The name comes from:
- **Ed** = Edwards (the curve type: Edwards curve)
- **25519** = the prime number that defines the curve: $2^{255} - 19$

#### What Is an Elliptic Curve? (Simplified Version)

Without going into deep mathematics: an elliptic curve is a mathematical equation that draws a curve with a special property — you can perform point "multiplication" operations that are easy to calculate in one direction but **practically impossible** to reverse.

```
Private key (secret number)  ──[multiply by generator point]──>  Public key (point on the curve)

                                    EASY →
                              ← IMPOSSIBLE (inversion)
```

This is what guarantees security: anyone can verify that a signature is valid using the public key, but nobody can derive the private key from the public one.

#### Ed25519 Properties

| Property | Value | Why it matters |
|-----------|-------|-----------------|
| Private key size | 32 bytes (256 bits) | Compact, easy to store |
| Public key size | 32 bytes (256 bits) | Fits easily in JSON |
| Signature size | 64 bytes (512 bits) | Compact for sending over HTTP |
| Signing speed | ~100,000/sec | An agent can sign thousands of requests/sec |
| Verification speed | ~70,000/sec | Servers can verify quickly |
| Deterministic | Yes | Same input → same signature (always) |
| Needs extra entropy | No | Doesn't depend on a random number generator |

#### Why Ed25519 and Not Other Algorithms?

| Algorithm | Problem | Ed25519 solves |
|-----------|----------|------------------|
| **RSA** | Keys of 2048+ bits (256 bytes), slow (~1,000 signatures/sec) | 32-byte keys, 100x faster |
| **ECDSA (secp256k1)** | Needs random entropy on each signature. If the RNG (random number generator) fails or is predictable, the private key gets exposed (real case: PlayStation 3 hack, 2010) | Deterministic: no extra RNG needed, eliminates that entire class of vulnerabilities |
| **DSA** | Obsolete, large keys, slow | Modern, compact, fast |

**Important fact for the Web3 community:** Ethereum uses ECDSA with curve secp256k1 (not Ed25519). Our SDK uses Ed25519 for the agent's identity signatures, but uses Ethereum/EVM addresses for the smart contract. They're two cryptographic systems coexisting, each in its own domain.

#### What Does "Deterministic" Mean?

In ECDSA, every time you sign the same message, the signature is **different** (because it uses an internal random number called `k`). If `k` repeats, an attacker can calculate your private key. This happened in real life:

> **PlayStation 3 Hack (2010):** Sony used the same `k` to sign multiple updates. Hackers extracted Sony's private key and could sign pirated software as if it were official.

In Ed25519, the signature is **deterministic**: the same message + the same private key → **always** the same signature. There's no random `k`. There's no risk of repetition.

---

### 3.4 Signing and Verifying — The Complete Flow with Real Code

Let's see exactly what our SDK does. The code is in `AgentIdentity.ts`:

#### Signing a Message

```typescript
// sdk/src/core/AgentIdentity.ts — line 148
public async signMessage(payload: string, agentPrivateKeyHex: string): Promise<string> {
    const messageBytes = new TextEncoder().encode(payload);     // 1. Convert text to bytes
    const privateKeyBytes = hexToBytes(agentPrivateKeyHex);     // 2. Convert hex key to bytes
    const signatureBytes = ed25519.sign(messageBytes, privateKeyBytes); // 3. Sign!
    return bytesToHex(signatureBytes);                          // 4. Return signature as hex
}
```

**Step by step:**

```
"Hello, I am the agent TradingBot"    →  TextEncoder.encode()  →  [72, 101, 108, 108, ...]
                                                                      (UTF-8 bytes)
                                                                          │
"a1b2c3..."                          →  hexToBytes()           →  [161, 178, 195, ...]
(private key hex)                                                  (key bytes)
                                                                          │
                                                                          ▼
                                                                   ed25519.sign()
                                                                          │
                                                                          ▼
                                                               [signature: 64 bytes]
                                                                          │
                                                                   bytesToHex()
                                                                          │
                                                                          ▼
                                                          "d4e5f6a7b8c9..."
                                                          (signature in hexadecimal)
```

#### Verifying a Signature

```typescript
// sdk/src/core/AgentIdentity.ts — line 275
public static async verifySignature(
    did: string, payload: string, signature: string, keyId?: string
): Promise<boolean> {

    // 1. Is the DID revoked?
    const isRevoked = await AgentIdentity.registry.isRevoked(did);
    if (isRevoked) return false;  // Revoked DID = rejected signature

    // 2. Resolve the DID → get DID Document
    const didDoc = await AgentIdentity.resolve(did);

    // 3. Convert payload and signature to bytes
    const messageBytes = new TextEncoder().encode(payload);
    const signatureBytes = hexToBytes(signature);

    // 4. Find valid keys for authentication
    const activeKeyIds = new Set(didDoc.authentication || []);
    const candidateMethods = didDoc.verificationMethod.filter((method) => {
        if (!method.publicKeyMultibase) return false;
        if (keyId) return method.id === keyId && activeKeyIds.has(method.id);
        return activeKeyIds.has(method.id);
    });

    // 5. Verify with each candidate key
    for (const verificationMethod of candidateMethods) {
        // decodePublicKeyMultibase handles the z + multicodec + base58btc format
        const publicKeyBytes = decodePublicKeyMultibase(verificationMethod.publicKeyMultibase!);
        const valid = ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);

        if (valid) return true;  // Valid signature!
    }

    return false;  // No key could verify
}
```

**The complete verification flow:**

```
┌──────────────────────────────────────────────────────────┐
│                    VERIFICATION                          │
│                                                          │
│  1. Is it revoked?  ──── Yes ──→ return false ❌        │
│         │                                                │
│        No                                                │
│         │                                                │
│  2. Resolve DID → get DID Document                       │
│         │                                                │
│  3. Filter keys in `authentication`                      │
│         │                                                │
│  4. For each candidate key:                              │
│     ┌────────────────────────────────────┐               │
│     │ ed25519.verify(sig, msg, pubKey)   │               │
│     │     true?  ──→ return true ✅      │               │
│     │     false? ──→ next key            │               │
│     └────────────────────────────────────┘               │
│         │                                                │
│  5. No key verified → return false ❌                    │
└──────────────────────────────────────────────────────────┘
```

**Key observation:** Verification first checks revocation, then resolves the DID, and then only tries keys that are in `authentication`. If you rotated keys, the old key is no longer in `authentication`, so the signature won't verify.

---

### 3.5 SHA-256 — Hashing to Protect Intellectual Property

#### What Is a Hash?

A **hash function** takes any data of any size and produces a **fixed-size** value. It's like a mathematical blender:

```
Input (any size)                Hash (always 256 bits = 64 hex characters)
─────────────────────────       ──────────────────────────────────────────
"Hello"                   → SHA-256 → "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c..."
"Hello."                  → SHA-256 → "798b2a8c5f14d449c73f98b7d8b2c9c5a7b3e1d4..."  ← Totally different!
(Don Quixote, complete)   → SHA-256 → "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b..."  (same size)
```

#### Fundamental Properties

| Property | Meaning | Implication |
|-----------|-------------|-------------|
| **Deterministic** | Same input → always the same hash | Two agents with the same prompt produce the same hash |
| **Irreversible** | You can't recover the input from the hash | Hashing a prompt doesn't reveal its content |
| **Avalanche effect** | Minimal change → completely different hash | You can't "guess" by getting closer gradually |
| **Collision-resistant** | It's practically impossible to find two inputs that produce the same hash | Each prompt/model has a unique hash |

#### The Real Code — `hash.ts`

```typescript
// sdk/src/crypto/hash.ts

import { ethers } from 'ethers';

// 1. hashPayload: converts a string to its SHA-256 hash
export function hashPayload(payload: string): string {
    const bytes = ethers.toUtf8Bytes(payload);   // "Hello" → [72, 101, 108, 108, 111]
    return ethers.sha256(bytes);                 // → "0x2cf24dba..."
}

// 2. formatHashUri: formats the hash as a URI
export function formatHashUri(hashHex: string): string {
    const cleanHash = hashHex.startsWith('0x') ? hashHex.slice(2) : hashHex;
    return `hash://sha256/${cleanHash}`;         // → "hash://sha256/2cf24dba..."
}

// 3. generateAgentMetadataHash: combines the two above
export function generateAgentMetadataHash(payload: string): string {
    const rawHash = hashPayload(payload);
    return formatHashUri(rawHash);               // → "hash://sha256/2cf24dba..."
}
```

Just 3 functions and ~20 lines of code. But these 20 lines are what protect the intellectual property of each agent.

#### How Is It Used in Practice?

When you create an agent with `AgentIdentity.create()`:

```typescript
const agent = await AgentIdentity.create({
    name: "TradingBot",
    model: "gpt-4-turbo",                           // ← model text
    systemPrompt: "You are a trading assistant...",  // ← secret prompt
    // ...other fields
});
```

Internally the SDK does:

```typescript
// sdk/src/core/AgentIdentity.ts — lines 100-101
const coreModelHashUri = generateAgentMetadataHash(params.model || '');
const systemPromptHashUri = generateAgentMetadataHash(params.systemPrompt || '');
```

And the resulting DID Document contains:

```json
"agentMetadata": {
    "coreModelHash": "hash://sha256/a1b2c3d4...",      // Doesn't say "gpt-4-turbo"
    "systemPromptHash": "hash://sha256/e5f6g7h8..."     // Doesn't say the prompt
}
```

**Result:** The world knows your agent uses *a specific model* and *a specific prompt*, can verify they haven't changed, but **doesn't know what they are**. If tomorrow someone copies your prompt and you need to prove you had it first, you show the blockchain with the timestamp of when you registered the hash.

**Technical note:** The SDK uses `ethers.sha256()` (from the ethers.js library) for hashing, not a custom implementation. `ethers.js` is one of the most audited libraries in the Ethereum ecosystem.

---

### 3.6 HTTP Signatures — RFC 9421 (HTTP Message Signatures)

So far we've seen simple message signatures (a string). But in the real world, agents communicate via **HTTP**. The question is:

> **How does a server know that an HTTP request truly came from a specific agent?**

The answer is **RFC 9421 — HTTP Message Signatures**, an IETF standard for signing HTTP requests.

#### The Problem It Solves

Today, APIs use **API keys** or **OAuth tokens**:

```
GET /api/data HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

Problems with this approach for AI agents:
1. If someone intercepts the token, they can impersonate the agent
2. The token isn't bound to the request content (you can reuse the token in another request)
3. There's no way to validate the agent's identity without asking the OAuth provider

**With HTTP signatures, each request has its own cryptographic signature bound to:**
- The exact URL (`@request-target`)
- The server host (`host`)
- The exact moment (`date`)
- The body content (`content-digest`)
- The agent's identity (`Signature-Agent`)

If someone intercepts the request and changes **anything**, the signature is invalidated.

#### The Step-by-Step Flow — `signHttpRequest()`

```typescript
// sdk/src/core/AgentIdentity.ts — line 157
public async signHttpRequest(params: SignHttpRequestParams): Promise<Record<string, string>> {
```

**Step 1: Calculate the Content-Digest (body hash)**

```typescript
// Private method: computeContentDigest()
const bodyHashHex = ethers.sha256(ethers.toUtf8Bytes(body || ""));
const bodyHashBase64 = Buffer.from(hexToBytes(cleanBodyHashHex)).toString('base64');
return `sha-256=:${bodyHashBase64}:`;
```

Example:
```
Body: '{"action": "buy", "symbol": "AAPL"}'
                    ↓ SHA-256
Content-Digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
```

**Step 2: Build the "signature base" (what is signed)**

```typescript
// Private method: buildHttpSignatureBase()
return [
    `(request-target): ${params.method.toLowerCase()} ${urlObj.pathname}${urlObj.search}`,
    `host: ${urlObj.host}`,
    `date: ${params.dateHeader}`,
    `content-digest: ${contentDigest}`
].join('\n');
```

Example of the string that is signed:
```
(request-target): post /api/v1/trade
host: api.exchange.com
date: Mon, 03 Mar 2026 14:30:00 GMT
content-digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
```

**Step 3: Sign with Ed25519**

```typescript
const signatureHex = await this.signMessage(stringToSign, params.agentPrivateKey);
const signatureBase64 = Buffer.from(hexToBytes(signatureHex)).toString('base64');
```

**Step 4: Build the response headers**

```typescript
return {
    'Signature': `sig1=:${signatureBase64}:`,
    'Signature-Input': `sig1=("@request-target" "host" "date" "content-digest");created=${timestamp};keyid="${verificationMethodId}";alg="ed25519"`,
    'Signature-Agent': params.agentDid,
    'Date': dateHeader,
    'Content-Digest': contentDigest
};
```

#### The 5 Headers Added to Each Request

| Header | Content | Purpose |
|--------|-----------|-----------|
| `Signature` | `sig1=:BASE64...:` | The cryptographic signature itself |
| `Signature-Input` | Signed components + metadata | What was signed, with which key, when |
| `Signature-Agent` | `did:agent:polygon:0x742d...` | Who signed (the agent's DID) |
| `Date` | `Mon, 03 Mar 2026 14:30:00 GMT` | When it was signed |
| `Content-Digest` | `sha-256=:BASE64...:` | Body hash (integrity) |

#### Complete Example of a Signed Request

```http
POST /api/v1/trade HTTP/1.1
Host: api.exchange.com
Date: Mon, 03 Mar 2026 14:30:00 GMT
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Agent: did:agent:polygon:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18
Signature-Input: sig1=("@request-target" "host" "date" "content-digest");created=1709473800;keyid="did:agent:polygon:0x742d...#key-1";alg="ed25519"
Signature: sig1=:dGhpcyBpcyBhIHNpbXBsaWZpZWQgZXhhbXBsZQ==:

{"action": "buy", "symbol": "AAPL", "quantity": 100}
```

---

### 3.7 HTTP Signature Verification — The Server Side

When the server receives the request, it executes `verifyHttpRequestSignature()`:

```
HTTP Request received
        │
        ▼
┌─────────────────────────────────────────┐
│ 1. Do the 5 required headers exist?     │
│    (Signature, Signature-Input,          │
│     Signature-Agent, Date,              │
│     Content-Digest)                     │
│    No → return false ❌                 │
└──────────┬──────────────────────────────┘
           │ Yes
           ▼
┌─────────────────────────────────────────┐
│ 2. Recalculate Content-Digest of body   │
│    Does it match the header?            │
│    No → return false ❌                 │
│    (body was altered in transit)        │
└──────────┬──────────────────────────────┘
           │ Yes
           ▼
┌─────────────────────────────────────────┐
│ 3. Parse Signature-Input                │
│    - Has the 4 components?              │
│      (@request-target, host, date,      │
│       content-digest)                   │
│    - Does keyid start with agentDid?    │
│    - Is the algorithm ed25519?          │
│    - Is the timestamp not too           │
│      old? (maximum 300 seconds)         │
└──────────┬──────────────────────────────┘
           │ All OK
           ▼
┌─────────────────────────────────────────┐
│ 4. Reconstruct signature base           │
│    (same calculation the agent did)     │
└──────────┬──────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│ 5. verifySignature()                    │
│    - DID revoked? → false               │
│    - Resolve DID → get public key       │
│    - ed25519.verify(sig, base, pubKey)  │
│    - true? → return true ✅             │
└─────────────────────────────────────────┘
```

**Crucial detail: the `maxSkew` (time deviation)**

```typescript
const maxSkew = params.maxCreatedSkewSeconds ?? 300;  // 300 seconds = 5 minutes
if (Math.abs(now - created) > maxSkew) continue;      // Signature too old → reject
```

This prevents **replay attacks**: if someone intercepts a signed request and tries to resend it later, it will be rejected because the `created` timestamp differs by more than 5 minutes from the current time.

---

### 3.8 Content-Digest — Body Integrity

The `Content-Digest` is a header standardized by the IETF that guarantees the integrity of the request body.

```typescript
// sdk/src/core/AgentIdentity.ts — private method
private static computeContentDigest(body?: string): string {
    const bodyHashHex = ethers.sha256(ethers.toUtf8Bytes(body || ""));
    const cleanBodyHashHex = bodyHashHex.startsWith('0x') ? bodyHashHex.slice(2) : bodyHashHex;
    const bodyHashBase64 = Buffer.from(hexToBytes(cleanBodyHashHex)).toString('base64');
    return `sha-256=:${bodyHashBase64}:`;
}
```

**Format:** `sha-256=:<base64(sha256(body))>:`

Why is it needed if we're already signing?
- The signature covers the **header** `Content-Digest`, not the body directly
- The Content-Digest links the body to the signature indirectly
- If someone modifies the body, the Content-Digest changes, and the signature becomes invalid

It's a **double lock**: the signature protects the headers, and the Content-Digest protects the body.

---

### 3.9 The `@noble/curves` Library — Why This One and Not Another?

```typescript
// sdk/src/core/AgentIdentity.ts — line 2
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
```

Our SDK uses the `@noble` family by **Paul Miller**. Why?

| Criterion | `@noble/curves` | `tweetnacl` | `libsodium-wrappers` |
|----------|-----------------|-------------|----------------------|
| Implementation | Pure JavaScript | Pure JavaScript | C compiled to WASM |
| Independent audit | ✅ Yes (Cure53) | ❌ No formal | ✅ Yes |
| Dependencies | 0 (zero deps) | 0 | Native binding |
| Size | ~40KB | ~7KB | ~200KB |
| Maintenance | Active (2024+) | No updates since 2020 | Active |
| Node.js + Browser | ✅ | ✅ | ⚠️ Requires WASM |

**Key decisions:**
1. **Pure JavaScript**: Works in any environment (Node.js, browser, Deno, edge functions) without native bindings
2. **Cure53 audit**: A recognized security firm reviewed the code. It's not "artisanal" cryptography
3. **Zero dependencies**: Less attack surface (supply chain attacks)
4. **Active maintenance**: Updated regularly, unlike abandoned alternatives

**Important warning for the community:** We **don't implement cryptography**. We use an audited library. Implementing your own cryptography is one of the worst security decisions you can make.

---

### 3.10 Putting It All Together — The Complete Picture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    CRYPTOGRAPHY IN THE SDK                            │
│                                                                      │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────────────────┐  │
│  │  @noble/     │    │    ethers.js      │    │   Ed25519 Keypair  │  │
│  │  curves      │    │                  │    │                    │  │
│  │              │    │  ethers.sha256()  │    │  Private (32B)     │  │
│  │  ed25519     │    │  ethers.toUtf8    │    │  Public  (32B)     │  │
│  │  .sign()     │    │  Bytes()          │    │                    │  │
│  │  .verify()   │    │                  │    │  Stored by the     │  │
│  │              │    │  Used in:         │    │  operator, NEVER   │  │
│  │  Used in:    │    │  • hash.ts        │    │  in the DID        │  │
│  │  • signMsg   │    │  • Content-       │    │  Document          │  │
│  │  • verifyMsg │    │    Digest         │    │                    │  │
│  │  • signHTTP  │    │  • documentRef    │    │                    │  │
│  └─────────────┘    └──────────────────┘    └────────────────────┘  │
│                                                                      │
│  Combined in:                                                        │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │                    AgentIdentity                              │   │
│  │                                                               │   │
│  │  create()        → generates keys + hashes + DID Document    │   │
│  │  signMessage()   → pure Ed25519 signature                    │   │
│  │  signHttpRequest()   → HTTP signature (5 headers)            │   │
│  │  verifySignature()   → resolves DID + verifies Ed25519       │   │
│  │  verifyHttpRequestSignature() → verifies headers + signature │   │
│  └───────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

---

### Module 3 Exercises

**Exercise 1**: Explain in your own words the difference between symmetric and asymmetric cryptography. Why does the SDK use asymmetric?

**Exercise 2**: A colleague tells you "Why not use ECDSA like Ethereum? It's already a proven standard." Respond in 3-4 sentences explaining why Ed25519 is better for frequent AI agent signatures.

**Exercise 3**: Given the prompt `"You are a helpful trading assistant"`, describe step by step what functions `hashPayload()` → `formatHashUri()` → `generateAgentMetadataHash()` do. What value ends up in the DID Document?

**Exercise 4**: Trace the complete flow of a signed HTTP request:
- The agent calls `signHttpRequest()` with method POST, URL `https://api.example.com/trade`, body `{"action":"buy"}`
- What headers are generated?
- The server receives the request. In what order does it verify? What happens if the body was altered?

**Exercise 5**: What is a replay attack and how does the `created` field in `Signature-Input` prevent it? What is the default value of `maxSkew` in our SDK?

**Exercise 6**: Why does the SDK use `@noble/curves` instead of implementing Ed25519 from scratch? Mention at least 3 reasons.

---

### Talking Points for the Community

- "We chose Ed25519 because it's deterministic — it eliminates the entire class of ECDSA vulnerabilities where a weak RNG leaks the private key (PlayStation 3 case, 2010)"
- "SHA-256 hashes protect the agent's intellectual property: you can prove what model you use without revealing the source code"
- "HTTP signatures let us authenticate agents on any API without API keys — each request carries its own cryptographic proof"
- "We use @noble/curves, audited by Cure53 — we don't implement cryptography, we use what experts have already verified"
- "The Content-Digest is a double lock: the signature protects the headers and the digest protects the body"
- "The 5-minute maxSkew prevents replay attacks — an intercepted signature expires before it can be reused"

---

### Sample Answers and Evaluation — Module 3

#### Exercise 1: Symmetric vs asymmetric cryptography — **9/10** 🌟

> "Symmetric cryptography uses the same key to encrypt and decrypt, like for example the password on a ZIP file. This implies a problem because you have to pass the key itself to the recipient who needs to decrypt the message, and this is a major security risk since someone can intercept the message and obtain the key."
>
> "Asymmetric cryptography uses two keys, a private key known only to the sender and a public key, which can be known by anyone. The message signed by the sender can be verified by the recipient with the public key, the sender's signature and the message itself. It's impossible to determine the private key from the public key."
>
> "The Agent DID SDK uses asymmetric cryptography to guarantee that anyone can determine the authenticity of the message's author using only pure mathematics without needing to know the private key, only their public key — therein lies the beauty of the Agent DID SDK's architecture."

**Excellent.** Clear, precise explanation with a good example (ZIP file). The final sentence demonstrates conviction — it's the type of communication that works with the community.

**Minor point to refine:** When you say "can be verified by the recipient", it's more precise to say **anyone**, not just the recipient. Verification is public — that's precisely the point.

---

#### Exercise 2: Why Ed25519 instead of ECDSA? — **7/10** ✅

> "Ed25519 is short (32 bytes), both for the private and public key, is 100x faster in signature generation and doesn't depend on random number generators that inject an additional dependency and therefore a possible failure mechanism."

**Correct on all 3 points**, but lacked development:

| Point | Evaluation |
|-------|-----------|
| 32-byte keys | ✅ But ECDSA (secp256k1) also uses 32-byte keys for the private key — not the main differentiator |
| 100x faster | ✅ (~100K vs ~1K signatures/sec) |
| Doesn't depend on RNG | ✅ **Strongest argument** — lacked explaining *why* it matters |

**What would have strengthened the answer:** Mentioning the real case of the PlayStation 3 hack (2010). Sony used ECDSA with a repeated `k` value and hackers extracted the private key. For an agent signing thousands of requests per day, that risk would be catastrophic.

**Model version:**
> "ECDSA needs an internal random number (k) on each signature. If that number repeats — something possible with thousands of daily signatures — the private key gets exposed. This happened to Sony in 2010. Ed25519 is deterministic: same input, same signature, no random numbers. Plus it's 100x faster, which matters when an agent signs every HTTP request."

---

#### Exercise 3: Hash flow — **8/10** ✅

> "hashPayload(): Converts a string to a SHA-256 Hash value. formatHashUri(): formats the SHA-256 Hash into a URI format, for example: hash://sha256/56cd25f.... generateAgentMetadataHash(): Uses the two above to generate the final hash with URI format."

**Correct and concise.** Failed to answer the second part: *"What value ends up in the DID Document?"*

```
"You are a helpful trading assistant"
         │
         ▼  hashPayload()
"0x7f83b1657ff1fc53b..."
         │
         ▼  formatHashUri()
"hash://sha256/7f83b1657ff1fc53b..."
         │
         ▼  In the DID Document:
"systemPromptHash": "hash://sha256/7f83b1657ff1fc53b..."
```

The prompt **never** appears in the document — only its hash in URI format.

---

#### Exercise 4: HTTP verification diagram — **10/10** 🌟🌟

The flow diagram presented is **impeccable**:

- ✅ Entry point: "Signed HTTP Request"
- ✅ Check 1: 5 required headers? → No → False
- ✅ Check 2: Recalculate body Digest → matches? → No → False
- ✅ Check 3: Parse Signature-Input with all 4 validations (components, keyid, algorithm, timestamp ≤ 300 sec)
- ✅ Check 4: Reconstruct signature base (same calculation the agent did)
- ✅ Check 5: Verify Signature → Yes → True / No → False

**What it demonstrates:** Understanding of the sequential validation order and the **fail-fast** pattern — the server doesn't waste resources on cryptographic verification (expensive) until all cheap validations pass first.

---

#### Exercise 5: Replay attack — **5/10** ⚠️

> "The replay attack occurs when an attacker tries to resend a message at a future time that exceeds the 3min threshold. The maxSkew defines that threshold at 3min."

**Two errors:**

1. **The maxSkew value is 300 seconds = 5 minutes**, not 3 minutes. From the code: `const maxSkew = params.maxCreatedSkewSeconds ?? 300;`

2. **Incomplete definition.** A replay attack is when an attacker **intercepts** a legitimate already-signed HTTP request and **resends** it as-is to execute the same action again. For example: intercepts a signed purchase order and resends it 10 times to buy 10 times.

**How `created` prevents it:** The server compares `created` with the current time. If the difference exceeds 300 seconds (5 minutes), the request is rejected. Thus, a request intercepted and resent 10 minutes later will be automatically rejected.

**Honest limitation:** The maxSkew doesn't prevent replays within the 5-minute window. For that, nonces (one-time numbers) would be needed, which our SDK v0.1.0 doesn't yet implement.

---

#### Exercise 6: Why `@noble/curves`? — **4/10** ⚠️

> "It would be a mistake to try to implement cryptography ourselves, @noble/curves is one of the most audited algorithms of Ethereum"

**Only 1 reason when 3 were requested.** Also, `@noble/curves` is not "from Ethereum" — it's an independent library by Paul Miller used in many projects.

**The 3+ expected reasons:**

1. **Professional audit:** Audited by Cure53, a recognized security firm
2. **Zero dependencies:** Less attack surface against supply chain attacks
3. **Pure JavaScript:** Works in Node.js, browser, Deno, edge functions without native bindings
4. **Active maintenance:** Updated regularly, unlike `tweetnacl` (abandoned since 2020)
5. **Golden rule:** Don't implement your own cryptography (your correct point)

---

#### Module 3 Evaluation Summary

| Exercise | Score | Level |
|-----------|-----------|-------|
| 1. Symmetric vs asymmetric | 9/10 | 🌟 Excellent |
| 2. Ed25519 vs ECDSA | 7/10 | ✅ Correct, lacked development |
| 3. Hash flow | 8/10 | ✅ Solid, missing final answer |
| 4. HTTP verification diagram | 10/10 | 🌟🌟 Perfect |
| 5. Replay attack | 5/10 | ⚠️ Incomplete definition, incorrect value |
| 6. Why @noble/curves? | 4/10 | ⚠️ Only 1 of 3 reasons, imprecision |
| **Average** | **7.2/10** | **✅ Approved** |

**Overall progress:**

| Module | Average | Trend |
|--------|---------|-----------|
| Module 1 | 7.8/10 | — |
| Module 2 | 8.0/10 | ↑ |
| Module 3 | 7.2/10 | ↓ |

**Analysis:** The strongest point continues to be architectural comprehension (diagram 10/10). The area for improvement is in exact details (5 min vs 3 min) and in developing discursive answers with more depth. For the community, use the structure: **Statement → Technical reason → Concrete example**.


## Module 4 — RFC-001: The Agent-DID Specification

### Learning objectives
- Understand the RFC-001 specification in its entirety
- Know each field of the Agent-DID Document and its justification
- Understand the hybrid on-chain/off-chain architecture
- Master the normative operational flows
- Master the 16 conformance controls and their evidence
- Know how to answer community questions about the standard's maturity

### 4.1 What is an RFC and why RFC-001?

**RFC** = Request For Comments. It is the standard format for documenting technical specifications, originated at the IETF (Internet Engineering Task Force) in 1969 with RFC 1 by Steve Crocker about ARPANET. Today there are more than 9,000 IETF RFCs that define HTTP, TCP/IP, DNS, TLS, etc.

Our **RFC-001** is an **internal RFC of the Agent-DID project**. The numbering "001" indicates it is the first formal specification of this project. Many open-source projects use internal RFC series (Rust has `rust-lang/rfcs`, React has internal RFCs, Ethereum has EIPs). There is no conflict with IETF's RFC 1 because our RFC lives in this project's namespace. Future specifications would be RFC-002, RFC-003, etc.

**Current document status:**
- **Status:** Active Draft
- **Version:** 0.2-unified
- **Scope:** Canonical and unified document for the Agent-DID specification

### 4.2 Relationship with existing standards

RFC-001 does not invent from scratch — it **orchestrates** existing standards for the specific case of autonomous agents:

| Existing standard | What it contributes to Agent-DID |
|---|---|
| **W3C DID / DID Document** | Foundation of decentralized identity — structure, resolution, format |
| **W3C Verifiable Credentials (VC)** | Support for auditable compliance certifications |
| **ERC-4337 / Account Abstraction** (optional) | Autonomous account so the agent can make payments and economic operations |
| **HTTP Message Signatures / Web Bot Auth** (emerging) | HTTP request signing for A2A authentication and APIs |

The key phrase from the RFC: *"Agent-DID does not replace these standards; it orchestrates them for the specific case of autonomous agents."*

### 4.3 The 5 design principles

These principles are the **fundamental architectural decisions** that guide the entire specification:

#### Principle 1: Persistent identity, mutable state
- The DID **never** changes — `did:agent:polygon:0xABC123` is permanent
- But the document can evolve: new model, new prompt, new keys, new capabilities
- **Analogy**: Your ID number doesn't change even if you change your address, job, or photo

#### Principle 2: Minimum on-chain
- Only the indispensable goes on blockchain: DID, controller, document reference, revocation status
- Everything else lives off-chain in decentralized storage (IPFS, HTTP)
- **Reasons**: Gas cost (storing 32 bytes on-chain ≈ 20,000 gas), speed, privacy

#### Principle 3: Strong cryptography by default
- Ed25519 comes configured out of the box — the developer doesn't have to choose or configure algorithms
- "By default" is key: security without friction
- Ed25519: deterministic, ~100K signatures/second, 32-byte keys, 64-byte signatures

#### Principle 4: Blockchain-agnostic
- The specification is not tied to any specific blockchain
- Compatible with **any network**, not just EVMs: could adapt to Solana, Cosmos, Hyperledger
- EVM (Polygon) is just the **reference implementation**, not a requirement

#### Principle 5: Interoperability
- Two concrete mechanisms: **JSON-LD schema** (document readable by any implementation) + **universal resolution** (any compatible resolver can resolve)
- If someone implements RFC-001 in Python, Go, or Rust, they must be able to verify signatures generated by the TypeScript SDK

### 4.4 Agent-DID Document structure

#### Base JSON-LD schema

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
  "id": "did:agent:polygon:0x1234...abcd",
  "controller": "did:ethr:0xCreatorWalletAddress",
  "created": "2026-02-22T14:00:00Z",
  "updated": "2026-02-22T14:00:00Z",
  "agentMetadata": {
    "name": "SupportBot-X",
    "description": "Level 1 technical support agent",
    "version": "1.0.0",
    "coreModelHash": "hash://sha256/...",
    "systemPromptHash": "hash://sha256/...",
    "capabilities": ["read:kb", "write:ticket"],
    "memberOf": "did:fleet:0xCorporateSupportFleet"
  },
  "complianceCertifications": [
    {
      "type": "VerifiableCredential",
      "issuer": "did:auditor:0xTrustCorp",
      "credentialSubject": "SOC2-AI-Compliance",
      "proofHash": "ipfs://Qm..."
    }
  ],
  "verificationMethod": [
    {
      "id": "did:agent:polygon:0x1234...abcd#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:ethr:0xCreatorWalletAddress",
      "publicKeyMultibase": "z...",
      "blockchainAccountId": "eip155:1:0xAgentSmartWalletAddress"
    }
  ],
  "authentication": ["did:agent:polygon:0x1234...abcd#key-1"]
}
```

#### Normative fields — REQUIRED vs OPTIONAL classification

| Field | Requirement | Description |
|---|---|---|
| `id` | **REQUIRED** | Unique DID of the agent (`did:agent:<network>:<id>`) |
| `controller` | **REQUIRED** | DID or identifier of the human/organizational controller |
| `created` / `updated` | **REQUIRED** | ISO-8601 timestamps of the document |
| `agentMetadata.coreModelHash` | **REQUIRED** | Immutable hash of the base model |
| `agentMetadata.systemPromptHash` | **REQUIRED** | Immutable hash of the system prompt |
| `verificationMethod` | **REQUIRED** | Valid public keys for signature verification |
| `authentication` | **REQUIRED** | References to valid authentication methods |
| `complianceCertifications` | OPTIONAL | Evidence of audits and VCs |
| `agentMetadata.capabilities` | OPTIONAL | Declared/authorized capabilities |
| `agentMetadata.memberOf` | OPTIONAL | Link to agent fleet/cohort |

**Key rule**: Without the REQUIRED fields, the document is invalid according to the specification. OPTIONAL fields enrich the identity but are not necessary for basic operation.

### 4.5 Controller vs Owner — The critical distinction

This is one of the most important and frequently confused distinctions:

| Aspect | Controller | Owner |
|---------|-----------|-------|
| **Where it lives** | In the DID Document (off-chain) | In the smart contract (on-chain) |
| **What it is** | Identity (DID) of the human/organization that governs the agent | EVM address with operational control of the registry |
| **Format** | `did:ethr:0x...` | `address` (0x...) |
| **What it can do** | Defines legal/organizational responsibility | Execute `revokeAgent`, `setDocumentRef`, `setRevocationDelegate`, `transferAgentOwnership` |
| **Example** | Acme Corp company | A DevOps engineer at Acme Corp |

**Realistic scenario**: A financial corporation (controller: `did:web:acmecorp.com`) creates an agent to deliver reports. It delegates to its IT department, specifically an engineer (owner: `0xEngineer...`), the on-chain registration and blockchain operations for the agent. If the engineer changes jobs, ownership is transferred to another engineer (`transferAgentOwnership`), but the controller remains the corporation.

**Can an agent be controller of another agent?** Technically yes. The `controller` field is a DID string, it doesn't specify it must be human. This enables **agent hierarchies**: an orchestrator agent that controls sub-agents. With ERC-4337, an agent can even be an on-chain owner with its own smart wallet.

### 4.6 Hybrid on-chain/off-chain architecture

#### What goes in each layer

```
┌─────────────────────────────────────────────────────────┐
│                      OFF-CHAIN                          │
│  (IPFS, HTTP, decentralized storage)                    │
│                                                         │
│  • Complete JSON-LD document                            │
│  • agentMetadata (name, model, prompt, capabilities)    │
│  • verificationMethod (public keys)                     │
│  • complianceCertifications (extensive VCs)              │
│  • Version history                                      │
└─────────────────────────────────────────────────────────┘
                          ▲
                          │ documentRef (URI)
                          │
┌─────────────────────────────────────────────────────────┐
│                       ON-CHAIN                          │
│  (Smart Contract AgentRegistry.sol)                     │
│                                                         │
│  • did (string) — identifier                            │
│  • controller (string) — controller reference           │
│  • createdAt (string) — creation timestamp              │
│  • revokedAt (string) — revocation timestamp            │
│  • documentRef (string) — URI to off-chain document     │
│  • exists (bool) — does this record exist?              │
│  • owner (address) — EVM account with operational ctrl  │
└─────────────────────────────────────────────────────────┘
```

#### The `bool exists` field — Solidity pattern

In Solidity, **all mappings return a default value** for any key, even if it was never written to the blockchain. If you query `records["did:agent:polygon:0xNONEXISTENT"]`, it doesn't throw an error — it returns a struct with all fields empty.

The `exists` field is marked `true` only when an agent is registered:
```solidity
records[did] = AgentRecord({
    ...
    exists: true,  // ← Explicitly marked
    ...
});
```

This allows distinguishing between "record with empty values" and "record never created":
- `require(record.exists, "not found")` → reject operations on unregistered DIDs
- `require(!records[did].exists, "already registered")` → prevent duplicates
- In `isRevoked()`: if it doesn't exist, returns `false` (it's not "revoked", it simply doesn't exist)

#### Why not put everything on blockchain?

| Consequence | Impact |
|---|---|
| **Prohibitive gas cost** | Storing 32 bytes on-chain ≈ 20,000 gas. A complete DID Document could cost tens of dollars per registration |
| **Permanent public information** | Everything on blockchain is visible forever. You don't want metadata, capabilities, or configurations permanently public |
| **Speed** | On-chain transactions take seconds/minutes. Off-chain queries are instant |
| **Rigid immutability** | If you need to correct data, you must make another transaction (more gas). Off-chain you update the document directly |
| **No granular access control** | Blockchain is all-or-nothing in visibility. Off-chain you can have selective access |

### 4.7 The 5 normative operational flows

#### Flow 1: Registration (RFC §6.1)
1. The controller generates the DID and Ed25519 keys for the agent
2. A JSON-LD document is built with the model and prompt hashes
3. The DID and controller are anchored in the on-chain registry (`registerAgent`)

```typescript
const identity = await AgentIdentity.create({
  name: 'SupportBot-X',
  coreModel: 'GPT-4-Turbo',
  systemPrompt: 'You are a level 1 support agent...',
  capabilities: ['read:kb', 'write:ticket']
});
```

#### Flow 2: Resolution and Verification (RFC §6.2)
1. The consumer obtains the `Signature-Agent` or the issuer's DID
2. Resolves the DID via universal resolver (with failover in production)
3. Verifies the signature with `verificationMethod`
4. Verifies non-revoked status in the registry

```typescript
const isValid = await AgentIdentity.verifySignature(
  did,
  payload,
  signature
);
// Internally: resolve(did) → get publicKey → verify signature → verify not revoked
```

#### Flow 3: Evolution (RFC §6.3)
1. The DID remains stable — never changes
2. `updated` and hashes change in the new document version
3. The registry points to the new document reference

```typescript
await AgentIdentity.updateDidDocument(did, {
  coreModelHash: 'hash://sha256/new-hash-gpt5...',
  updated: '2026-06-01T00:00:00Z'
});
```

#### Flow 4: Revocation (RFC §6.4)
1. The controller (or defined policy) marks the DID as revoked
2. All subsequent verifications must fail
3. In the EVM contract: the owner or an authorized delegate executes `revokeAgent(did)`

```typescript
await AgentIdentity.revokeDid(did);
// On-chain: record.revokedAt = current timestamp → all future verification fails
```

#### Flow 5: HTTP Signing — Web Bot Auth (RFC §6.5)
1. The agent signs HTTP components (`@request-target`, `host`, `date`, `content-digest`)
2. Includes an agent identity header (`Signature-Agent`)
3. The server validates: signature + DID + revocation status before authorizing

```typescript
const signedHeaders = await AgentIdentity.signHttpRequest({
  method: 'POST',
  url: '/api/data',
  headers: { host: 'api.example.com', 'content-type': 'application/json' },
  body: JSON.stringify({ query: 'financial-report' }),
  did: identity.did,
  privateKey: identity.privateKey,
  keyId: `${identity.did}#key-1`
});
// Result: headers with Signature, Signature-Input, Signature-Agent, Date, Content-Digest
```

### 4.8 A2A Communication (Agent-to-Agent)

HTTP signing enables the most powerful use case of the SDK — bilateral verification between agents:

```
┌─────────────────────┐                    ┌─────────────────────┐
│   AGENT ALICE       │                    │   AGENT BOB         │
│ did:agent:poly:0xA  │                    │ did:agent:poly:0xB  │
└──────────┬──────────┘                    └──────────┬──────────┘
           │                                          │
     1. Alice prepares HTTP request                   │
     2. Signs with her private Ed25519                │
     3. Includes headers:                             │
        - Signature                                   │
        - Signature-Input                             │
        - Signature-Agent: did:agent:poly:0xA         │
        - Date                                        │
        - Content-Digest                              │
           │                                          │
           │────── POST /api/negotiate ──────────────▶│
           │                                          │
           │                                    4. Bob extracts Signature-Agent
           │                                    5. Bob resolves did:agent:poly:0xA
           │                                       → gets Alice's publicKey
           │                                    6. Bob verifies signature against payload
           │                                    7. Bob verifies Alice is not revoked
           │                                    8. Bob verifies Alice's capabilities
           │                                          │
           │                                    9. Bob prepares response
           │                                   10. Bob signs with HIS Ed25519
           │                                   11. Bob includes Signature-Agent: 0xB
           │                                          │
           │◀───── 200 OK (signed) ──────────────────│
           │                                          │
    12. Alice extracts Bob's Signature-Agent           │
    13. Alice resolves did:agent:poly:0xB              │
    14. Alice verifies Bob's signature                 │
    15. Alice verifies Bob is not revoked              │
```

**What is verified in each direction:**
- **Authenticity**: the signature corresponds to the DID's public key
- **Integrity**: the payload was not altered (Content-Digest)
- **Validity**: the DID is not revoked
- **Identity**: capabilities, coreModelHash, complianceCertifications can be inspected

**Difference from A2A without DID**: Without Agent-DID, agents authenticate with shared API keys — no non-repudiation, no decentralized identity. If a key leaks, there's no way to know which agent used it. With Agent-DID, each agent has a unique and irrefutable cryptographic identity.

### 4.9 Response to verification anomalies

When a server detects an anomaly in the cryptographic verification of a signed HTTP request:

**What RFC-001 ALREADY defines:**
- The request is **rejected** immediately
- Invalid signature, altered payload, or revoked DID prevent authorization

**What the RFC does NOT prescribe (intentionally):**
An automatic notification protocol for revocation. Reasons:
1. **False positives**: an invalid signature could be a network error or client bug, not an attack
2. **Authority**: only the controller/owner can revoke — the server detecting the anomaly typically doesn't have that authority

**Recommended response pattern:**
```
[Server detects anomaly]
       │
       ▼
[1. Security log with evidence]
  - Agent's DID, timestamp, failure type, complete headers
       │
       ▼
[2. Alert to controller/owner]
  - Webhook / email / alerting system
       │
       ▼
[3. Human decision or automated policy]
  - Confirmed incident → controller calls revokeDid()
  - Repeated pattern → rate limiting / temporary blacklist
  - False positive → no action
       │
       ▼
[4. On-chain revocation (if applicable)]
  - owner or delegate executes revokeAgent(did)
  - All future verifications fail automatically
```

This is a natural candidate for an **RFC-002: Incident Response Protocol for Agent-DID Anomalies**.

### 4.10 The Smart Contract: AgentRegistry.sol

The contract implements **8 functions**, **4 events**, and the `AgentRecord` structure:

#### Contract functions:

| Function | Who can call it | What it does |
|---------|---------------------|----------|
| `registerAgent(did, controller)` | Anyone | Registers a new DID with its controller |
| `revokeAgent(did)` | Owner or delegate | Marks the DID as revoked with timestamp |
| `setDocumentRef(did, documentRef)` | Owner only | Updates the reference to the off-chain document |
| `setRevocationDelegate(did, delegate, authorized)` | Owner only | Authorizes/deauthorizes an address as delegate |
| `transferAgentOwnership(did, newOwner)` | Owner only | Transfers ownership to another address |
| `getAgentRecord(did)` | Anyone (view) | Queries the registry data |
| `isRevoked(did)` | Anyone (view) | Queries if the DID is revoked |
| `isRevocationDelegate(did, delegate)` | Anyone (view) | Queries if an address is a delegate |

#### Events:
- `AgentRegistered(did, controller, createdAt)` — on registration
- `AgentRevoked(did, revokedAt)` — on revocation
- `RevocationDelegateUpdated(did, delegate, authorized)` — on delegate changes
- `AgentOwnershipTransferred(did, previousOwner, newOwner)` — on ownership transfer

#### Access control for revocation (internal function):
```solidity
function _isAuthorizedRevoker(string calldata did, address actor) private view returns (bool) {
    AgentRecord memory record = records[did];
    return record.owner == actor || revocationDelegates[did][actor];
}
```
Only two types of accounts can revoke: the direct owner or an authorized delegate. This is control SHOULD-04.

### 4.11 The 16 conformance controls

#### A. MUST Controls (11 mandatory) — All PASS

| ID | Control | Evidence |
|---|---|---|
| MUST-01 | Emit document with REQUIRED fields | `types.ts`, `AgentIdentity.ts` |
| MUST-02 | Support `create(params)` | `AgentIdentity.ts` |
| MUST-03 | Support `signMessage(payload, privateKey)` | `AgentIdentity.ts` |
| MUST-04 | Support `signHttpRequest(params)` with required components | `AgentIdentity.ts`, positive/negative tests |
| MUST-05 | Support `resolve(did)` | `UniversalResolverClient.ts`, HTTP/JSON-RPC sources, direct `did:wba` resolution |
| MUST-06 | Support `verifySignature` and fail if revoked | `AgentIdentity.ts`, tests |
| MUST-07 | Support `revokeDid(did)` | `AgentIdentity.ts`, registries |
| MUST-08 | Registry with minimum operations | `AgentRegistry.sol`, SDK registries |
| MUST-09 | Valid signature before and invalid after revocation | smoke + unit tests |
| MUST-10 | Evolution cycle (updated + rotation) | `AgentIdentity.ts`, tests |
| MUST-11 | On-chain/off-chain separation with reference | `AgentRegistry.sol`, SDK |

#### B. SHOULD Controls (5 recommended) — All PASS

| ID | Control | What it solves |
|---|---|---|
| **SHOULD-01** | Universal serverless resolver with cache and high availability | DID resolution works in production with failover, cache TTL, and direct `did:wba` web resolution |
| **SHOULD-02** | Homogeneous temporal normalization | Time is the same regardless of whether you read it from blockchain (Unix timestamp) or SDK (ISO-8601). Implemented in `time.ts` |
| **SHOULD-03** | Interoperable verification mode | Signatures generated by the TypeScript SDK can be verified by implementations in other languages. Ensured with shared vectors in `interop-vectors.json` |
| **SHOULD-04** | Access control policies for revocation | Not just anyone can revoke any agent. The contract implements owner + delegates with `_isAuthorizedRevoker` |
| **SHOULD-05** | Evolution traceability by version | Track the complete version history of the document (what model was this agent using last week). Implemented with `getDocumentHistory(did)` |

#### Exit criteria — "RFC-001 conformant"

An implementation is conformant when:
1. All MUSTs are PASS
2. At least 3 SHOULDs are PASS and none are FAIL for production deployment

**Executable verification:** `npm run conformance:rfc001`

### 4.12 RFC → SDK mapping

| RFC Flow | SDK API/Artifact |
|---|---|
| Identity registration (§6.1) | `AgentIdentity.create(params)` |
| Payload signing (§6.2) | `signMessage(payload, privateKey)` |
| HTTP signing (§6.5) | `signHttpRequest(params)` |
| DID resolution (§6.2) | `AgentIdentity.resolve(did)` |
| Signature verification (§6.2) | `verifySignature(...)` and `verifyHttpRequestSignature(...)` |
| Document evolution (§6.3) | `updateDidDocument(did, patch)` |
| Key rotation (§8.2) | `rotateVerificationMethod(did)` |
| Revocation (§6.4) | `revokeDid(did)` |
| Production resolver (§5.3) | `useProductionResolverFromHttp(...)`, `useProductionResolverFromJsonRpc(...)` |
| EVM integration (§5.2) | `EthersAgentRegistryContractClient` + `EvmAgentRegistry` |

### 4.13 Security and privacy

The RFC establishes 5 security rules:

1. **Do not publish prompts in plain text**: use verifiable hashes (`hash://sha256/...`)
2. **Key rotation**: define rotation and `verificationMethod` update policy
3. **Immediate revocation**: critical requirement when keys are compromised
4. **Principle of least privilege**: explicit and bounded capabilities
5. **Auditing**: maintain evidence of versions and state changes

### 4.14 Reference use cases

The RFC defines 5 use cases that validate the specification:

1. **Independent agents on social/economic platforms** — own identity without depending on the platform
2. **Corporate governance and audited compliance** — SOC2, ISO 27001 VCs anchored in the document
3. **Massive agent fleets with individual identity** — each agent has its DID even if it belongs to a fleet
4. **Integration with Zero-Trust APIs via HTTP signing** — cryptographic authentication without API keys
5. **Agent-to-agent commerce with cryptographic non-repudiation** — irrefutable proof of who paid whom

### 4.15 Agents and economic operations

The RFC explicitly foresees the possibility of agents participating in economic operations:

- **ERC-4337 (Account Abstraction)**: An agent can have a smart wallet on Ethereum/Polygon with ETH, MATIC, ERC-20 tokens (USDC, USDT)
- The `blockchainAccountId` field in `verificationMethod` links the agent's identity with its economic account:
  ```json
  "blockchainAccountId": "eip155:1:0xAgentSmartWalletAddress"
  ```
- **Bitcoin**: Not directly EVM, but an agent could use wrapped BTC (WBTC) as an ERC-20 token, or have an associated Bitcoin address in its document
- **Use case #5 of the RFC**: *"Agent-to-agent commerce with cryptographic non-repudiation"* — each transaction has cryptographic signature as irrefutable proof

**Note**: The current SDK is focused on identity, not payments. Payment integration would be a natural extension (potential RFC-002 or RFC-003).

### Talking Points for the community

- *"RFC-001 has 16 conformance controls, all PASS — you can verify it yourself with `npm run conformance:rfc001`"*
- *"It's not just a draft — it's a functional and validated implementation with 16 verifiable controls"*
- *"We're not inventing cryptography or starting from zero. We're extending proven standards (W3C, Ed25519, Solidity) to solve decentralized identity for AI agents"*
- *"The hybrid architecture optimizes gas costs: only the minimum on blockchain, the rest off-chain"*
- *"Model and prompt hashes protect IP without sacrificing verifiability"*
- *"The DID persists even if you change the model, prompt, or keys — it's the agent's identity, not its configuration"*
- *"A2A with Agent-DID replaces shared API keys with cryptographic identity and non-repudiation"*

---

### Module 4 Questions and Answers

**Q1: Why RFC-001 and not another number? Doesn't an RFC 001 already exist?**
IETF RFCs are the global Internet standards (RFC 1, from 1969, about ARPANET). Our RFC-001 is an internal RFC of the Agent-DID project — the numbering "001" indicates it's the first specification of this project. Many open-source projects (Rust, React, Ethereum/EIPs) use their own internal RFC series. There's no conflict because our RFC lives in the project's namespace.

**Q2: The on-chain `bool exists` field, what does it refer to?**
It's a classic Solidity pattern for distinguishing between a record that was created with empty values and one that never existed. In Solidity, mappings return default values for any key (they don't throw errors). Without `exists`, you can't tell if a DID wasn't registered or was registered with empty data. It's marked `true` only at the moment of registration.

**Q3: When a verification anomaly is detected in HTTP, what's the process to revoke?**
The RFC defines verification and rejection, but doesn't prescribe an automatic notification protocol — intentionally, because: (a) an invalid signature could be a false positive (network error, bug), and (b) only the owner/delegate can revoke, not the server detecting the anomaly. The recommended pattern is: security log → alert to controller → human decision or automated policy → on-chain revocation if the incident is confirmed.

**Q4: What is SHOULD-02 "Homogeneous temporal normalization"?**
It ensures time is consistent between layers. The smart contract uses `block.timestamp` (Unix, number), while the SDK and DID Document use ISO-8601 (`"2026-02-22T14:00:00Z"`). Without normalization, there would be confusion and comparison errors. The solution is in `time.ts`: bidirectional conversions so the SDK always exposes ISO-8601.

**Q5: What is SHOULD-03?**
Interoperable verification mode with external implementations. It ensures that if someone implements RFC-001 in Python, Go, or Rust, signatures generated by the TypeScript SDK can be verified and vice versa. Achieved with shared interoperability vectors in `interop-vectors.json`, like standardized exams where the correct answers are the same regardless of the implementation.

**Q6: What does SHOULD-04 refer to?**
Access control policies for revocation at the contract level. It ensures not just anyone can revoke any agent. The contract implements: direct owner (who registered), authorized delegates (`setRevocationDelegate`), and ownership transfer. The `_isAuthorizedRevoker()` function checks: `owner == actor || revocationDelegates[did][actor]`.

**Q7: And SHOULD-05?**
Evolution traceability by version. When a DID Document evolves (model, keys, capabilities change), the complete version history can be tracked. Implemented with `getDocumentHistory(did)`. Allows answering: "what model was this agent using last week when it signed a contract?" Analogy: like Git commit history.

**Q8: Can an agent be Controller or Owner?**
Technically yes in both cases. As controller: an agent DID can be `controller` of another agent (agent hierarchies). As on-chain owner: with ERC-4337 (Account Abstraction), an agent can have its own smart wallet and execute transactions. The RFC allows it but emphasizes that the chain of responsibility should always be traceable back to a human or organization.

**Q9: Could an agent have or receive bitcoins?**
Yes, with nuances. On EVM: with ERC-4337 it can hold ETH, MATIC, ERC-20 tokens. For Bitcoin specifically: it can use wrapped BTC (WBTC) as ERC-20, or have an associated Bitcoin address in its document. Use case #5 of the RFC covers "agent-to-agent commerce with cryptographic non-repudiation". The current SDK is focused on identity; payment integration would be a natural extension.

**Q10: In A2A, how would communication and verification work?**
Bilateral verification: Alice signs her HTTP request with her Ed25519, includes `Signature-Agent` with her DID. Bob resolves Alice's DID, verifies the signature, verifies non-revocation. Bob responds by signing with his own key and including his own `Signature-Agent`. Alice verifies Bob the same way. Each side verifies authenticity, integrity, validity, and identity. The difference from A2A without DID: replaces shared API keys with cryptographic identity and non-repudiation.

---

### Module 4 Exercises

**Exercise 1:** The RFC defines 5 design principles. Without looking at the module, list all 5 and explain in your own words why each one is important.

**Student answer:**
1. Fixed identity, mutable state: The agent's DID never changes, but its configurations such as model, prompt, keys, etc. can change
2. Minimum on-chain: Only a minimum is stored on the blockchain, everything else goes in the DID document, which reduces costs and doesn't make all the agent's information public
3. Strong cryptography: The signature is verified by mathematics, the message is also verified by cryptography, as is the DID document, the model, and the prompt
4. Blockchain-agnostic: It's compatible with any EVM, Ethereum, Polygon, etc.
5. Interoperability: Any resolver can resolve the DID document

**Evaluation: 7.5/10**
- Principles 1-2: ✅ Correct with good examples
- Principle 3: ⚠️ Partial — failed to mention that Ed25519 comes **"by default"** (configured out of the box, without the developer choosing) and the specific recommended curve
- Principle 4: ⚠️ Partial — said "compatible with any EVM" but the principle says **blockchain-agnostic** (could work with Solana, Cosmos, Hyperledger, not just EVMs). EVM is only the reference implementation
- Principle 5: ⚠️ Partial — only mentioned resolvers, but interoperability is achieved through two mechanisms: **JSON-LD schema** (standardized format) + **universal resolution**

---

**Exercise 2:** Given the following DID Document, classify each field as REQUIRED or OPTIONAL.

**Student answer:**
| Field | Classification |
|---|---|
| `@context` | REQUIRED |
| `id` | REQUIRED |
| `controller` | REQUIRED |
| `created` | REQUIRED |
| `updated` | REQUIRED |
| `name` | OPTIONAL |
| `version` | OPTIONAL |
| `coreModelHash` | REQUIRED |
| `systemPromptHash` | REQUIRED |
| `capabilities` | OPTIONAL |
| `memberOf` | OPTIONAL |
| `complianceCertifications` | OPTIONAL |
| `verificationMethod` | REQUIRED |
| `authentication` | REQUIRED |

**Evaluation: 9.5/10**
- 14/14 fields correct. Excellent mastery of the normative table.
- Minor deduction for typo ("OPCTIONAL" in the original answer). In a presentation, these details matter.

---

**Exercise 3:** Explain in your own words the difference between controller and owner. Invent a realistic scenario where they are different persons/entities.

**Student answer:**
The controller is the one responsible for the agent and the owner is the one who has privileges to generate operations on the blockchain with the agent's wallet. Scenario: An agent has been created to deliver corporate financial data at certain morning hours without leaking information before the news, the agent's responsible party is corporation XYZ. The corporation has delegated to its IT department, specifically one of the engineers (owner), the registration and all blockchain operations for the agent.

**Evaluation: 8.0/10**
- Scenario: ✅ Excellent — realistic, well-constructed, demonstrates separation of responsibilities
- Definitions: ⚠️ The owner definition is imprecise: said "with the agent's wallet" — but the owner doesn't control the agent's wallet. The owner is the **EVM address that has operational control of the DID's registration in the smart contract** (can revoke, assign delegates, transfer ownership, update `documentRef`). The agent's wallet (if it has ERC-4337) is something separate.
- Key correction: Owner ≠ "controls the agent's wallet". Owner = "controls the DID's registration in the contract".

---

**Exercise 4:** Why is the architecture "hybrid" (on-chain + off-chain)? What would happen if you put the entire DID Document on blockchain? Mention at least 3 consequences.

**Student answer:**
The architecture is hybrid seeking to place the bare minimum on the blockchain (Minimum on-chain Principle) and the rest of the information in a reference document, the DID document, aiming for:
A. Reduce gas consumption
B. Not leave all information visible on the blockchain (more granular control of public and private information)
C. Speed, since blockchain operations take seconds, only critical operations are done here
D. Flexibility, if most information is in the DID Document, this reduces gas consumption and processing times for non-critical operations

**Evaluation: 7.5/10**
- Points A-C: ✅ Solid and correct (gas, privacy, speed)
- Point D: ⚠️ Overlaps with A and C (says the same thing differently)
- Missing mention: **Rigid immutability** — data on blockchain is permanent. If you put the prompt hash on blockchain and need to correct it, you must make another transaction (more gas). Off-chain you simply update the document.
- Missing figure: **Concrete cost** — storing 32 bytes on-chain ≈ 20,000 gas. A full DID Document could cost tens of dollars per registration.

---

**Exercise 5:** Trace the complete lifecycle of an agent: registration → use → evolution → key compromise → revocation → post-revocation verification.

**Student answer:** BPMN diagram with 4 independent flows (Registration, Verification, Revocation, Evolution).

**Evaluation: 6.5/10**
- ✅ Correctly identifies the 4 main flows with correct actors
- ✅ Clear and professional BPMN notation
- ✅ The verification flow shows TRUE/FALSE as output
- ⚠️ Lacks sequentiality: shows 4 independent flows instead of the connected cycle the exercise asked for (registration → use → evolution → compromise → revocation → post-revocation verification as a continuous story)
- ⚠️ Missing "key compromise" as a trigger for revocation
- ⚠️ Missing "post-revocation verification" (the crucial part: after revoking, someone verifies and the result is FAIL)
- ⚠️ Typo: "SKD" instead of "SDK" in the last flow

---

**Exercise 6:** The community asks you: "Why should I trust your specification if it's just a draft?" Respond in 30 seconds.

**Student answer:**
"It's not just a specification, it's a validated implementation and its 5 principles solve use cases that today are either not covered or generate external dependencies that we can solve independently with mathematics. We're using architectures, principles, and specifications that have already been widely validated/approved by organizations and the community (W3C, widely used and audited cryptographic algorithms, etc.). We're not inventing cryptography or starting from specifications from scratch, we're extending and taking puzzle pieces to solve AI agent decentralized identity."

**Evaluation: 8.0/10**
- ✅ "It's not just a specification, it's a validated implementation" — powerful opening
- ✅ "We're not inventing cryptography" — generates immediate trust
- ✅ "Extending puzzle pieces" — good metaphor
- ✅ Mentions standards validated by organizations and community
- ⚠️ Missing the killer data point: **"16 conformance controls, all PASS. You can verify it yourself with a single command: `npm run conformance:rfc001`"** — unbeatable executable evidence
- ⚠️ A bit long for 30 seconds. Suggested compact version: *"It's not just a draft — it's a functional implementation with 16 conformance controls, all verified. It's built on W3C DIDs, Ed25519, and Solidity — we didn't invent cryptography, we extend proven standards. And you can validate it yourself with one command: `npm run conformance:rfc001`."*

---

### Consolidated evaluation — Module 4

| Exercise | Grade | Strength | Area for improvement |
|-----------|------|-----------|----------------|
| 1. Design principles | 7.5 | Captures the essence | "blockchain-agnostic" ≠ "EVM-compatible" |
| 2. REQUIRED/OPTIONAL | 9.5 | 14/14 correct | Watch for typos in presentation |
| 3. Controller vs Owner | 8.0 | Excellent scenario | Owner ≠ "agent's wallet" |
| 4. Hybrid architecture | 7.5 | 3 solid points | Avoid redundancy, add immutability |
| 5. Lifecycle diagram | 6.5 | Professional notation | Lacks sequentiality and post-revocation |
| 6. 30-second response | 8.0 | Powerful opening | Add killer data point (16 controls PASS) |

**Module 4 Average: 7.8/10** ✅ Passed

**Overall progress:**

| Module | Average | Trend |
|--------|---------|-----------|
| Module 1 | 7.8/10 | — |
| Module 2 | 8.0/10 | ↑ |
| Module 3 | 7.2/10 | ↓ |
| Module 4 | 7.8/10 | ↑ |

**Analysis:** Conceptual understanding is solid and recovering. The strong point continues to be realistic scenarios and architectural vision. Areas for improvement: precision in technical details (blockchain-agnostic vs EVM-compatible, owner vs wallet), connecting flows as sequential story (not as isolated processes), and including demolishing quantitative data in presentation answers (16 controls, `npm run conformance:rfc001`). For the community, use the structure: **Statement → Verifiable data → Invitation to check it**.


---

## Module 5 — SDK Core: `AgentIdentity` Line by Line

### Learning objectives
- Master the main class `AgentIdentity` and its complete API
- Understand each method, its parameters, its internal flow, and its mapping to RFC-001
- Be able to explain the code with confidence
- Understand the facade + dependency injection pattern
- Understand the static vs instance separation and its technical rationale

### 5.1 General SDK architecture

The SDK has **4 layers**, organized as a pyramid of responsibilities:

```
┌───────────────────────────────────────────────┐
│            AgentIdentity (Facade)              │  ← Core Layer
│   The ONLY class the developer uses            │
│   All methods are static or instance           │
├───────────────────────────────────────────────┤
│              types.ts + time.ts                │  ← Types and utilities
│   TypeScript interfaces + temporal             │
│   normalization (SHOULD-02)                    │
├───────────────────────────────────────────────┤
│              crypto/hash.ts                    │  ← Crypto Layer
│   SHA-256 (ethers) for IP hashes               │
│   3 functions, ~20 lines                       │
├───────────────┬───────────────────────────────┤
│  Resolver     │         Registry              │  ← Infrastructure Layer
│  InMemory     │         InMemory              │
│  Universal    │         EvmAgentRegistry      │
│  HTTP Source  │         EthersContractClient   │
│  RPC Source   │                               │
└───────────────┴───────────────────────────────┘
```

**Design pattern: Facade with dependency injection**
- **Facade**: `AgentIdentity` is the only entry point. The developer never needs to touch the resolver, registry, or hash functions directly.
- **Dependency injection**: The resolver and registry are interchangeable. By default, `InMemoryDIDResolver` and `InMemoryAgentRegistry` are used (for testing), but you can substitute them with `UniversalResolverClient` and `EvmAgentRegistry` for production.

```typescript
// Testing (default, you don't need to do anything):
// resolver = InMemoryDIDResolver
// registry = InMemoryAgentRegistry

// Production — inject real implementations:
AgentIdentity.setResolver(myProductionResolver);
AgentIdentity.setRegistry(myEVMRegistry);
```

**Key point**: The same code in `create()`, `signMessage()`, `verifySignature()` works EXACTLY the same in testing and production. Only the infrastructure underneath changes.

### 5.2 The `types.ts` file — The data contract

`types.ts` is the **dictionary of the SDK** — it defines exactly what shape each object has. The main interfaces directly reflect the RFC-001 normative table (fields without `?` are REQUIRED, with `?` are OPTIONAL):

```typescript
interface AgentMetadata {
  name: string;
  description?: string;         // OPTIONAL
  version: string;
  coreModelHash: string;        // REQUIRED — hash://sha256/...
  systemPromptHash: string;     // REQUIRED — hash://sha256/...
  capabilities?: string[];      // OPTIONAL
  memberOf?: string;            // OPTIONAL
}

interface VerificationMethod {
  id: string;                   // "did:agent:polygon:0x...#key-1"
  type: string;                 // "Ed25519VerificationKey2020"
  controller: string;           // Controller's DID
  publicKeyMultibase?: string;  // "z6Mk..." (multicodec Ed25519 + base58btc)
  blockchainAccountId?: string; // "eip155:1:0x..." (for ERC-4337)
  deactivated?: string;         // ISO 8601 timestamp when key was deactivated
}

interface AgentDIDDocument {
  "@context": string[];
  id: string;
  controller: string;
  created: string;              // ISO-8601
  updated: string;              // ISO-8601
  agentMetadata: AgentMetadata;
  complianceCertifications?: VerifiableCredentialLink[];
  verificationMethod: VerificationMethod[];
  authentication: string[];     // IDs of active verification methods
}
```

**Input and output parameters:**

```typescript
// What you pass to create (plain text — the SDK hashes for you):
interface CreateAgentParams {
  name: string;
  coreModel: string;          // "GPT-4-Turbo" — the SDK hashes it
  systemPrompt: string;       // "You are..." — the SDK hashes it
  capabilities?: string[];
}

// What you receive:
interface CreateAgentResult {
  document: AgentDIDDocument;  // The complete document
  agentPrivateKey: string;     // The Ed25519 private key (hex) — KEEP IT SAFE!
}
```

### 5.3 The `hash.ts` file — The crypto layer

Only 3 functions, ~42 lines. The thinnest layer of the SDK:

```typescript
// 1. Hash a string → SHA-256 hex
function hashPayload(payload: string): string {
  const bytes = ethers.toUtf8Bytes(payload);  // String → UTF-8 bytes
  return ethers.sha256(bytes);                 // bytes → "0x1234abcd..."
}

// 2. Format the hash as URI
function formatHashUri(hashHex: string): string {
  const cleanHash = hashHex.startsWith('0x') ? hashHex.slice(2) : hashHex;
  return `hash://sha256/${cleanHash}`;         // "hash://sha256/1234abcd..."
}

// 3. Convenience: hash + format in one step
function generateAgentMetadataHash(payload: string): string {
  const rawHash = hashPayload(payload);
  return formatHashUri(rawHash);
}
```

It uses SHA-256 from ethers.js instead of another library because ethers is already a dependency for EVM interaction — dependency economy.

### 5.4 The `time.ts` file — Temporal normalization (SHOULD-02)

Solves the SHOULD-02 problem: the smart contract stores timestamps as Unix strings (`"1740787200"`), but the SDK needs ISO-8601 (`"2026-02-28T22:40:00Z"`):

```typescript
// Is it a Unix timestamp as string?
function isUnixTimestampString(value: string): boolean {
  return /^\d+$/.test(value.trim());  // Only digits = Unix
}

// Unix string → ISO-8601
function unixStringToIso(value: string): string {
  const seconds = Number(value);
  const date = new Date(seconds * 1000);  // Unix in seconds, JS uses milliseconds
  return date.toISOString();
}

// ISO-8601 → Unix string
function isoToUnixString(value: string): string {
  const ms = Date.parse(value);
  return Math.floor(ms / 1000).toString();
}

// Normalize: if Unix converts it, if already ISO leaves it
function normalizeTimestampToIso(value?: string): string | undefined {
  if (!value) return undefined;
  return isUnixTimestampString(value) ? unixStringToIso(value) : value;
}
```

`normalizeTimestampToIso` is smart — it automatically detects whether the value is Unix or ISO and always returns ISO. EVM adapters use it so the developer never sees Unix timestamps.

### 5.5 The `AgentIdentity` class — Static vs instance state

The class mixes static and instance state. This separation is an important design decision:

```typescript
export class AgentIdentity {
  // ═══ STATIC State (shared across the entire app) ═══
  private static resolver: DIDResolver = new InMemoryDIDResolver();
  private static registry: AgentRegistry = new InMemoryAgentRegistry();
  private static documentHistoryStore: Map<string, AgentDocumentHistoryEntry[]> = new Map();

  // ═══ INSTANCE State (per controller) ═══
  private signer: ethers.Signer;   // The controller's wallet
  private network: string;         // The blockchain network

  constructor(config: AgentIdentityConfig) {
    this.signer = config.signer;
    this.network = config.network || 'polygon';  // Default: Polygon
  }
}
```

| Type | What it stores | Why static/instance |
|------|-------------|---------------------------|
| `resolver` | Where to look for documents | **Static**: the entire app uses the same resolver |
| `registry` | Where to anchor DIDs | **Static**: the entire app uses the same registry |
| `documentHistoryStore` | Change history | **Static**: accessible without instance |
| `signer` | Controller's wallet | **Instance**: each controller has its wallet |
| `network` | Blockchain network | **Instance**: each agent can be on a different network |

**Practical consequence**: `create()` is **instance** (needs `this.signer` and `this.network`), but `verifySignature()`, `resolve()`, `revokeDid()` are **static** (they don't need a controller — anyone can verify).

### 5.6 `create()` — Line by line

The most important method of the SDK. Creates an agent's complete identity in 8 steps:

**Step 1: Get the Controller's address**
```typescript
const controllerAddress = await this.signer.getAddress();
const controllerDid = `did:ethr:${controllerAddress}`;
```
The `signer` is an ethers.js wallet of the human/organization. Its Ethereum address is obtained and converted to DID format.

**Step 2: Generate the agent's unique DID**
```typescript
const timestamp = new Date().toISOString();
const nonce = ethers.hexlify(ethers.randomBytes(16));  // 16 BYTES = 128 bits
const rawAgentId = ethers.keccak256(
  ethers.toUtf8Bytes(`${controllerAddress}-${timestamp}-${nonce}`)
);
const agentDid = `did:agent:${this.network}:${rawAgentId}`;
```
Three values are concatenated: controller address + timestamp + random nonce of **16 bytes** (128 bits of entropy). Hashed with Keccak-256 (Ethereum's native hash — consistency with the EVM ecosystem). The nonce prevents collisions if the same controller creates agents in the same millisecond.

**Step 3: Hash the IP (model and prompt)**
```typescript
const coreModelHashUri = generateAgentMetadataHash(params.coreModel);
const systemPromptHashUri = generateAgentMetadataHash(params.systemPrompt);
```
Plain text (`"GPT-4-Turbo"`, `"You are a support agent..."`) is converted to `hash://sha256/...`. The plain text **disappears** at this point — it is never stored.

**Step 4: Generate Ed25519 keys**
```typescript
const privateKeyBytes = ed25519.utils.randomPrivateKey();     // 32 random bytes
const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes); // Derive public
const privateKeyHex = bytesToHex(privateKeyBytes);            // → hex string
const publicKeyHex = bytesToHex(publicKeyBytes);              // → hex string
```
Here the agent's cryptographic identity is born. The private key is returned to the caller in `CreateAgentResult.agentPrivateKey`. **The SDK does not store it** — it is the developer's responsibility to store it securely (Key Vault, HSM, etc.). If lost, the agent cannot sign.

**Step 5: Generate EVM wallet (Account Abstraction)**
```typescript
const agentWallet = ethers.Wallet.createRandom();
```
Random EVM wallet for the `blockchainAccountId` — enables ERC-4337 if needed in the future. Independent of the Ed25519 keys.

**Step 6: Assemble the DID Document**
```typescript
const document: AgentDIDDocument = {
  "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
  id: agentDid,
  controller: controllerDid,
  created: timestamp,
  updated: timestamp,         // On creation, created === updated
  agentMetadata: { name, coreModelHash, systemPromptHash, capabilities, ... },
  verificationMethod: [verificationMethod],
  authentication: [verificationMethodId]    // #key-1
};
```
Complete JSON-LD document, RFC-001 compliant. Note: `created === updated` at the moment of creation.

**Step 7: Register in resolver + registry + history**
```typescript
AgentIdentity.resolver.registerDocument(document);        // Off-chain: store document
await AgentIdentity.registry.register(                     // On-chain: anchor DID
  document.id, document.controller, 
  AgentIdentity.computeDocumentReference(document)
);
AgentIdentity.appendHistory(document, 'created');          // History: first entry
```
Three simultaneous registrations: document to the resolver (off-chain), DID + controller + reference to the registry (on-chain), entry to history.

**Step 8: Return**
```typescript
return { document, agentPrivateKey: privateKeyHex };
```

### 5.7 `signMessage()` — The simplest signature

```typescript
public async signMessage(payload: string, agentPrivateKeyHex: string): Promise<string> {
  const messageBytes = new TextEncoder().encode(payload);     // String → UTF-8 bytes
  const privateKeyBytes = hexToBytes(agentPrivateKeyHex);     // Hex → bytes
  const signatureBytes = ed25519.sign(messageBytes, privateKeyBytes);  // Sign!
  return bytesToHex(signatureBytes);                           // bytes → hex (128 chars = 64 bytes)
}
```

4 lines. All the cryptographic power of Ed25519 in a trivial function.

### 5.8 `signHttpRequest()` — Web Bot Auth

Implements HTTP signing from RFC §6.5. Generates 5 headers:

```typescript
public async signHttpRequest(params: SignHttpRequestParams): Promise<Record<string, string>> {
  // Input validations
  if (!params.method?.trim()) throw new Error("HTTP method is required");
  if (!params.url?.trim()) throw new Error("HTTP URL is required");

  // 1. Prepare components
  const timestamp = Math.floor(Date.now() / 1000).toString();  // Unix seconds
  const dateHeader = new Date().toUTCString();                   // RFC 2822
  const contentDigest = AgentIdentity.computeContentDigest(params.body);

  // 2. Build the "signature base" (what gets signed)
  const stringToSign = AgentIdentity.buildHttpSignatureBase({...});

  // 3. Sign with Ed25519 and encode in base64
  const signatureHex = await this.signMessage(stringToSign, params.agentPrivateKey);
  const signatureBase64 = Buffer.from(hexToBytes(signatureHex)).toString('base64');

  // 4. Return the 5 headers
  return {
    'Signature':       `sig1=:${signatureBase64}:`,
    'Signature-Input': `sig1=("@request-target" "host" "date" "content-digest");created=${timestamp};keyid="${verificationMethodId}";alg="ed25519"`,
    'Signature-Agent': params.agentDid,
    'Date':            dateHeader,
    'Content-Digest':  contentDigest
  };
}
```

**The "signature base" — what exactly gets signed:**
```
(request-target): post /api/data
host: api.example.com
date: Thu, 07 Mar 2026 15:30:00 GMT
content-digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
```

If any character changes (method, URL, date, or body), the signature is invalidated.

**Note on encodings:** Content-Digest uses base64 because RFC 9530 (HTTP Digest Fields) dictates it. The internal signature from `signMessage()` uses hex by convention of the crypto/EVM ecosystem. Each format is dictated by the standard of the context where it's used.

### 5.9 `verifyHttpRequestSignature()` — The complete verification

The most complex method of the SDK (~80 lines). It has **7 gates** (failure points):

```
HTTP Verification
      │
 Gate 1: Are all 5 headers present?
      │ (Signature, Signature-Input, Signature-Agent, Date, Content-Digest)
      │ If any missing → return false
      │
 Gate 2: Does Content-Digest match the body?
      │ Recalculate SHA-256 of body and compare
      │ If mismatch → return false
      │
 Gate 3: Parse Signature-Input dictionary
      │ Extract label, components, keyid, created, alg
      │
 Gate 4: Does it have keyid and created?
      │ If missing → skip this signature
      │
 Gate 5: Does it cover the 4 required components?
      │ (@request-target, host, date, content-digest)
      │ If any missing → skip
      │
 Gate 6: Is the timestamp within allowed skew?
      │ Default: ±300 seconds (5 minutes)
      │ If outside → skip (possible replay attack)
      │
 Gate 7: Does keyid belong to Signature-Agent?
      │ keyid must start with "${signatureAgent}#"
      │ If not → skip
      │
 Final cryptographic verification:
      │ Reconstruct signature base → verifySignature()
      │ Internally: resolve DID → get publicKey → ed25519.verify()
      │
      ▼
  true (if any signature verifies) / false (if none do)
```

The method supports **multiple signatures** in a single request (`sig1`, `sig2`, etc.) — useful for multi-signature scenarios like bilateral A2A approval, agent+controller co-signing, inter-organizational transactions, and audit witness.

### 5.10 `verifySignature()` — The base verification

```typescript
public static async verifySignature(
  did: string, payload: string, signature: string, keyId?: string
): Promise<boolean> {
  // 1. Is it revoked? → FAIL immediately
  const isRevoked = await AgentIdentity.registry.isRevoked(did);
  if (isRevoked) return false;

  // 2. Resolve the DID Document
  const didDoc = await AgentIdentity.resolve(did);

  // 3. Filter candidate verification methods
  const activeKeyIds = new Set(didDoc.authentication || []);
  const candidateMethods = didDoc.verificationMethod.filter((method) => {
    if (!method.publicKeyMultibase) return false;
    if (keyId) return method.id === keyId && activeKeyIds.has(method.id);
    return activeKeyIds.has(method.id);
  });

  // 4. Try each candidate
  for (const vm of candidateMethods) {
    const publicKeyHex = vm.publicKeyMultibase!.startsWith('z')
      ? vm.publicKeyMultibase!.slice(1) : vm.publicKeyMultibase!;
    const valid = ed25519.verify(signatureBytes, messageBytes, hexToBytes(publicKeyHex));
    if (valid) return true;
  }
  return false;
}
```

**Why verify revocation BEFORE resolving?** Two reasons:
1. **Security**: A revoked DID is a dead identity — it doesn't matter if the signature is mathematically valid
2. **Efficiency**: `isRevoked()` is a simple query to the registry. If revoked, you save the cost of resolving the complete document (HTTP requests, IPFS lookups, etc.)

### 5.11 `resolve()` and `revokeDid()`

```typescript
// Resolve: finds the document, but first verifies it's not revoked
public static async resolve(did: string): Promise<AgentDIDDocument> {
  const isRevoked = await AgentIdentity.registry.isRevoked(did);
  if (isRevoked) throw new Error(`DID is revoked: ${did}`);  // Throws error (doesn't silence)
  return AgentIdentity.resolver.resolve(did);
}

// Revoke: marks as revoked and records in history
public static async revokeDid(did: string): Promise<void> {
  const existing = await AgentIdentity.resolve(did);
  await AgentIdentity.registry.revoke(did);
  AgentIdentity.appendHistory(existing, 'revoked');
}
```

`resolve()` throws an **error** if revoked (unlike `verifySignature()` which returns `false`). Intentional: if something tries to resolve a revoked DID, it's an error that must propagate.

### 5.12 `updateDidDocument()` — Document evolution

```typescript
public static async updateDidDocument(
  did: string, patch: UpdateAgentDocumentParams
): Promise<AgentDIDDocument> {
  const existing = await AgentIdentity.resolve(did);
  const now = new Date().toISOString();

  const updatedDocument: AgentDIDDocument = {
    ...existing,
    updated: now,
    agentMetadata: {
      ...existing.agentMetadata,
      description: patch.description ?? existing.agentMetadata.description,
      version: patch.version ?? existing.agentMetadata.version,
      coreModelHash: patch.coreModel
        ? generateAgentMetadataHash(patch.coreModel)  // Re-hash if changed
        : existing.agentMetadata.coreModelHash,
      // ... same for systemPrompt, capabilities, memberOf
    }
  };

  AgentIdentity.resolver.registerDocument(updatedDocument);
  await AgentIdentity.registry.setDocumentReference(did, ...);
  AgentIdentity.appendHistory(updatedDocument, 'updated');
  return updatedDocument;
}
```

The `??` pattern (nullish coalescing): if the patch brings a value, it's used. If it's `null`/`undefined`, the current one is kept. If you change `coreModel`, the SDK re-hashes it automatically — you pass plain text, not the hash.

### 5.13 `rotateVerificationMethod()` — Key rotation

```typescript
public static async rotateVerificationMethod(did: string): Promise<RotateVerificationMethodResult> {
  const existing = await AgentIdentity.resolve(did);

  // 1. Calculate next index (#key-2, #key-3, etc.)
  const nextIndex = Math.max(...keyIndexes) + 1;

  // 2. Generate NEW Ed25519 key
  const privateKeyBytes = ed25519.utils.randomPrivateKey();
  const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);

  // 3. Updated document
  const updatedDocument = {
    ...existing,
    updated: new Date().toISOString(),
    verificationMethod: [...existing.verificationMethod, newVerificationMethod],  // APPENDS
    authentication: [verificationMethodId]  // REPLACES (only the new one)
  };

  // 4. Register
  AgentIdentity.resolver.registerDocument(updatedDocument);
  await AgentIdentity.registry.setDocumentReference(did, ...);
  AgentIdentity.appendHistory(updatedDocument, 'rotated-key');

  return { document: updatedDocument, verificationMethodId, agentPrivateKey: privateKeyHex };
}
```

**The critical detail:**
- `verificationMethod` **accumulates** — the old key (#key-1) remains for historical signature verification
- `authentication` **replaces** — only the new key (#key-2) is valid for new signatures

Why not delete the old key? If an agent signed a contract 3 months ago with #key-1, you need the public key to verify that contract. By keeping it in `verificationMethod` (but out of `authentication`), you can verify historical signatures by searching for `keyId="#key-1"`.

### 5.14 `getDocumentHistory()` — Traceability (SHOULD-05)

```typescript
public static getDocumentHistory(did: string): AgentDocumentHistoryEntry[] {
  const history = AgentIdentity.documentHistoryStore.get(did) || [];
  return JSON.parse(JSON.stringify(history));  // Deep clone for immutability
}
```

Each action adds an entry via `appendHistory()`:
```
Revision 1: created     → 2026-03-01T00:00:00Z → v1.0.0
Revision 2: updated     → 2026-03-15T00:00:00Z → v1.1.0 (changed model)
Revision 3: rotated-key → 2026-04-01T00:00:00Z → v1.1.0 (rotated key)
Revision 4: revoked     → 2026-06-01T00:00:00Z → v1.1.0 (compromised)
```

**Current storage state**: History is stored in a static `Map` in RAM — it's lost when the process terminates. In production it should be migrated to a persistent backend (IPFS for immutable documents + database for queries + on-chain events for registry operations). The SHOULD-05 checklist acknowledges it: *"Maintain historical persistence when migrating to external backend"*.

### 5.15 Dependency injection — From testing to production

```typescript
// Change resolver and registry:
public static setResolver(resolver: DIDResolver): void { ... }
public static setRegistry(registry: AgentRegistry): void { ... }

// Pre-configured production profiles:
public static useProductionResolverFromHttp(config): void { ... }
public static useProductionResolverFromJsonRpc(config): void { ... }
public static useProductionResolver(config): void { ... }
```

| Method | Source | Use |
|--------|--------|-----|
| `useProductionResolverFromHttp()` | HTTP/HTTPS + IPFS gateways | Documents on HTTP or IPFS |
| `useProductionResolverFromJsonRpc()` | JSON-RPC 2.0 | Centralized/decentralized RPC service |
| `useProductionResolver()` | Custom | Your own implementation |

All internally create a `UniversalResolverClient` with: registry + documentSource + fallback (InMemory) + cache + observability.

### 5.16 The `index.ts` — What gets exported

```typescript
export { AgentMetadata, AgentDIDDocument, CreateAgentParams, ... } from './core/types';
export { AgentIdentity, AgentIdentityConfig, ... } from './core/AgentIdentity';
```

Only the **types** and the **`AgentIdentity` class**. Internal layers (hash.ts, time.ts, resolvers, registries) are implementation details — the SDK consumer doesn't see them directly.

### 5.17 Visual summary — Complete flow

```
┌─ Developer ────────────────────────────────────────────────────┐
│                                                                │
│  const identity = new AgentIdentity({ signer: wallet });       │
│  const { document, agentPrivateKey } = await identity.create({ │
│    name: 'Bot', coreModel: 'GPT-4', systemPrompt: '...'       │
│  });                                                           │
│                                                                │
│  ┌─ create() internally ────────────────────────────────────┐  │
│  │  1. wallet.getAddress() → controllerDid                  │  │
│  │  2. keccak256(addr+time+nonce) → agentDid                │  │
│  │  3. generateAgentMetadataHash() → IP hashes              │  │
│  │  4. ed25519.utils.randomPrivateKey() → keypair           │  │
│  │  5. Assemble DID Document JSON-LD                        │  │
│  │  6. resolver.registerDocument() → off-chain              │  │
│  │  7. registry.register() → on-chain                       │  │
│  │  8. appendHistory('created')                             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  const sig = await identity.signMessage('hello', privateKey);  │
│  ┌─ signMessage() ───────────────────────────────┐             │
│  │  TextEncoder.encode → ed25519.sign → bytesToHex│            │
│  └────────────────────────────────────────────────┘            │
│                                                                │
│  const ok = await AgentIdentity.verifySignature(did, 'hello',  │
│    sig);                                                       │
│  ┌─ verifySignature() ──────────────────────────────────────┐  │
│  │  1. isRevoked(did)? → false ✓                            │  │
│  │  2. resolve(did) → DID Document                          │  │
│  │  3. Filter authentication → candidateMethods             │  │
│  │  4. ed25519.verify(sig, msg, pubKey) → true ✓            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  await AgentIdentity.revokeDid(did);                           │
│  ┌─ revokeDid() ──────────────────────────────┐               │
│  │  1. resolve(did) → verify it exists         │               │
│  │  2. registry.revoke(did) → on-chain         │               │
│  │  3. appendHistory('revoked')                │               │
│  └─────────────────────────────────────────────┘               │
│                                                                │
│  const ok2 = await AgentIdentity.verifySignature(did, ...);    │
│  // → false (revoked — gate 1 stops it)                        │
└────────────────────────────────────────────────────────────────┘
```

### Talking Points for the community
- *"The SDK uses the facade pattern: a single class `AgentIdentity` exposes all functionality"*
- *"Dependencies are minimal and audited — @noble/curves for crypto, ethers for EVM"*
- *"Dependency injection allows using the same SDK in testing (InMemory) and production (EVM + HTTP) without changing a single line of logic"*
- *"Document history provides complete traceability — every change is recorded with action, timestamp, and reference"*
- *"HTTP verification has 7 security gates — from header presence to temporal skew anti-replay"*
- *"Rotated keys are not removed from the document — they maintain the ability to verify historical signatures"*

---

### Module 5 Questions and Answers

**Q1: What example cases can have multi-signature scenarios?**
The SDK supports multiple signatures because `verifyHttpRequestSignature()` parses the `Signature-Input` as a dictionary with `sig1`, `sig2`, etc. Real scenarios:
- **Bilateral A2A approval**: Analyst agent (sig1) + supervisor agent (sig2) both sign a purchase order
- **Agent + controller co-signing**: Critical operations (>$10K) require the agent's signature + human controller approval
- **Inter-organizational transaction**: Company A agent (sig1) proposes a purchase, company B agent (sig2) accepts — both signatures in the final request to the escrow
- **Audit witness**: Operational agent (sig1) + auditor agent (sig2) for sensitive records (PII, medical data)
- **Agent quorum**: 3 of 5 agents must agree on a diagnosis to validate the request

Note: The current SDK verifies that at least one signature is valid. For "all must verify" or "N of M" policies, additional logic would be needed — candidate for extension.

**Q2: The change history, where is it stored? Off-chain?**
Currently in **RAM** (a static `Map<string, AgentDocumentHistoryEntry[]>`). It's lost when the process terminates. In production, the recommended strategy is a **hybrid** model: documents in IPFS (immutable with CID) + index in database (fast queries) + on-chain events (AgentRegistered, AgentRevoked, etc. that already exist as implicit history on the blockchain). The SHOULD-05 checklist acknowledges this pending migration.

---

### Module 5 Exercises

**Exercise 1:** In `create()`, why is `keccak256` used to generate the DID and not `SHA-256`? What would happen if two controllers create an agent in the same millisecond?

**Student answer:**
Keccak256 is native to Ethereum, which is already a dependency for EVM interaction, using another library to perform the same job is unnecessary (dependency economy). The implementation in agent DID creation contains the generation of a random 16-bit nonce to prevent collisions in the same millisecond.

**Evaluation: 7.5/10**
- ✅ Keccak-256 native to Ethereum and dependency economy — correct
- ✅ Random nonce prevents collisions — correct
- ⚠️ Said "16 bits" — they are **16 bytes** (128 bits). `ethers.randomBytes(16)` generates 16 bytes. 16 bits = 65,536 combinations (insecure). 16 bytes = 2¹²⁸ combinations (practically impossible to collide).
- ⚠️ Missing mention of **ecosystem consistency**: Ethereum addresses themselves are derived from Keccak-256, using SHA-256 for the DID would be inconsistent with the `0x...` format of the EVM ecosystem

---

**Exercise 2:** The SDK returns `agentPrivateKey` in `CreateAgentResult`. Where should it be stored? What happens if it's lost?

**Student answer:**
There are several solutions, for example Azure Key Vault, or the corresponding mechanism in each cloud (Amazon, Oracle, Google). It's essential that private key storage is treated with utmost care and protection and it's the programmer/architect's responsibility. If lost, the agent loses the ability to sign and therefore its identity cannot be verified.

**Evaluation: 8.5/10**
- ✅ Azure Key Vault as a concrete example and multi-cloud equivalents
- ✅ Developer/architect responsibility
- ✅ Correct consequence: no key = no signature
- ⚠️ Missing mention of **HSMs** (Hardware Security Modules) — dedicated physical hardware, maximum security level
- ⚠️ Important detail: `rotateVerificationMethod()` can be executed to generate a new key BEFORE losing the old one. If you've already completely lost it without backup, the agent's identity is effectively dead

---

**Exercise 3:** In `verifySignature()`, in what real scenario would there be more than one candidate? Trace step by step.

**Student answer:**
There is more than one `candidateMethods` when there has been key rotation. When a specific `keyId` is passed, that candidate is directly tested; if not, all active signatures in `authentication` are tested.

**Evaluation: 6.0/10**
- ✅ Identifies rotation as the scenario
- ✅ Behavior with/without keyId correct
- ⚠️ Did not trace step by step as the exercise asked
- ⚠️ Conceptual error: after `rotateVerificationMethod()`, `authentication` only contains the new key. The old key remains in `verificationMethod` but no longer in `authentication`, so the filter `activeKeyIds.has(method.id)` will only match ONE key. The `for` loop exists as defensive design for the general case (custom implementations with multiple simultaneously active keys)

---

**Exercise 4:** After rotation, what happens with `verificationMethod` and `authentication`? Why isn't the old key deleted?

**Student answer:**
The array appends (accumulates), the old key continues in the document as a historical reference and in `authentication` the `verificationMethodId` is replaced.

**Evaluation: 7.0/10**
- ✅ `verificationMethod` accumulates and `authentication` replaces — correct
- ✅ Historical reference — partially correct
- ⚠️ Missing the main functional reason: the old key is maintained to **verify old signatures**. If an agent signed something with #key-1 three months ago and then rotated to #key-2, you need the #key-1 public key to verify that historical signature. Without it in the document, you lose that capability.

---

**Exercise 5:** Why does Content-Digest use base64 and `signMessage()` return hex? What standard dictates each format?

**Student answer:**
Content-Digest guarantees that the message has not been modified, while signMessage signs the message with the private key. The first seeks integrity; the second seeks authenticity.

**Evaluation: 3.5/10**
- ⚠️ Answered a different question. The question was about **encoding** (representation format: base64 vs hex), not about function (integrity vs authenticity).
- Expected answer: Content-Digest uses base64 because RFC 9530 (HTTP Digest Fields) and RFC 8941 (HTTP Structured Fields) dictate it — binary values in HTTP headers go in base64. signMessage() uses hex by convention of the crypto/EVM ecosystem — all tools (ethers.js, @noble/curves, 0x... addresses) expect hex. It's not an arbitrary decision: each format is dictated by the standard of its context.

---

**Exercise 6:** Why is `verifySignature()` `static` but `create()` is instance?

**Student answer:**
`verifySignature` doesn't require an instance, it's resolution and mathematics. `create` requires generating a concrete instance of an agent DID Document specific to the agent.

**Evaluation: 6.5/10**
- ✅ Correct direction: verify doesn't need instance, create does
- ⚠️ Missing the concrete technical reason: `create()` needs `this.signer` (the controller's wallet) and `this.network` (the blockchain network) — instance properties. `verifySignature()` only needs `resolver` and `registry` which are static. It's not that create needs "an agent instance" (the agent doesn't exist yet) but that it needs to know **who** creates it (signer) and **where** (network).

---

### Consolidated evaluation — Module 5

| Exercise | Grade | Strength | Area for improvement |
|-----------|------|-----------|----------------|
| 1. keccak256 vs SHA-256 | 7.5 | Dependency economy | 16 bytes ≠ 16 bits, ecosystem consistency |
| 2. Private key storage | 8.5 | Multi-cloud examples | HSMs, rotate-before-lost |
| 3. Multiple candidateMethods | 6.0 | Identifies rotation | Did not trace step by step |
| 4. verificationMethod vs authentication | 7.0 | Correct mechanism | Missing functional reason (historical signatures) |
| 5. Base64 vs hex | 3.5 | — | Answered function instead of encoding |
| 6. Static vs instance | 6.5 | Correct direction | Missing this.signer and this.network |

**Module 5 Average: 6.5/10** ✅ Passed

**Overall progress:**

| Module | Average | Trend |
|--------|---------|-----------|
| Module 1 | 7.8/10 | — |
| Module 2 | 8.0/10 | ↑ |
| Module 3 | 7.2/10 | ↓ |
| Module 4 | 7.8/10 | ↑ |
| Module 5 | 6.5/10 | ↓ |

**Analysis:** This was the most technical module and it shows in the results. Strengths continue to be architectural decisions (exercises 1 and 2). Critical areas for improvement: (1) **Unit precision** — 16 bits vs 16 bytes is an 8x error that matters a lot in a technical/presentation context; (2) **Read exactly what is being asked** — exercise 5 asked about encoding format and the answer addressed function; before the community, distinguishing these layers is fundamental; (3) **Trace flows step by step** — when an exercise asks for sequence, follow the code line by line, don't answer generally. Advice: **Statement → Concrete variable/code line → Consequence**.


---

## Module 6 — Resolvers and Registry: From Local to Production

### Learning objectives
- Understand the 4 types of resolvers available
- Master the UniversalResolverClient architecture
- Understand HTTP and JSON-RPC as document sources
- Know the registry system (InMemory and EVM)
- Understand caching, failover, and observability

### 6.1 What problem do Resolvers and Registries solve?

`AgentIdentity` uses two static dependencies:

```typescript
private static resolver: DIDResolver = new InMemoryDIDResolver();
private static registry: AgentRegistry = new InMemoryAgentRegistry();
```

They are the **two legs** of the identity system:

```
                    ┌──────────────────────────────────────────┐
                    │          AgentIdentity (Facade)           │
                    └──────┬──────────────────────┬────────────┘
                           │                      │
                    ┌──────▼──────┐        ┌──────▼──────┐
                    │  RESOLVER   │        │  REGISTRY   │
                    │             │        │             │
                    │ "Who is     │        │ "Does it    │
                    │  this DID?" │        │  exist?     │
                    │             │        │  Is it      │
                    │ Returns the │        │  revoked?"  │
                    │ COMPLETE    │        │             │
                    │ DID Document│        │ Returns the │
                    │ (off-chain) │        │ MINIMAL     │
                    │             │        │ ANCHOR      │
                    │             │        │ (on-chain)  │
                    └─────────────┘        └─────────────┘
```

**Analogy**: The **Registry** is like the civil registry — it knows "this person exists, was born on this date, is alive or dead". The **Resolver** is like your complete medical record — it has all the details, but you need to know where to look for it.

The separation has an economic reason: storing data on-chain costs gas. The **registry** only stores the minimum on-chain (DID + controller + reference). The **resolver** stores the complete document off-chain (HTTP, IPFS, JSON-RPC) where it's free or very cheap.

### 6.2 The interfaces — The contract every implementation must fulfill

#### `DIDResolver` — 3 methods

```typescript
// sdk/src/resolver/types.ts
export interface DIDResolver {
  registerDocument(document: AgentDIDDocument): void;  // Store document
  resolve(did: string): Promise<AgentDIDDocument>;      // Find document by DID
  remove(did: string): void;                             // Delete document
}
```

#### `DIDDocumentSource` — The document source

```typescript
export interface DIDDocumentSource {
  getByReference(documentRef: string): Promise<AgentDIDDocument | null>;
  storeByReference?(documentRef: string, document: AgentDIDDocument): Promise<void>;  // Optional
}
```

`storeByReference` is **optional** (`?`) because some sources are read-only (e.g., public IPFS).

#### `AgentRegistry` — 5 methods

```typescript
// sdk/src/registry/types.ts
export interface AgentRegistryRecord {
  did: string;
  controller: string;
  createdAt: string;
  revokedAt?: string;      // undefined if alive
  documentRef?: string;     // Reference to document (hash for off-chain lookup)
}

export interface AgentRegistry {
  register(did: string, controller: string, documentRef?: string): Promise<void>;
  setDocumentReference(did: string, documentRef: string): Promise<void>;
  revoke(did: string): Promise<void>;
  getRecord(did: string): Promise<AgentRegistryRecord | null>;
  isRevoked(did: string): Promise<boolean>;
}
```

All methods are `async` (`Promise`) because real implementations (EVM) involve blockchain transactions.

#### `EvmAgentRegistryContract` — The EVM contract

```typescript
// sdk/src/registry/evm-types.ts
export interface EvmTxResponse {
  wait?: () => Promise<unknown>;  // Wait for block confirmation
}

export interface EvmAgentRegistryContract {
  registerAgent(did: string, controller: string, documentRef?: string): Promise<EvmTxResponse | void>;
  setDocumentRef(did: string, documentRef: string): Promise<EvmTxResponse | void>;
  revokeAgent(did: string): Promise<EvmTxResponse | void>;
  getAgentRecord(did: string): Promise<AgentRegistryRecord | null>;
  isRevoked?(did: string): Promise<boolean>;  // OPTIONAL
}
```

`isRevoked` is **optional** in this interface because not all Solidity contracts implement a dedicated `isRevoked()` function. If it doesn't exist, `EvmAgentRegistry` calculates it from `getAgentRecord()` by checking `record.revokedAt`.

### 6.3 `InMemoryDIDResolver` — The testing resolver

~25 lines, the simplest file in the SDK:

```typescript
export class InMemoryDIDResolver implements DIDResolver {
  private readonly documentStore = new Map<string, AgentDIDDocument>();

  public registerDocument(document: AgentDIDDocument): void {
    // Deep clone on WRITE: prevents the caller from mutating the store
    this.documentStore.set(document.id, JSON.parse(JSON.stringify(document)));
  }

  public async resolve(did: string): Promise<AgentDIDDocument> {
    const document = this.documentStore.get(did);
    if (!document) throw new Error(`DID not found: ${did}`);
    // Deep clone on READ: prevents the receiver from mutating the store
    return JSON.parse(JSON.stringify(document));
  }

  public remove(did: string): void {
    this.documentStore.delete(did);
  }
}
```

**Double Deep Clone**: Clones on write and on read. Write-cloning protects against post-write mutation (the caller modifies the original object after registering it). Read-cloning protects against post-read mutation (the receiver modifies the returned object and corrupts the internal store).

### 6.4 `UniversalResolverClient` — The production resolver

Coordinates 4 pieces:

```
┌─ UniversalResolverClient ────────────────────────────────────┐
│                                                               │
│   ┌──────────┐    ┌──────────┐    ┌───────────────┐          │
│   │  CACHE   │    │ REGISTRY │    │ DOCUMENT      │          │
│   │ Map +TTL │    │ (on-chain│    │ SOURCE        │          │
│   │ hits/    │    │  lookup) │    │ (HTTP/RPC/    │          │
│   │ misses   │    │          │    │  IPFS)        │          │
│   └──────────┘    └──────────┘    └───────────────┘          │
│                                                               │
│   ┌──────────────────────┐    ┌───────────────────────────┐  │
│   │ FALLBACK RESOLVER    │    │ OBSERVABILITY             │  │
│   │ (InMemory or custom) │    │ onResolutionEvent()       │  │
│   └──────────────────────┘    └───────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

**Configuration:**

```typescript
export interface UniversalResolverConfig {
  registry: AgentRegistry;                    // REQUIRED: where to look for records
  documentSource: DIDDocumentSource;          // REQUIRED: where to look for documents
  fallbackResolver?: DIDResolver;             // OPTIONAL: plan B
  cacheTtlMs?: number;                        // OPTIONAL: cache TTL (default 60_000ms)
  onResolutionEvent?: (event) => void;        // OPTIONAL: observability callback
}
```

**`resolve()` flow step by step:**

```
resolve("did:agent:polygon:0xABC123")
      │
      ▼
 ┌─ STEP 1: Cache ──────────────────────────────────────────────┐
 │  const cached = this.cache.get(did);                         │
 │  if (cached && cached.expiresAt > Date.now()) {              │
 │    this.hits++;  emit('cache-hit');                           │
 │    return clone(cached.document);  ← FAST PATH (~0ms)        │
 │  }                                                           │
 │  this.misses++;  emit('cache-miss');                          │
 └───────────────┬──────────────────────────────────────────────┘
                 │ (no cache or expired)
                 ▼
 ┌─ STEP 2: Registry Lookup ────────────────────────────────────┐
 │  emit('registry-lookup');                                    │
 │  const record = await this.registry.getRecord(did);          │
 │  if (!record)        → resolveWithFallback("not found")      │
 │  if (!record.docRef) → resolveWithFallback("no docRef")      │
 └───────────────┬──────────────────────────────────────────────┘
                 │ (has documentRef)
                 ▼
 ┌─ STEP 3: Document Source Fetch ──────────────────────────────┐
 │  emit('source-fetch', documentRef=...);                      │
 │  const resolved = await documentSource.getByReference(ref)   │
 │    .catch(() → resolveWithFallback());                       │
 │  if (!resolved)           → resolveWithFallback()            │
 │  if (resolved.id !== did) → throw Error("DID mismatch")     │
 │                         ↑ SECURITY: anti-spoofing            │
 └───────────────┬──────────────────────────────────────────────┘
                 │ (valid document)
                 ▼
 ┌─ STEP 4: Cache + Return ─────────────────────────────────────┐
 │  this.cache.set(did, { document, expiresAt: now + TTL });    │
 │  emit('resolved');                                           │
 │  return clone(resolved);                                     │
 └──────────────────────────────────────────────────────────────┘
```

**Anti-spoofing verification:** `if (resolved.id !== did) throw Error("DID mismatch")` — without this check, a malicious server could return ANOTHER agent's document → impersonation. Guarantees the document belongs exactly to the requested DID.

**Fallback mechanism:** If the document source fails, it tries the fallback resolver. The fallback result **is also cached** — if the primary source went down and thousands of requests come in, only the first one hits the fallback.

**Cache TTL (default 60s):** Balance between reflecting changes quickly (like key rotation) and performance. Low TTL (5s) = more calls to registry; high TTL (10min) = key rotations take longer to propagate.

**Observability — `onResolutionEvent`:**

```typescript
interface ResolverResolutionEvent {
  did: string;
  stage: 'cache-hit' | 'cache-miss' | 'registry-lookup' | 'source-fetch' 
       | 'source-fetched' | 'fallback' | 'resolved' | 'error';
  durationMs: number;
  message?: string;
}
```

Allows building monitoring dashboards: each stage emits an event with duration in milliseconds. Ideal for detecting latencies in registry lookup, slowness in document source, or excess fallbacks.

**`getCacheStats()`:** Returns `{ hits, misses, size }`. A low hit ratio indicates TTL too short or too many unique DIDs.

### 6.5 `HttpDIDDocumentSource` — Documents via HTTP/IPFS

```typescript
export class HttpDIDDocumentSource implements DIDDocumentSource {
  constructor(config: HttpDIDDocumentSourceConfig = {}) {
    this.referenceToUrl = config.referenceToUrl || ((ref) => ref);       // Default: ref IS the URL
    this.referenceToUrls = config.referenceToUrls;
    this.fetchFn = config.fetchFn || globalThis.fetch;                    // Default: native fetch
    this.ipfsGateways = config.ipfsGateways || [
      'https://cloudflare-ipfs.com/ipfs/',
      'https://ipfs.io/ipfs/'
    ];
  }
}
```

**Candidate URL resolution — IPFS logic:**

```typescript
private resolveCandidateUrls(documentRef: string): string[] {
  if (this.referenceToUrls) return this.referenceToUrls(documentRef);  // Custom

  if (documentRef.startsWith('ipfs://')) {
    const cidPath = documentRef.slice('ipfs://'.length).replace(/^\/+/, '');
    return this.ipfsGateways.map((gw) => `${gw}${cidPath}`);
    // "ipfs://QmABC123" → ["https://cloudflare-ipfs.com/ipfs/QmABC123",
    //                       "https://ipfs.io/ipfs/QmABC123"]
  }

  return [this.referenceToUrl(documentRef)];  // The reference IS the URL
}
```

A reference `ipfs://QmABC123` is converted into **multiple URLs** (one per gateway) — free failover.

**Fetch algorithm with failover:** Tries each URL sequentially. Three possible outcomes:
1. **OK** → returns the document
2. **All 404** → returns `null` (doesn't exist, not an error — perhaps not yet published)
3. **Real error (500, timeout, network)** → throws error (infrastructure problem that must propagate)

**`fetchFn` injection:** For testing (mock without real HTTP), Node.js < 18 (no native fetch), or custom (interceptors, retry, logging).

### 6.6 `JsonRpcDIDDocumentSource` — Documents via JSON-RPC 2.0

```typescript
export class JsonRpcDIDDocumentSource implements DIDDocumentSource {
  constructor(config: JsonRpcDIDDocumentSourceConfig = {}) {
    this.endpoints = config.endpoints || (config.endpoint ? [config.endpoint] : []);
    this.method = config.method || 'agent_resolveDocumentRef';
    this.buildParams = config.buildParams || ((ref) => [ref]);
    this.transport = config.transport || this.defaultTransport;
    this.headers = { 'content-type': 'application/json', ...(config.headers || {}) };

    if (this.endpoints.length === 0) throw new Error('requires at least one endpoint');
  }
}
```

**JSON-RPC 2.0 protocol:**

```json
// Request:
{ "jsonrpc": "2.0", "id": 1709830000000, "method": "agent_resolveDocumentRef",
  "params": ["hash://sha256/abc123..."] }

// Success response:
{ "result": { "@context": [...], "id": "did:agent:polygon:0x...", ... } }

// Error response:
{ "error": { "code": -32004, "message": "Document not found" } }
```

- **Multi-endpoint failover:** tries each endpoint sequentially
- **Codes `-32004` and `404`**: treated as "not found" (skip, not error)
- **Custom transport/headers:** injectable for auth tokens, retry, logging
- **Fail-fast:** if no endpoints are configured, throws error in the constructor

### 6.7 `InMemoryAgentRegistry` — The testing registry

```typescript
export class InMemoryAgentRegistry implements AgentRegistry {
  private readonly records = new Map<string, AgentRegistryRecord>();

  async register(did, controller, documentRef?): Promise<void> {
    if (this.records.get(did)) return;  // IDEMPOTENT: no error if already exists
    this.records.set(did, { did, controller, createdAt: new Date().toISOString(), documentRef });
  }

  async setDocumentReference(did, documentRef): Promise<void> {
    if (!this.records.get(did)) throw new Error(`DID not found: ${did}`);  // GUARD
    this.records.set(did, { ...existing, documentRef });
  }

  async revoke(did): Promise<void> {
    if (!this.records.get(did)) throw new Error(`DID not found: ${did}`);  // GUARD
    this.records.set(did, { ...existing, revokedAt: new Date().toISOString() });
  }

  async getRecord(did): Promise<AgentRegistryRecord | null> {
    return this.records.get(did) || null;
  }

  async isRevoked(did): Promise<boolean> {
    return Boolean(this.records.get(did)?.revokedAt);
  }
}
```

**`register()` idempotent, `setDocumentReference()`/`revoke()` with guards.** Reflects the smart contract: registering an existing DID doesn't revert, but operating on a non-existent DID does `revert`.

### 6.8 `EvmAgentRegistry` — The blockchain adapter

Bridge between the `AgentRegistry` interface and a real EVM smart contract:

```
 AgentIdentity                EvmAgentRegistry              ContractClient           Smart Contract
      │                            │                              │                       │
      │  registry.register(did)    │                              │                       │
      ├───────────────────────────►│  contractClient              │                       │
      │                            │  .registerAgent(did,ctrl)    │                       │
      │                            ├─────────────────────────────►│  registerAgent(       │
      │                            │                              │    bytes32, address)   │
      │                            │           tx                 │  ────────────────────► │
      │                            │◄─────────────────────────────┤  ◄──── tx receipt     │
      │                            │  if(awaitConfirmation)       │                       │
      │                            │    await tx.wait()           │                       │
      │  ◄── void (completed) ─────┤                              │                       │
```

**`awaitTransactionConfirmation`:** Default `true` (waits for block mining). With `false`, fire-and-forget (for demos or bulk uploads). On Polygon ~2-4s wait; on Ethereum mainnet 12-15s.

**`register()` with DocumentRef:** Potentially executes **two separate transactions** (registerAgent + setDocumentRef). If the first confirms but the second fails, the DID is registered on-chain but without `documentRef` — an orphaned record unresolvable from the document source.

### 6.9 `EthersAgentRegistryContractClient` — The ethers.js wrapper

The lowest layer — connects directly with `ethers.Contract`:

```typescript
export class EthersAgentRegistryContractClient implements EvmAgentRegistryContract {
  constructor(contract: EthersLikeContract) {
    this.contract = contract;
  }
}
```

**Dual response decoding:** ethers.js can return contract data as array (legacy Solidity tuple) or object (modern form). The client handles both:

```typescript
// Array: ["did:agent:...", "0xCtrl...", "1740787200", "", ""]
if (Array.isArray(rawRecord)) {
  const [recordDid, controller, createdAt, revokedAt, documentRef] = rawRecord;
  return { did: String(recordDid), ...,
    createdAt: normalizeTimestampToIso(String(createdAt)) || String(createdAt), ... };
}

// Object: { did: "...", controller: "...", createdAt: "1740787200" }
return { did: String(rawRecord.did), ...,
  createdAt: normalizeTimestampToIso(String(rawRecord.createdAt)) || ..., ... };
```

Here `normalizeTimestampToIso()` from SHOULD-02 reappears — converts Unix timestamps from the contract (`"1740787200"`) to ISO-8601 (`"2025-02-28T22:40:00.000Z"`).

**Type-safe guard checks:** Each method verifies the injected contract has that function: `if (!this.contract.registerAgent) throw new Error('method not available')`.

### 6.10 The complete architecture — Everything connected

```
┌─ Developer ─────────────────────────────────────────────────────────────┐
│                                                                         │
│   AgentIdentity.useProductionResolverFromHttp({                         │
│     registry: new EvmAgentRegistry({                                    │
│       contractClient: new EthersAgentRegistryContractClient(contract)    │
│     }),                                                                 │
│     ipfsGateways: ['https://cloudflare-ipfs.com/ipfs/'],                │
│     cacheTtlMs: 120_000,                                                │
│     onResolutionEvent: (e) => monitor.log(e)                            │
│   });                                                                   │
│                                                                         │
│   // From here on, create/verify/resolve use real infrastructure        │
└─────────────────────────────────────────────────────────────────────────┘

 Internally this chain is assembled:

  AgentIdentity.resolver = new UniversalResolverClient({
    registry:        EvmAgentRegistry → EthersContractClient → Polygon Contract
    documentSource:  HttpDIDDocumentSource → IPFS Gateways / HTTP servers
    fallbackResolver: InMemoryDIDResolver (plan B)
    cacheTtlMs:      120_000
    onResolutionEvent: monitor.log()
  });
```

**Complete layer chain in `resolve(did)`:**

```
Layer 1: AgentIdentity.resolve(did) → verify revocation + delegate
Layer 2: UniversalResolverClient.resolve(did) → cache, coordination
Layer 3: EvmAgentRegistry.getRecord(did) → delegate to contract client
Layer 4: EthersAgentRegistryContractClient.getAgentRecord(did) → get documentRef
Layer 5: HttpDIDDocumentSource.getByReference(documentRef) → resolve URLs
Layer 6: fetch(url) → bytes arrive from the network
```

6 layers between the developer's call and the document bytes from the network.

**Responsibility summary:**

| Component | Layer | Responsibility | State |
|---|---|---|---|
| `InMemoryDIDResolver` | Resolver | Testing — Map in RAM | Synchronous, ephemeral |
| `UniversalResolverClient` | Resolver | Production — cache + fallback + observability | Coordinates everything |
| `HttpDIDDocumentSource` | Document Source | HTTP/IPFS fetch with multi-URL failover | Network I/O |
| `JsonRpcDIDDocumentSource` | Document Source | JSON-RPC 2.0 with multi-endpoint failover | Network I/O |
| `InMemoryAgentRegistry` | Registry | Testing — Map in RAM | Synchronous, ephemeral |
| `EvmAgentRegistry` | Registry | Production — adapter to EVM smart contract | Blockchain transactions |
| `EthersAgentRegistryContractClient` | Contract Client | ethers.js wrapper — decodes responses | Lowest level |

### Talking Points for the community
- *"The resolver is designed for production: cache TTL, multi-endpoint failover, IPFS gateways, observability"*
- *"We support HTTP and JSON-RPC as sources — compatible with any infrastructure"*
- *"Resolution telemetry allows monitoring SLOs in real production"*
- *"IPFS gives us decentralized storage without gas costs for complete documents"*
- *"The resolver/registry separation optimizes costs: the minimum on-chain, the complete off-chain"*
- *"There are 6 layers between your call and the network bytes — each with a clear responsibility"*

---

### Module 6 Exercises

**Exercise 1:** Why does `InMemoryDIDResolver` clone documents both when writing (`registerDocument`) and reading (`resolve`)? What vulnerability does each cloning prevent?

**Student answer:**
Cloning prevents the document from being modified by reference; if it were returned or written with the object's reference, we would risk clients or anyone else modifying the document's properties.

**Evaluation: 7.0/10**
- ✅ Reference concept correct — understands that without cloning there's a mutation risk
- ⚠️ Failed to distinguish what EACH cloning prevents separately: write-cloning protects against post-write mutation (the caller modifies the original object after registering it and corrupts the store), read-cloning protects against post-read mutation (the receiver modifies the returned object and corrupts the store). They are two distinct attack vectors.

---

**Exercise 2:** In `UniversalResolverClient.resolve()`, there's a line that says `if (resolved.id !== did) throw new Error("DID mismatch")`. What attack does it prevent? Describe a concrete scenario.

**Student answer:**
This verification prevents dealing with a different document; this is called anti-spoofing security. This way we prevent, for example, a malicious server from returning another agent's document (impersonation). It's the guarantee that the document belongs to the DID we requested.

**Evaluation: 8.5/10**
- ✅ Identifies anti-spoofing, impersonation, and the belonging guarantee — excellent
- ⚠️ Could have traced the complete attack flow: attacker controls the HTTP document source → you request `did:agent:polygon:0xVICTIM` → server returns document of `did:agent:polygon:0xATTACKER` (with their public key) → without the check, you accept that document → the attacker can sign messages that appear to come from the victim.

---

**Exercise 3:** `HttpDIDDocumentSource` distinguishes between "all returned 404" (null) and "real error" (throw). Why? What would happen if it always returned null?

**Student answer:**
This distinction is important because if all lookups return 404, it's not considered an error — perhaps the document hasn't been published yet — but a different type of error such as a 500 or timeout is an infrastructure error that must propagate.

**Evaluation: 7.0/10**
- ✅ First part correct — clear semantic distinction between "doesn't exist" and "infrastructure error"
- ⚠️ Didn't answer the second part of the question: if it always returned `null`, the `UniversalResolverClient` would treat infrastructure errors (server down, timeout) as if the document didn't exist → would fall to fallback silently → **you'd never know your infrastructure is broken**. Silent failures are the worst type of failure in production.

---

**Exercise 4:** `EvmAgentRegistry.register()` executes two transactions. What happens if the first confirms but the second fails? How would you handle it?

**Student answer:**
The fact that the second transaction fails doesn't imply a serious error since it indicates the registration couldn't be done in the EVM; given the case that "wait for confirmation" is configured. If "wait" is not configured, there should be a subsequent verification mechanism in the fallback that checks whether or not the document reference has been registered on the EVM network.

**Evaluation: 5.0/10**
- ⚠️ **It IS a serious problem**: the first transaction (`registerAgent`) is ALREADY confirmed on-chain — the DID exists. But without `documentRef` (second transaction failed), when someone tries to resolve that DID: `registry.getRecord(did)` → `{ documentRef: undefined }` → UniversalResolverClient says "Missing documentRef" → falls to fallback. The agent exists on-chain but is **unresolvable** — an orphaned record.
- ⚠️ Expected handling: (1) Automatic retry of `setDocumentRef` with exponential backoff, (2) Reconciliation job that detects records without `documentRef` and repairs them, (3) Make registration atomic in a single contract transaction (requires Solidity modification).

---

**Exercise 5:** Complete chain of `useProductionResolverFromHttp()`. How many layers are there between `resolve(did)` and the network bytes?

**Student answer:**
Correct structure diagram. "There are two layers: Abstraction of contracts (interfaces), Implementation of interfaces that end in direct communication with the blockchain."

**Evaluation: 5.5/10**
- ✅ Structure diagram is correct — well reproduced
- ⚠️ Layer count is incorrect. There are **6 layers**, not 2:
  - Layer 1: `AgentIdentity.resolve()` — verifies revocation + delegates
  - Layer 2: `UniversalResolverClient.resolve()` — cache, coordination
  - Layer 3: `EvmAgentRegistry.getRecord()` — delegates to contract client
  - Layer 4: `EthersAgentRegistryContractClient.getAgentRecord()` — gets documentRef
  - Layer 5: `HttpDIDDocumentSource.getByReference()` — resolves URLs
  - Layer 6: `fetch(url)` — bytes from the network

---

**Exercise 6:** Why is `register()` idempotent but `revoke()` throws an error if it doesn't exist? What smart contract behavior does it reflect?

**Student answer:**
Idempotency guarantees that the document is not registered more than once. If we're trying to revoke something that doesn't exist, it indicates the possibility of a bug that should be propagated as an error for subsequent analysis.

**Evaluation: 7.0/10**
- ✅ Logical reasoning correct in both cases
- ⚠️ Failed to explicitly connect with the smart contract as the question asked: `register` idempotent reflects that in Solidity `registerAgent()` with an existing DID simply does nothing (doesn't revert). `revoke` with guard reflects that in Solidity `revokeAgent()` on a non-existent DID does `revert` (the transaction reverts completely). These are contract behaviors that InMemory faithfully replicates.

---

### Consolidated evaluation — Module 6

| Exercise | Grade | Strength | Area for improvement |
|-----------|------|-----------|----------------|
| 1. Double Deep Clone | 7.0 | Reference concept | Distinguish each direction |
| 2. Anti-spoofing | 8.5 | Impersonation scenario | Trace complete attack flow |
| 3. 404 vs real error | 7.0 | Semantic distinction | Answer both parts |
| 4. Two transactions | 5.0 | — | Identify orphaned record |
| 5. Layer chain | 5.5 | Correct diagram | 6 layers, not 2 |
| 6. Idempotency vs guard | 7.0 | Logical reasoning | Connect with Solidity revert |

**Module 6 Average: 6.7/10** ✅ Passed

**Overall progress:**

| Module | Average | Trend |
|--------|---------|-----------|
| Module 1 | 7.8/10 | — |
| Module 2 | 8.0/10 | ↑ |
| Module 3 | 7.2/10 | ↓ |
| Module 4 | 7.8/10 | ↑ |
| Module 5 | 6.5/10 | ↓ |
| Module 6 | 6.7/10 | → |
| Module 7 | 6.8/10 | → |

**Final result: 7.3/10 — COURSE PASSED** ✅

**Analysis:** Conceptual modules (1-4) average ~7.7, deep technical modules (5-7) average ~6.7. Clear pattern: conceptual and design understanding is solid, but when tracing step-by-step flows, counting concrete layers, or identifying intermediate failure states, precision is lacking. Outstanding strength: architectural vision and analogies (E4-M7 = 9.0, best grade in the course). Critical area: technical precision in details (ISO vs Unix, OpenZeppelin, units).


---

## Module 7 — Smart Contract, Security, and Community Preparation

### Learning objectives
- Understand the smart contract `AgentRegistry.sol` line by line
- Master the security model: revocation delegation, ownership transfer, access policies
- Understand the 16 conformance controls (11 MUST + 5 SHOULD) and how they are validated
- Trace the complete flow of `revocation-policy-check.js` (10 steps)
- Prepare to present the project to the community with answers to the 8 frequently asked questions

### 7.1 AgentRegistry.sol — Complete anatomy

The smart contract has **157 lines**, **zero external dependencies** (does not use OpenZeppelin), and is written in Solidity ^0.8.24. This minimalism is a deliberate design decision: it reduces attack surface, eliminates supply chain risk, and facilitates auditing.

#### Struct `AgentRecord`

```solidity
struct AgentRecord {
    string did;          // The full DID "did:agent:polygon:0x..."
    string controller;   // The controller DID "did:ethr:0x..."
    string createdAt;    // Unix timestamp as string (e.g.: "1710500000")
    string revokedAt;    // Empty "" if active, timestamp if revoked
    string documentRef;  // Reference to off-chain document (IPFS hash, URL)
    bool exists;         // Guard to differentiate "doesn't exist" from "exists with defaults"
    address owner;       // Ethereum address with operational control
}
```

**Architectural decision — `string` for timestamps:**
The contract uses `string` instead of `uint256` for timestamps. This is because `_timestampToString()` converts `block.timestamp` to its text representation. The SDK (`time.ts`) then normalizes these Unix timestamps to ISO 8601 with `normalizeTimestampToIso()`. This allows the on-chain data to be readable without decoding and the SDK to present human-readable format.

#### Storage

```solidity
mapping(string => AgentRecord) private records;
mapping(string => mapping(address => bool)) private revocationDelegates;
```

Two mappings:
1. **`records`** — DID string → AgentRecord. The DID as string is the key, not a hash. This consumes more gas than using `bytes32`, but allows the DID to be readable directly in events and queries.
2. **`revocationDelegates`** — DID → address → bool. Nested mapping for granular delegation per agent.

### 7.2 The 8 contract functions

| # | Function | Type | Access | Description |
|---|----------|------|--------|-------------|
| 1 | `registerAgent(did, controller)` | Write | Public (once per DID) | Registers new agent, assigns `msg.sender` as owner |
| 2 | `revokeAgent(did)` | Write | Owner + authorized delegates | Permanently revokes DID (irreversible) |
| 3 | `setRevocationDelegate(did, delegate, authorized)` | Write | Owner only | Authorizes or deauthorizes revocation delegates |
| 4 | `transferAgentOwnership(did, newOwner)` | Write | Owner only | Transfers operational ownership to another address |
| 5 | `setDocumentRef(did, documentRef)` | Write | Owner only | Updates the reference to the off-chain document |
| 6 | `getAgentRecord(did)` | View (read) | Public | Returns the 5 fields of the record (without `exists` or `owner`) |
| 7 | `isRevoked(did)` | View (read) | Public | Returns `true` if the agent was revoked |
| 8 | `isRevocationDelegate(did, delegate)` | View (read) | Public | Checks if an address is an authorized delegate |

#### Deep analysis of each function

**1. `registerAgent()` — Registration with guards**

```solidity
function registerAgent(string calldata did, string calldata controller) external {
    require(bytes(did).length > 0, "did required");
    require(bytes(controller).length > 0, "controller required");
    require(!records[did].exists, "already registered");   // ← Uniqueness guard

    string memory nowIso = _timestampToString(block.timestamp);

    records[did] = AgentRecord({
        did: did,
        controller: controller,
        createdAt: nowIso,
        revokedAt: "",        // ← Empty = not revoked
        documentRef: "",      // ← Set later with setDocumentRef()
        exists: true,         // ← Guard activated
        owner: msg.sender     // ← Registrant becomes the owner
    });

    emit AgentRegistered(did, controller, nowIso);
}
```

**Key points:**
- `calldata` instead of `memory` — gas savings because strings are not copied
- `require(!records[did].exists)` does **revert** if the DID already exists — the transaction is completely reverted and gas consumed up to that point is lost
- `msg.sender` automatically becomes owner — you cannot register and assign to another

**2. `revokeAgent()` — Revocation with delegation**

```solidity
function revokeAgent(string calldata did) external {
    AgentRecord storage record = records[did];
    require(record.exists, "not found");
    require(bytes(record.revokedAt).length == 0, "already revoked");
    require(_isAuthorizedRevoker(did, msg.sender), "not authorized");

    string memory nowIso = _timestampToString(block.timestamp);
    record.revokedAt = nowIso;

    emit AgentRevoked(did, nowIso);
}
```

**Key points:**
- `storage` (not `memory`) — directly modifies on-chain state
- Triple require: exists, not revoked, authorized
- `_isAuthorizedRevoker()` checks: `owner || authorized delegate`
- Once revoked, `revokedAt` has a value and the second `require` blocks re-revocation
- **Irreversible** — there is no `unrevokeAgent()` function

**3. `setRevocationDelegate()` — Granular delegation**

```solidity
function setRevocationDelegate(string calldata did, address delegate, bool authorized) external {
    AgentRecord storage record = records[did];
    require(record.exists, "not found");
    require(record.owner == msg.sender, "only owner");
    require(delegate != address(0), "delegate required");

    revocationDelegates[did][delegate] = authorized;
    emit RevocationDelegateUpdated(did, delegate, authorized);
}
```

**Key points:**
- `authorized = true` → authorizes, `authorized = false` → deauthorizes
- Only the owner can delegate — delegates CANNOT delegate to others
- Each delegate is per specific DID — delegating for one agent does not grant access to others

**4. `transferAgentOwnership()` — Ownership transfer**

```solidity
function transferAgentOwnership(string calldata did, address newOwner) external {
    AgentRecord storage record = records[did];
    require(record.exists, "not found");
    require(record.owner == msg.sender, "only owner");
    require(newOwner != address(0), "newOwner required");

    address previousOwner = record.owner;
    record.owner = newOwner;

    emit AgentOwnershipTransferred(did, previousOwner, newOwner);
}
```

**Key points:**
- Immediate transfer — the previous owner loses access in the same transaction
- Existing delegates **remain** — the new owner must explicitly deauthorize them if desired
- The DID Document's `controller` (off-chain layer) does NOT change — they are independent layers

**5-8. View functions and `setDocumentRef()`**

`setDocumentRef()` updates the off-chain reference (IPFS hash, URL). Only the owner can do this.

`getAgentRecord()` returns 5 fields (did, controller, createdAt, revokedAt, documentRef) — **does not expose** `exists` or `owner` by design. Does `revert` if the DID doesn't exist.

`isRevoked()` returns `false` if the DID doesn't exist (**fail-late** design — does not revert). This allows checking without knowing beforehand whether the DID was registered.

`isRevocationDelegate()` simply reads the nested mapping.

### 7.3 The 4 events

```solidity
event AgentRegistered(string did, string controller, string createdAt);
event AgentRevoked(string did, string revokedAt);
event RevocationDelegateUpdated(string did, address delegate, bool authorized);
event AgentOwnershipTransferred(string did, address previousOwner, address newOwner);
```

Events are fundamental for:
1. **Off-chain indexing** — services like The Graph can index all registered agents
2. **Auditing** — every critical action is recorded in the blockchain's immutable log
3. **Notifications** — services can subscribe to revocation events for immediate reaction
4. **Traceability** — the complete ownership chain is reconstructable from events

### 7.4 Revocation and delegation model

#### Complete flow of the `revocation-policy-check.js` script

This script validates the delegation model in 10 steps:

```
Step 1:  Get 4 signers → [deployer, owner, delegate, newOwner]
Step 2:  owner registers didOne
Step 3:  delegate attempts to revoke didOne → REVERT "not authorized" ✓
Step 4:  owner authorizes delegate with setRevocationDelegate(didOne, delegate, true)
Step 5:  Verify isRevocationDelegate(didOne, delegate) === true ✓
Step 6:  delegate successfully revokes didOne ✓
Step 7:  owner registers didTwo
Step 8:  owner transfers ownership of didTwo to newOwner
Step 9:  owner attempts to delegate on didTwo → REVERT "only owner" ✓
         (no longer owner, the transfer was immediate)
Step 10: newOwner delegates to delegate → delegate revokes didTwo ✓
```

```
┌──────────┐           ┌──────────┐           ┌──────────┐
│  owner   │──register──▶│  didOne  │◀──revoke──│ delegate │
│          │──delegate──▶│          │           │          │
│          │             └──────────┘           └──────────┘
│          │
│          │──register──▶┌──────────┐──transfer──▶┌──────────┐
│          │             │  didTwo  │             │ newOwner │
│          │             └──────────┘             │          │
│  ✗ no    │──delegate──▶    REVERT               │──delegate──▶ delegate
│  longer  │                                     │          │
│  owner   │                                     └──────────┘
└──────────┘
```

#### Model principles

1. **Owner revocation:** the owner can revoke directly without delegates
2. **Delegated revocation:** the owner can authorize delegates with `setRevocationDelegate()`
3. **Authorization check:** `_isAuthorizedRevoker()` → `owner || revocationDelegates[did][actor]`
4. **Permanence:** once revoked, there is no "un-revoke" mechanism — irreversible
5. **Granularity:** each delegate is authorized per specific DID, not globally
6. **Non-transitivity:** delegates CANNOT delegate to others

**Enterprise use case:** an organization has 50 AI agents. The CISO authorizes the security team (3 addresses) as revocation delegates. If an agent is compromised, anyone on the team can revoke without waiting for the original owner. If the CISO rotates, ownership is transferred and the new CISO manages the delegates.

### 7.5 Ownership vs Controller — Two independent layers

| Concept | Layer | Who controls it | What can they do |
|---------|-------|-----------------|------------------|
| **Owner** | On-chain (Solidity) | `address` in `AgentRecord.owner` | `setDocumentRef`, `transferAgentOwnership`, `setRevocationDelegate`, `revokeAgent` |
| **Controller** | Off-chain (DID Document) | DID string in `controller` | Authorize changes to DID Document per W3C DID Core |

**Outsourcing scenario:**
A company (owner: `0xCompany`) hires a vendor to operate an AI agent. The DID Document controller is the vendor (`did:ethr:0xProvider`). If the vendor compromises security:
1. The company (owner) revokes the agent on-chain → immediate
2. The company transfers ownership to another internal address
3. The DID Document controller becomes obsolete — the revoked agent is no longer verifiable

**Fleet scenario:**
A company operates 100 agents. The on-chain owner is the company (one address), but each agent has its own controller (the agent instance). Centralized ownership for governance, distributed controller for operation.

### 7.6 Security — Threat model

| Threat | Vector | Mitigation in Agent-DID | Layer |
|--------|--------|--------------------------|-------|
| Private key theft | Access to agent process | Immediate revocation, keys never leave the process, pre-authorized delegates | On-chain + SDK |
| DID impersonation | Create fake DID that appears legitimate | DID derived from cryptographic hash (`sha256(publicKey + network + controller)`) | SDK |
| Document manipulation | Alter DID Document after publishing | On-chain `documentRef` serves as integrity anchor (verifiable hash) | On-chain |
| HTTP replay attack | Reuse valid HTTP signature | Timestamp in signatures + maximum clock skew (300s) + nonce in components | SDK |
| Registry manipulation | Modify registry without authorization | Smart contract with access control: `require(owner == msg.sender)` | Solidity |
| Supply chain attack | Compromised dependency injects malicious code | Zero dependencies in contract, minimal in SDK (`@noble/curves`, `ethers`) | Design |
| Denial of service | Registration spam to fill storage | Natural gas cost of Ethereum limits spam, each registration costs ETH | EVM |
| Key rotation failure | Old key continues to be accepted | `verificationMethod` is updated, `verifySignature` uses current list | SDK |

### 7.7 Security best practices

1. **Store private keys in secure enclaves or HSMs** — never in plaintext environment variables
2. **TLS for all communication with resolvers** — HTTP and JSON-RPC endpoints must use HTTPS
3. **Validate document hash vs on-chain anchor** in each resolution — `documentRef` as integrity proof
4. **Rate limiting on resolver endpoints** — prevent enumeration attacks and DoS
5. **Monitor unexpected revocation events** — subscribe to `AgentRevoked` for early detection
6. **Proactive key rotation** — recommended every 90 days, use `updateVerificationMethod()`
7. **Principle of least privilege in capabilities** — declare only the capabilities the agent actually needs
8. **Pre-authorize revocation delegates** — before an incident occurs, have the response plan ready
9. **Audit dependencies regularly** — `npm audit`, verify that `@noble/curves` and `ethers` are up to date

### 7.8 Conformance — The 16 controls

The conformance system is executed with:

```bash
npm run conformance:rfc001
```

This command executes `scripts/conformance-rfc001.js`, which performs:

1. **6 technical verifications** (in sequence, stops at first failure):
   - SDK build (`npm --prefix sdk run build`)
   - SDK tests (`npm --prefix sdk test`)
   - Revocation policy smoke (`npm run smoke:policy`)
   - HA resolver drill (`npm run smoke:ha`)
   - RPC resolver smoke (`npm run smoke:rpc`)
   - E2E smoke (`npm run smoke:e2e`)

2. **Checklist parsing** (`docs/RFC-001-Compliance-Checklist.md`):
   - Reads the Markdown file
   - Extracts rows with `MUST-` and `SHOULD-` prefix
   - Counts: PASS, PARTIAL, FAIL, UNKNOWN
   - Shows executive summary

#### The 11 MUST Controls (Mandatory)

| ID | Control | Status | Key evidence |
|----|---------|--------|--------------|
| MUST-01 | DID Document with required fields (`id`, `controller`, `created`, `updated`, `agentMetadata`, `verificationMethod`, `authentication`) | PASS | `types.ts`, `AgentIdentity.ts` |
| MUST-02 | `create(params)` operation | PASS | `AgentIdentity.ts` |
| MUST-03 | `signMessage(payload, privateKey)` | PASS | `AgentIdentity.ts` |
| MUST-04 | `signHttpRequest()` with RFC 9421 (`@request-target`, `host`, `date`, `content-digest`, identity) | PASS | Positive/negative tests, tamper, multiple signatures |
| MUST-05 | `resolve(did)` with multiple sources | PASS | HTTP failover, IPFS gateways, JSON-RPC failover, direct `did:wba` resolution |
| MUST-06 | `verifySignature()` + failure if revoked | PASS | Tests with `keyId` and rotation |
| MUST-07 | `revokeDid(did)` | PASS | Registry + contract |
| MUST-08 | Minimum registry (`registerAgent`, `revokeAgent`, `getAgentRecord`, `isRevoked`) | PASS | `AgentRegistry.sol`, SDK registry |
| MUST-09 | Valid signature before revocation, invalid after | PASS | `npm run smoke:e2e` |
| MUST-10 | Evolution (`updated` + `verificationMethod` rotation) | PASS | Evolution tests |
| MUST-11 | On-chain/off-chain separation with document reference | PASS | `documentRef` in contract |

#### The 5 SHOULD Controls (Recommended)

| ID | Control | Status | Key evidence |
|----|---------|--------|--------------|
| SHOULD-01 | Universal resolver with cache and high availability | PASS | `UniversalResolverClient.ts`, HTTP + RPC failover, direct `did:wba` resolution, HA runbook |
| SHOULD-02 | Homogeneous temporal normalization SDK ↔ contract | PASS | `time.ts`, Unix on-chain → ISO in SDK |
| SHOULD-03 | Interoperable verification with external implementations | PASS | `interop-vectors.json`, `InteropVectors.test.ts` |
| SHOULD-04 | Access control policies for revocation | PASS | `setRevocationDelegate`, `transferAgentOwnership`, `revocation-policy-check.js` |
| SHOULD-05 | Document evolution traceability by version | PASS | Evolution tests, `updated` in DID Document |

**Executive summary:** 11/11 MUST PASS + 5/5 SHOULD PASS = **16/16 conformant controls**

### 7.9 Community preparation

#### Contract deployment — `deploy-agent-registry.js`

```javascript
const AgentRegistry = await hre.ethers.getContractFactory('AgentRegistry');
const contract = await AgentRegistry.deploy();   // Zero constructor params
await contract.waitForDeployment();
```

**4 lines.** No constructor params, no initializers, no proxies. The contract is **immutable** — once deployed, there is no upgrade path. If a new version is needed, a new contract is deployed and records are migrated (migrating only the state, not the code).

#### What questions will they ask?

| # | Question | Prepared answer |
|---|----------|-----------------|
| 1 | "How does it differ from did:ethr or did:web?" | Agent-DID adds AI agent metadata (model hash, system prompt hash, capabilities), IP protection, and fleet governance. did:ethr is just generic identity. |
| 2 | "Why don't you use ZKPs?" | It's on the roadmap Phase 3 (F3-03) for capability verification without revealing content. Currently we use hashes for IP protection. |
| 3 | "How does it scale?" | Minimum on-chain (only registration and revocation), horizontally scalable off-chain documents. A registration is ~200 bytes on-chain, the complete document can be on IPFS. |
| 4 | "Does it work with LangChain/CrewAI?" | Yes. The LangChain integration is already implemented in [../integrations/langchain/README.md](../integrations/langchain/README.md), CrewAI now has a functional Python integration in [../integrations/crewai/README.md](../integrations/crewai/README.md), Semantic Kernel now has a functional Python integration in [../integrations/semantic-kernel/README.md](../integrations/semantic-kernel/README.md), and Microsoft Agent Framework now has a functional Python integration in [../integrations/microsoft-agent-framework/README.md](../integrations/microsoft-agent-framework/README.md). The SDK remains framework-agnostic. Azure AI Agent Service remains a separate planned integration track. |
| 5 | "Is there a contract audit?" | Automated static analysis with Slither/Mythril is already completed (F1-05) and runs in CI. F3-04 formal third-party verification is planned for mainnet. The contract is 157 lines with zero dependencies — the audit surface is minimal. |
| 6 | "What blockchain do you use?" | Any EVM-compatible chain (Ethereum, Polygon, Arbitrum, etc.). The reference implementation uses Polygon for lower gas costs. |
| 7 | "How do I revoke if I lose my keys?" | Pre-authorized revocation delegates. If the owner loses access, a delegate can revoke. That's why it's critical to configure delegates BEFORE an incident occurs. |
| 8 | "Is it W3C compatible?" | Yes, it extends W3C DID Core 1.0 with the `agentMetadata` namespace. The base fields (`id`, `controller`, `verificationMethod`, `authentication`) are W3C standard. |

#### Recommended presentation structure (18 minutes)

| Block | Duration | Content | Tip |
|-------|----------|---------|-----|
| Problem | 2 min | AI agents act without verifiable identity — you can't know if who you're talking to is who they claim to be | Use concrete example: impersonated banking agent |
| Solution | 3 min | Agent-DID — digital passport for AI agents | Show real DID Document, point out `agentMetadata` |
| Live demo | 5 min | `create → signMessage → signHttp → verifySignature → revoke → verify fails` | Have script prepared, don't improvise |
| Architecture | 3 min | Hybrid on-chain/off-chain diagram | Use the layer diagram from Module 1 |
| RFC-001 | 2 min | Open standard, 16/16 controls passing | Run `npm run conformance:rfc001` live |
| Roadmap | 2 min | Python SDK, LangChain integration, ZKPs, W3C submission | Show backlog on GitHub |
| Call to action | 1 min | Contribute, use, give feedback | Have QR with repo |

### Talking Points for the community

- "RFC-001 is an open standard — not a proprietary product"
- "We have 16 conformance controls verified in CI"
- "The contract supports revocation delegation — enterprise governance model"
- "All crypto operations use audited libraries — we don't reinvent the wheel"
- "The roadmap includes Python SDK, agent framework integrations, and W3C submission"
- "157 lines of Solidity, zero dependencies — maximum auditability"
- "On-chain/off-chain separation — only the essentials go to the blockchain"

---

### Module 7 Exercises

**Exercise 1:** If `registerAgent()` is called with a DID that already exists, what happens exactly? How much gas is lost? What risk does idempotency hide?

**Student answer:**
If the DID already exists, registerAgent() fails with the message "already registered" and the transaction reverts. The gas consumed up to the point of the revert is lost. The main risk is that the existing registration silently blocks new attempts without making it evident that it was already registered with a different controller.

**Evaluation: 6.0/10**
- ✅ Correct that the transaction reverts with "already registered"
- ✅ Partially identifies the risk of silent blocking
- ⚠️ Gas is NOT lost "up to the point of the revert" — in a `require` fail, all gas consumed up to that point of the execution path is used, but the state is completely reverted. In practice, the gas consumed is minimal because the `require` is early in the function (3 checks before any storage write).
- ⚠️ **Idempotency** is not the design here — the contract is **NOT idempotent**, it does `revert`. Idempotent would be if the second call simply did nothing and returned successfully. The real risk is that the `InMemoryAgentRegistry` in the SDK (which IS idempotent — it simply ignores the second registration) can **hide identity conflicts**: if two agents try to register the same DID, the first one wins silently. In the contract, at least the revert alerts you.

---

**Exercise 2:** Why does `isRevoked()` return `false` for a DID that doesn't exist, but `getAgentRecord()` does `revert`? What design pattern does it reflect?

**Student answer:**
`isRevoked()` returns `false` because semantically a DID that doesn't exist cannot be revoked — the absence of a record implies absence of revocation. `getAgentRecord()` does revert because if you request the data of an agent that doesn't exist, it's a caller error that must propagate. The pattern is: boolean state queries are tolerant, complete data queries are strict.

**Evaluation: 8.0/10**
- ✅ Excellent semantic reasoning about why `false` is correct for nonexistent
- ✅ Good distinction between tolerant boolean queries and strict data queries
- ⚠️ Failed to name the pattern: **fail-late** design pattern. `isRevoked()` is fail-late (allows the flow to continue and the caller decides), `getAgentRecord()` is **fail-fast** (cuts immediately). This allows chaining: `if (!isRevoked(did)) { record = getAgentRecord(did); }` — if both did revert, you'd need try/catch in Solidity (more expensive in gas).

---

**Exercise 3:** What's the difference between an owner calling `revokeAgent(did)` and calling `setRevocationDelegate(did, delegate, false)`? The question is about the functional difference and end result.

**Student answer:**
`revokeAgent(did)` permanently revokes the DID — the agent becomes unusable forever. `setRevocationDelegate(did, delegate, false)` simply deauthorizes a specific delegate, but the agent remains active. The difference is: one destroys the identity, the other reduces governance permissions.

**Evaluation: 6.5/10**
- ✅ Correct that `revokeAgent` is permanent and `setRevocationDelegate(false)` only removes permissions
- ✅ Good metaphor "destroys identity vs reduces governance permissions"
- ⚠️ The question asked for the complete functional difference. Missing: (1) `revokeAgent` can be called by owner OR by delegates — `setRevocationDelegate` only by owner. (2) `revokeAgent` modifies `records[did].revokedAt` (agent data) — `setRevocationDelegate` modifies `revocationDelegates[did][delegate]` (governance data). They are completely different mappings. (3) After `revokeAgent`, even the owner cannot do anything more useful with that DID (only `getAgentRecord` and `isRevoked` continue working).

---

**Exercise 4:** What is the relationship between `owner` (on-chain) and `controller` (off-chain)? Give me a real scenario where they are different entities.

**Student answer:**
The `owner` is the Ethereum address that controls on-chain operations (revoke, transfer, delegate). The `controller` is the DID that controls the DID Document per W3C. They can be different: a company (owner: `0xCompanyWallet`) hires an ML vendor (controller: `did:ethr:0xMLProvider`) to operate an analysis agent. The company maintains on-chain revocation power, but the vendor manages the agent's keys and operation. If the vendor is compromised, the company revokes immediately without needing access to the agent's keys. It's like a landlord (owner) vs tenant (controller) — the tenant operates the space, but the landlord can terminate the contract.

**Evaluation: 9.0/10**
- ✅ Perfect distinction between owner (on-chain) and controller (off-chain)
- ✅ Excellent real scenario with company + ML vendor
- ✅ The landlord/tenant analogy is precise and memorable
- ✅ Correctly identified that the owner can revoke without access to the agent's keys
- ⚠️ For 10: mention that `transferAgentOwnership` changes owner but NOT controller, and that `controller` is set once in `registerAgent` and there is no function to change it on-chain — it is immutable in the contract.

---

**Exercise 5:** If you had to migrate from `InMemoryAgentRegistry` to `EvmAgentRegistry` in production, what steps would you follow? What is lost, what is preserved?

**Student answer:**
Steps: (1) Deploy AgentRegistry.sol on the chosen EVM network, (2) Configure the SDK with `useEvmRegistry(contractAddress, signer)`, (3) Re-register all existing agents with `registerAgent()` in the contract, (4) Update off-chain documents so the resolver points to the new source. Preserved: the DID Document structure, keys, metadata. Lost: the timestamp history (new ones will be from the moment of re-registration, not the originals), and any prior revocation state must be re-applied manually.

**Evaluation: 7.0/10**
- ✅ The 4 steps are correct in sequence
- ✅ Correctly identifies that timestamps are lost (createdAt will be from re-registration)
- ✅ Good observation about re-applying revocations
- ⚠️ Missing precision in the plan: step 2 should include `provider` configuration (RPC connection to the network) in addition to `contractAddress` and `signer`
- ⚠️ Omission error: off-chain documents do NOT need "reprocessing" — if they're on IPFS, the hashes are the same. Only `setDocumentRef()` in the contract is needed for each migrated agent.
- ⚠️ Failed to mention that migration implies gas costs for each `registerAgent()` — with 100 agents, that's a significant cost that must be budgeted.

---

**Exercise 6:** Why doesn't the contract use OpenZeppelin? What does it gain and lose? Are the timestamps ISO or Unix?

**Student answer:**
OpenZeppelin is not used because it's not possible in this context — the contract needs to be completely autonomous without external dependencies. Gains: simplicity, complete auditability of 157 lines, zero supply chain risk. Loses: proven patterns like Ownable, Pausable, AccessControl that are already audited. Timestamps are stored in ISO 8601 format which is the DID Document standard.

**Evaluation: 4.0/10**
- ✅ Correct benefits: simplicity, auditability, zero supply chain risk
- ✅ Correct trade-offs: loses patterns like Ownable, Pausable, AccessControl
- ❌ **Factual error 1:** "It's not possible" to use OpenZeppelin — it IS possible, it's a **design decision**, not a technical limitation. Any Solidity contract can import OpenZeppelin with `import "@openzeppelin/contracts/access/Ownable.sol"`. The deliberate decision was to minimize attack surface and dependencies.
- ❌ **Factual error 2:** Timestamps are NOT stored in ISO 8601 in the contract. They are stored as **Unix timestamp strings** — `_timestampToString(block.timestamp)` converts the `uint256` from `block.timestamp` (Unix epoch in seconds) to its string representation (e.g.: `"1710500000"`). It's the SDK (`time.ts` → `normalizeTimestampToIso()`) that converts from Unix string to ISO 8601 for application consumption.

---

### Consolidated evaluation — Module 7

| Exercise | Grade | Strength | Area for improvement |
|----------|-------|----------|----------------------|
| 1. registerAgent revert | 6.0 | Identifies silent blocking | Gas in revert, idempotency vs guard |
| 2. isRevoked vs getAgentRecord | 8.0 | Semantic reasoning | Name fail-late pattern |
| 3. revokeAgent vs delegate(false) | 6.5 | Correct metaphor | Identify different mappings |
| 4. Owner vs Controller | 9.0 | Excellent real scenario | Immutability of controller |
| 5. Migration InMemory → EVM | 7.0 | Correct sequence | Gas costs, off-chain documents |
| 6. OpenZeppelin and timestamps | 4.0 | Correct trade-offs | Two factual errors |

**Module 7 Average: 6.8/10** ✅ Passed

---

## Final Course Evaluation

### Progress by module

| Module | Topic | Average | Trend |
|--------|-------|---------|-------|
| Module 1 | Fundamentals and digital identity | 7.8/10 | — |
| Module 2 | DID Documents and W3C | 8.0/10 | ↑ |
| Module 3 | Applied cryptography | 7.2/10 | ↓ |
| Module 4 | RFC-001, Compliance and Governance | 7.8/10 | ↑ |
| Module 5 | SDK — AgentIdentity in depth | 6.5/10 | ↓ |
| Module 6 | Resolvers and Registry | 6.7/10 | → |
| Module 7 | Smart Contract, Security and Community | 6.8/10 | → |

### Final result: **7.3/10 — COURSE PASSED** ✅

### Student profile

**Outstanding strengths:**
- **Architectural vision** — excellent understanding of design decisions and trade-offs (E4-M7 = 9.0, best grade in the course)
- **Semantic reasoning** — understands the "why" behind each technical decision
- **Analogies and metaphors** — landlord/tenant, digital passport, shields — facilitate communication with mixed audiences
- **Systems design** — concepts like layer separation, least privilege, delegated governance are well internalized

**Areas for improvement:**
- **Technical precision** — confusions like ISO vs Unix, "not possible" vs design decision, 16 bits vs 16 bytes (M5)
- **Reading the question exactly** — tendency to answer a slightly different version of what was asked
- **Tracing step-by-step flows** — in technical modules (5-7), answers are conceptually correct but lack concrete details (which variable, which line, which mapping)
- **Layer counting** — when asked to enumerate concrete components, verify against actual code

### Recommendation for the presentation

The student has a **solid foundation for presenting** to the community. Strengths in architectural vision and analogies are ideal for a mixed audience. **Key advice:** before the presentation, practice the 8 frequently asked questions from section 7.9 and for each technical answer, have the exact code reference prepared (file, line, function) — this will turn answers from "conceptually correct" to "technically precise".

---

## Summary of Technologies Covered

| Technology | Where learned | Use in the project |
|---|---|---|
| W3C DID Core 1.0 | Module 2 | Foundation of the identity standard |
| JSON-LD | Module 2 | DID Document format with semantics |
| Ed25519 (EdDSA) | Module 3 | Message and HTTP signing and verification |
| SHA-256 | Module 3 | Metadata hashing for IP protection |
| RFC 9421 (HTTP Message Signatures) | Module 3 | HTTP agent-to-service authentication |
| TypeScript | Modules 5-6 | SDK implementation language |
| ethers.js v6 | Modules 5-6 | EVM blockchain interaction |
| @noble/curves | Modules 3, 5 | Ed25519 cryptography |
| JSON-RPC 2.0 | Module 6 | Protocol for document resolution |
| IPFS | Module 6 | Decentralized document storage |
| Solidity | Module 7 | Smart contract for on-chain registry |
| Hardhat | Module 7 | Contract development framework |
| EVM (Ethereum Virtual Machine) | Modules 6-7 | Runtime for smart contracts |
| Verifiable Credentials (VC) | Module 4 | Compliance certifications |

---

## Prerequisites and Resources

### To follow this course you need:
- Node.js 18+ installed
- npm
- The repository cloned and with dependencies installed:
  ```bash
  npm install
  npm --prefix sdk install
  npm --prefix contracts install
  ```

### Recommended external resources:
- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/)
- [Ed25519 — RFC 8032](https://tools.ietf.org/html/rfc8032)
- [HTTP Message Signatures — RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)
- [Solidity Docs](https://docs.soliditylang.org/)
- [@noble/curves](https://github.com/paulmillr/noble-curves)

---

**Next step:** Type "Ready" in chat to begin Module 1 interactively.
