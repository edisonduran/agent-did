# ADR-006: Wire alignment before the rc.5 freeze

- **Status:** Accepted (2026-11-15)
- **Deciders:** Maintainer
- **Applies from:** `1.0.0-rc.5`
- **Discussion:** `[RFC]` issues #248 (D-8a), #249 (D-8b), #250 (D-8c), #251 (D-8d)

## Context

The wire freeze of [DEPRECATION-POLICY.md](DEPRECATION-POLICY.md) starts at `1.0.0-rc.5`. After it, a change to signed bytes or document content needs a new major line. A review of the rc.4 wire found four places where Agent-DID diverges from a neighbouring specification or claims more than it can check. They are cheap to fix now and expensive afterwards:

1. **`Signature-Agent` collides with Web Bot Auth.** RFC-001 §6.5 puts the agent's DID, as a bare String, in a header named `Signature-Agent` and covers it as `"signature-agent"`. The IETF Web Bot Auth draft ([`draft-ietf-webbotauth-httpsig-protocol-01`](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/), 2026-10-29) defines the same header name differently: a Structured Field **Dictionary** keyed by signature label, each member an `https` URI of a JWKS key directory, covered as `"signature-agent";key="<label>"`, with `tag="web-bot-auth"` and `keyid` a JWK SHA-256 thumbprint. Signers MUST send the dictionary form; verifiers MAY accept the bare String as legacy. A Web Bot Auth verifier that receives an Agent-DID request reads our DID as a legacy directory URI and fails, or worse, tries to fetch it. An intermediary that understands only one of the two cannot tell them apart.
2. **Verification method type.** Documents use `Ed25519VerificationKey2020`. W3C's Controlled Identifiers v1.0 and Data Integrity specify `Multikey` with the same `publicKeyMultibase` value (`z` + base58btc(`0xed01` ‖ key)). The did:webvh log proofs we produce already use `Multikey` for `updateKeys`. Neither SDK checks the `type` of a verification method: both decode `publicKeyMultibase` only.
3. **`coreModelHash` / `systemPromptHash` are REQUIRED** (RFC-001 §4.2). An agent that does not want to commit to a model or prompt has to publish a placeholder, and the RFC does not say what a verifier may conclude from the values. They are statements by the controller, not facts anyone checked.
4. **Metadata is only in the DID document.** Every claim about the agent (`agentMetadata`) changes the document, so it costs a log entry, is public to anyone who resolves the DID and cannot be shown selectively. There is no way to carry the same claims as a credential that a relying party can store and verify on its own.

## Decision

Each item lists the options considered. The maintainer accepted the recommended option of each one on 2026-11-15. The order of implementation is 3, 2, 4, 1: the document changes first, the HTTP profile last, so every fixture is regenerated once.

### D-8a. HTTP header for the agent DID

`[RFC]` #248.

| Option | Wire | Web Bot Auth interop | Cost |
|---|---|---|---|
| (i) Keep `Signature-Agent`, dictionary form, DID as the member value | `Signature-Agent: sig1="did:webvh:…"`, covered `"signature-agent";key="sig1"` | Still collides: a WBA verifier requires an `https` URI and a JWKS behind it | Low |
| **(ii) Own header, dictionary form keyed by label** | `Agent-DID: sig1="did:webvh:…"`, covered `"agent-did";key="sig1"`, `tag="agent-did"` unchanged | No collision. A request MAY also carry a separate WBA signature (`sig2`, own `Signature-Agent`, `tag="web-bot-auth"`) when the agent publishes a WBA key directory | Medium: header name, covered component, verifier rules, vectors |
| (iii) Adopt Web Bot Auth fully | `Signature-Agent` → JWKS directory, `keyid` = JWK thumbprint, DID only inside the directory or a JWK parameter | Native | High: the DID stops being the key identifier, which is the point of Agent-DID |

**Decision: (ii).** The DID stays the identifier and `keyid` stays a DID URL. Keying the member by label lets more than one signature share a request without ambiguity, which RFC 9421 permits and Web Bot Auth relies on. Publishing a WBA directory is optional and out of scope for rc.5: the RFC notes that both can coexist on one request. Verifiers reject a request whose `Agent-DID` member for the signature's label is missing, is not a String or carries parameters, and accept nothing from a bare-String `Signature-Agent` (no legacy path: rc.4 signatures stop verifying, as every rc.5 wire change does).

Component order in §6.5 item 2 becomes `"@method" "@authority" "@path" "@query" "content-digest" "date" "agent-did";key="<label>"`.

### D-8b. `Multikey` verification methods

`[RFC]` #249.

| Option | New documents | Reading rc.4 logs |
|---|---|---|
| **(i) Emit `Multikey`, accept both on read** | `Multikey` | `Ed25519VerificationKey2020` with the same `publicKeyMultibase` form stays valid |
| (ii) Emit `Multikey`, reject the old type | `Multikey` | rc.4 identities must be recreated |
| (iii) Keep `Ed25519VerificationKey2020` | unchanged | unchanged |

**Decision: (i).** rc.4 logs are published and their entries are signed: a verifier cannot rewrite them, and the key encoding is identical, so accepting the old type costs nothing in security. New documents use `Multikey` with the `https://w3id.org/security/multikey/v1` term, which `contexts/v1.jsonld` already defines (ADR-003). The document guard accepts exactly these two types for Ed25519 keys and rejects others, which also closes the current gap of not checking `type` at all. The W3C DID Core suite run (`conformance:did-core`) is repeated on the new documents.

### D-8c. Optional model and prompt commitments

`[RFC]` #250.

**Decision:** `agentMetadata.coreModelHash` and `agentMetadata.systemPromptHash` become **OPTIONAL**. When present, they keep the §4.3 format (salted commitment or immutable URI). RFC-001 states that they are **assertions by the controller**: a match proves that the controller committed to that value when it signed the log entry, not that the agent runs that model or prompt. A verifier MUST NOT treat a missing value as a failure, and MUST NOT treat a present value as evidence of runtime behaviour. SDK create/update APIs make both parameters optional in TS and Python.

Alternative considered: keep them REQUIRED and allow an explicit `none` value. Rejected: it adds a sentinel every verifier must special-case and says nothing more than absence.

### D-8d. Agent metadata as a Verifiable Credential

`[RFC]` #251.

**Decision:**

- New credential type `AgentMetadataCredential` (W3C VC Data Model 2.0). `issuer` = the controller DID; `credentialSubject.id` = the agent DID; the subject carries the `agentMetadata` members (`name`, `description`, `version`, `capabilities`, `memberOf`, and the optional commitments of D-8c).
- Proof: Data Integrity, cryptosuite `eddsa-jcs-2022`, `proofPurpose: assertionMethod`, signed by a key in the controller's `assertionMethod`. JCS keeps the canonicalization we already use (RFC 8785) and needs no JSON-LD processing.
- Verification checks the proof, that `issuer` is the agent document's `controller`, that `credentialSubject.id` is the agent DID, `validFrom` / `validUntil`, and that the agent DID is not deactivated.
- Linking: the credential is presented out of band (A2A Agent Card, MCP, request body). A DID document MAY point to a hosted copy with a `service` entry of type `LinkedVerifiablePresentation` (DIF Linked VP); the SDKs do not fetch it during DID resolution.
- `agentMetadata` stays in the DID document for rc.5 with the same members; the credential is an additional, selectively shareable form, not a replacement. Moving claims out of the document is a post-1.0 question.
- Conformance: no claim of VC 2.0 or `eddsa-jcs-2022` conformance unless a CI job verifies the W3C `vc-di-eddsa` test vectors with our implementation (planned in WP-46). Until then the docs say "aligned with".

## Consequences

- All four change the wire and land before the wire-freeze re-pin of the rc.5 release: HTTP vectors, interop vectors, did:webvh log vectors, key-at-time vectors and the JSON-LD context fixtures are regenerated once, in the order above.
- rc.4 HTTP signatures do not verify under rc.5 (D-8a). rc.4 DID logs still resolve and verify (D-8b (i)).
- Both SDKs, every integration, A2A and LangChain JS change in the same PRs (parity rule). Migration guides `MIGRATION-1.0-rc.4-to-rc.5.md` gain one section per item.
- RFC-001 §4.2, §4.3, §6.5 and a new credential section change; each goes through its `[RFC]` issue first (GOVERNANCE.md).
- Web Bot Auth is a moving draft. We use our own header name precisely so that its changes do not break us; the RFC cites the draft revision it was compared against and claims no Web Bot Auth conformance.
