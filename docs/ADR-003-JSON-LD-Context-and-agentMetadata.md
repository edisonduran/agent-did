# ADR-003: JSON-LD context and placement of `agentMetadata`

- **Status:** Accepted (2026-11-04)
- **Date:** 2026-11-04
- **Work item:** M-19 (`1.0.0-rc.4` train)
- **Deciders:** Agent-DID maintainers
- **Related:** [RFC-001 §4](RFC-001-Agent-DID-Specification.md), [ADR-002](ADR-002-did-webvh-v1.0-Implementation.md), [RELEASE-1.0-CRITERIA](RELEASE-1.0-CRITERIA.md)

## Context

Every Agent-DID document lists `https://agent-did.org/v1` in its `@context`, and RFC-001 §4.1 calls the document "JSON-LD". Until this ADR nothing was published at that URL, and no file in the repository defined the terms. Consequences:

- A JSON-LD processor cannot load the context. A verifier that dereferences it fails, and one that does not has no definition of `agentMetadata`, `coreModelHash`, `systemPromptHash`, `capabilities`, `memberOf` or `complianceCertifications`.
- `https://www.w3.org/ns/did/v1` does not define `created`, `updated`, `publicKeyMultibase`, `deactivated`, `blockchainAccountId` or the `Ed25519VerificationKey2020`, `Multikey` and `EcdsaSecp256k1RecoveryMethod2020` types either. In strict (safe-mode) expansion those are dropped or rejected, so even the standard-looking part of our documents was undefined.
- The document hash (`documentRef`), the did:webvh SCID and every log entry cover the `@context` value. Whatever we decide must not change it silently.

Two questions were open:

1. Publish the context, or remove it from `@context`.
2. Keep `agentMetadata` as a property of the DID document, or issue it as a Verifiable Credential signed by the controller.

## Options

### Q1. The context

- **C1. Publish `contexts/v1.jsonld`, keep the identifier `https://agent-did.org/v1`.** No wire change.
- **C2. Remove `https://agent-did.org/v1` from `@context`.** A wire change (document hash, SCID, every log). It leaves `agentMetadata` undefined, which is invalid under strict JSON-LD processing, unless the terms move elsewhere.

### Q2. Where `agentMetadata` lives

- **M1. Property of the DID document (status quo).** The did:webvh log versions it with the key material, so a change to the model or prompt commitments is a new, controller-signed log entry. Resolution returns it with no second fetch.
- **M2. Verifiable Credential issued by the controller.** Fits W3C vocabulary and lets capabilities evolve without rewriting the DID log. But a VC needs its own context and proof suite, status and revocation story, a second resolution path and a binding from the DID document to the credential. It is a wire change, and every SDK, integration and the hash model (`documentRef`, M-06) would change in `rc.4`.

## Decision

**C1 + M1.** The change is purely additive and keeps all existing documents and logs valid.

1. **The context is published as `contexts/v1.jsonld`** and is the source for `https://agent-did.org/v1`. It defines, with the standard IRIs where they exist:
   - the Agent-DID terms: `agentMetadata` (with scoped `name`, `description`, `version`, `coreModelHash`, `systemPromptHash`, `capabilities`, `memberOf`), `complianceCertifications` (scoped `issuer`, `credentialSubject`, `proofHash`), `blockchainAccountId`, `deactivated`, in the vocabulary namespace `https://agent-did.org/vocab#`;
   - the terms the DID v1 context lacks and that our documents already use: `created`, `updated`, `publicKeyMultibase`, and the types `Ed25519VerificationKey2020`, `Multikey` and `EcdsaSecp256k1RecoveryMethod2020`.
2. **A published version is immutable.** `contexts/v1.jsonld.sha256` pins the file; CI fails if the file changes. Any change to a term is a new `contexts/v2.jsonld` with a new URL. Documents that already name `v1` keep their meaning.
3. **Verifiers SHOULD use the pinned copy**, not fetch the URL. RFC-001 §4.1 now says this: a fetched context is a network dependency and an attack surface, and the content is fixed by its hash. Agent-DID verification never needs JSON-LD processing: the SDKs treat documents as JSON (hashing is JCS, RFC 8785), so the `@context` is for consumers that do process JSON-LD.
4. **`agentMetadata` stays in the DID document.** The controller-issued VC is not adopted for 1.0. It remains compatible with this decision as an optional profile: `complianceCertifications` already links external credentials, and a future `agentMetadataCredential` property can be added in a new context version without touching existing documents.
5. **Evidence.** `CI — JSON-LD Context` (`npm run check:jsonld-context`) expands the did:webvh log vectors and `fixtures/jsonld-context-documents.json` (which exercises every term) in JSON-LD safe mode, failing on any undefined term, and checks the pin. The Python SDK has a matching test that the documents it builds use only defined terms. We claim that documents are *expandable with this context*, not conformance with a JSON-LD test suite.

## Hosting

The file lives in the repository. The maintainers must serve it, byte for byte, at `https://agent-did.org/v1` with `Content-Type: application/ld+json` (or `application/json`) and long-lived caching, and keep the `agentdid` vocabulary namespace `https://agent-did.org/vocab#` resolvable to human-readable documentation. Until the URL is live, the pinned copy in the repository is the only normative source, and RFC-001 §4.1 says so. **Publishing the URL is a release task, not a repository change.**

## Known gaps

- Upstream `didwebvh-ts` and `did-webvh` add implicit services of type `relativeRef` and `LinkedVerifiablePresentation` that no context defines, including the DID v1 context. They are not Agent-DID terms, so the check excludes them.
- `credentialSubject` inside `complianceCertifications` is a plain string, not an IRI, because the SDKs accept labels such as `SOC2-AI-Compliance`.

## Consequences

- **No wire change.** Document hashes, SCIDs, interop vectors and API snapshots are unchanged; no migration guide entry is required.
- A JSON-LD consumer can expand Agent-DID documents once the URL is served, or immediately with the pinned copy.
- Adding or renaming a term now requires a new context version and an RFC change, which is the intended cost.
- Revisit M2 (the VC profile) after 1.0 if a use case needs capabilities that change faster than the DID log should.
