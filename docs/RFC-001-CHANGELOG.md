# RFC-001 Changelog

This document tracks normative and materially relevant editorial changes to RFC-001 independently from the ecosystem release train tracked in [../CHANGELOG.md](../CHANGELOG.md).

> **Current canonical text:** [RFC-001-Agent-DID-Specification.md](RFC-001-Agent-DID-Specification.md) is now at `0.3-pivot-pattern-on-webvh`.

---

## [0.3-pivot-pattern-on-webvh] - 2026-05-06

### Decision Trigger

- Public review feedback in `decentralized-identity/didwebvh#277` exposed a structural mismatch between the current RFC text, the shipped SDK behavior, and the project positioning.
- ADR-001 accepted the pivot to Agent-DID as an application pattern on top of `did:webvh`.

### Planned Normative Changes

- `did:webvh` becomes the recommended/default DID method for agent identifiers.
- `did:agent` is removed as a standalone DID method from RFC-001.
- EVM anchoring moves out of the normative reference architecture into an optional deployment profile.
- The A2A Identity Composition Contract, `agentMetadata` extension, and HTTP Message Signatures profile remain the normative differentiators of Agent-DID.
- Compliance no longer requires mandatory on-chain/off-chain separation.

### Planned Document Moves

- Move the EVM ABI/reference registry material to `RFC-001-EVM-Profile.md`.
- Update `PHILOSOPHY.md`, `README.md`, `QUICKSTART.md`, and `RFC-001-Compliance-Checklist.md` to align with the pivot.

### Rationale

- The codebase already produces agent identities on existing DID methods rather than a live `did:agent` method implementation.
- A single recommended method removes positioning ambiguity and aligns the project with the `did:webvh` ecosystem.
- The pivot preserves the project value at the application layer instead of competing at the DID method layer.

### Phase Status

- ADR recorded and accepted.
- Core RFC sections refactored to make `did:webvh` the normative default method.
- Optional EVM profile extracted to `RFC-001-EVM-Profile.md`.
- README, PHILOSOPHY, and QUICKSTART aligned to the `did:webvh` default positioning without overstating current SDK automation.
- The A2A Identity Composition Contract now includes the canonical `did:webvh` controller-to-agent recursion model and keeps unknown-method handling as a compatibility fallback.
- Compliance initially reflected the post-pivot reality: core runtime was short of `did:webvh` conformance, and implementation tracking was opened in issue `#64`.
- The TypeScript SDK now resolves `did:webvh` via `did.jsonl` in the universal resolver / HTTP bootstrap path and creates canonical `did:webvh` identities by default, auto-bootstrapping a local `did:webvh` controller root while keeping `did:agent` only as an explicit compatibility mode.
- The Python SDK now resolves `did:webvh` via `did.jsonl` in the universal resolver / HTTP bootstrap path and mirrors the same canonical default-create/bootstrap behavior, closing direct cross-SDK parity on the web-native path.
- Both SDKs now wire controller-chain resolution into signature verification, rejecting inactive/unresolvable controller roots while preserving key-purpose enforcement for active chains.
- Shared interoperability fixtures now include both legacy and `did:webvh` vectors, and both SDKs validate those vectors under the controller-chain-aware verification model.
- Python RFC-001 conformance now passes end-to-end against the canonical `did:webvh` default profile, and the compliance checklist was updated to mark all MUST controls as PASS.
- Both SDKs now support candidate-URL failover for `did:webvh` DID-log fetches in the production HTTP resolver profile, and the HA smoke drills now exercise the canonical web-native path instead of only the legacy registry/RPC path.
- Both SDKs now retain per-revision document snapshots internally and can export canonical `did:webvh` lifecycle state as `did.jsonl`, allowing local lifecycle flows to produce a persistable DID-log artifact instead of only in-memory audit metadata.
- Both SDKs can now import that exported `did:webvh` DID log back into runtime state, restoring the latest document plus the base audit trail after process reset; the remaining P2 gap is persistence/recovery outside the in-memory process boundary.
- Both SDKs now also support file-backed save/load wrappers around that `did:webvh` DID log, closing the local persistence/recovery loop for process restarts and leaving real external endpoint coverage as the next unresolved production-hardening slice.
- Both SDKs now expose source-backed DID-log persistence/recovery hooks on top of the resolver document-source abstraction, so external storage adapters can plug into the same `did:webvh` export/import path without forcing filesystem-only persistence.
- Both SDKs now ship a concrete filesystem-backed `DIDDocumentSource` adapter for document and raw `did:webvh` DID-log roundtrips, closing the first reusable storage-adapter implementation over the new source-backed persistence hooks.
- Both SDKs now also ship opt-in external `did:webvh` smoke wrappers parameterized by URL/DID so maintainers can validate real network resolution against published logs without binding the baseline conformance suite to a third-party endpoint.
- Both SDKs now load a repo-managed public `did:webvh` smoke-target manifest by default, backed by a checked-in `did.jsonl` fixture published through raw GitHub plus a jsDelivr mirror, while preserving explicit env-var overrides for alternate manifests and local/private validation.
- Both SDKs now extend `HttpDIDDocumentSource` into a writable remote adapter that can store DID documents and raw `did:webvh` DID logs over HTTP(S), providing the first non-filesystem concrete remote backend over the source-backed persistence contract.
- Both SDKs now also ship a `BearerTokenHttpDIDDocumentSource` wrapper that injects bearer or custom token headers into the existing HTTP adapter flow, covering authenticated API/gateway storage backends without adding provider SDKs.
- Both SDKs now also ship a presigned/object-storage style adapter that separates public read URLs from upload/write URLs, covering the common CDN + presigned PUT/POST backend pattern without adding provider-specific SDK dependencies.
- The presigned/object-storage adapter now splits document reads from DID-log reads as well, and both SDKs now ship an `S3CompatibleDIDDocumentSource` that maps DID references into bucket/object-key layouts plus optional presigned uploads for S3-compatible backends without pulling in provider SDKs.
- Both SDKs now also ship an `AwsSigV4S3DIDDocumentSource` that signs S3-compatible GET/PUT/POST requests with AWS Signature Version 4, landing the first authenticated provider-specific managed backend on top of the new storage-adapter stack without adding AWS SDK dependencies.
- Maintainer communication to contributors remains intentionally deferred until the broader doc-alignment work after RFC v0.3.