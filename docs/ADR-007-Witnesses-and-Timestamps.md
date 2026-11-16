# ADR-007: did:webvh witnesses and RFC 3161 timestamps

- **Status:** Accepted (2026-11-15)
- **Deciders:** Maintainer
- **Applies from:** `1.0.0-rc.5`
- **Discussion:** `[RFC]` #262

## Context

Two questions about time and history have no answer in rc.4:

1. **Who else has seen this log?** A did:webvh log is self-certifying: every entry is signed by the controller's `updateKeys`. A controller (or whoever holds its keys) can still publish two different, equally valid logs to two audiences, or rewrite the tip before most verifiers have fetched it. did:webvh v1.0 answers this with **witnesses**: the `witness` parameter (`{threshold, witnesses: [{id: did:key…}]}`) names DIDs that must approve each entry with an `eddsa-jcs-2022` proof published in `did-witness.json` next to `did.jsonl`. A resolver rejects an entry whose approvals do not reach the threshold. Agent-DID rc.4 rejects every log that declares witnesses (ADR-002, condition 7), so an operator who wants this protection cannot use Agent-DID at all.
2. **When was this signed?** `verifySignatureAtTime` (RFC-001 §6.6.7) decides whether a key was authorized at the time an artifact states. That time is asserted by the signer. After a key is retired, a holder of the old key can sign with any earlier stated time, so the verifier answers `indeterminate` unless the caller passes `trustedTimeNotAfter`. Today the SDK takes that value on trust: "the SDK does not verify timestamp tokens". The usual evidence is an RFC 3161 timestamp token from a Time Stamping Authority (TSA), and every caller has to verify it on its own.

Both reference libraries already implement witness verification: `didwebvh-ts` 3.1.0 (`witnessProofs` option, `WitnessVerificationResult`) and `did-webvh` 1.0.1 (`resolve_witness_log` on the document source, `#witness-verification-failed`). The pinned DIF `didwebvh-test-suite` has two witness scenarios (`witness-threshold`, `witness-update`) with logs and `did-witness.json` files from several implementations; both SDKs currently classify them as "unsupported, must reject".

Neither SDK has an ASN.1/CMS stack. TSAs sign with RSA or ECDSA (P-256/P-384), not Ed25519, so the crypto-hygiene rule (`@noble/*`, `pynacl`/`hashlib`) does not cover them and this ADR has to justify a new dependency.

## Decision

Options per item; the recommended option is in bold. The maintainer accepted the recommended option of every item on 2026-11-15.

### D-11a. Scope of witness support

| Option | Create / update | Resolution | Witness side |
|---|---|---|---|
| (i) Resolve only | No witness parameter | Enforce thresholds of logs created elsewhere | None |
| **(ii) Resolve + configure + approve** | `witness` (`{threshold, witnesses}`) at create and update; update accepts the collected `witnessProofs` | Enforce thresholds | `createWitnessProof(log, versionId, witnessSigner)` / `create_witness_proof(...)`: a witness's approval of one entry, so an operator can run one and tests do not need a third party |
| (iii) (ii) + watchers | as (ii), plus `watchers` | as (ii), plus notifying watchers | as (ii) |

**Decision: (ii).** (i) leaves Agent-DID unable to create the logs it accepts. Watchers are a notification channel, not a verification rule, and no verifier decision depends on them: they stay deferred (ADR-002 condition 7 is amended to "watchers and portability remain deferred").

Rules for (ii):

- **Fetch.** `did-witness.json` is fetched by the SDK's own document sources, from the URL derived from the log URL (same directory), with the same SSRF guards, size limit, timeouts and fetch queue as `did.jsonl`. The libraries' own `fetch` stays disabled (`noNetworkFetch` / no-op source).
- **Fail closed.** If any entry in the resolved range has a non-zero threshold and the witness file is missing, malformed, too large, or its approvals do not reach the threshold, resolution fails (`did_resolution_failed`). There is no fallback to resolving without witnesses or to another source (integrity rule).
- **Publishing order.** The SDK does not publish anything. When an update changes or is governed by a witness rule, the caller collects approvals and publishes `did-witness.json` first, then `did.jsonl`, as did:webvh v1.0 requires. The SDK returns the candidate entry and checks the supplied proofs before returning the new log.
- **Metadata.** Resolution metadata gains `witnessThreshold` (string, `"0"` when none) and `witnesses` (list of DIDs) for the resolved version, so callers can see what protected it. Both are DID Core §7.3 value types.
- **Conformance.** The two DIF witness scenarios move from `unsupported` to positive cases in `fixtures/didwebvh-test-suite.json` and must resolve in both SDKs, with the official `did-witness.json`. Only that lets the docs say witness verification is checked against the DIF suite; nothing broader.

### D-11b. What an RFC 3161 token proves and how verification uses it

| Option | `messageImprint` covers | Effect |
|---|---|---|
| **(i) The signature bytes** | SHA-256 of the raw signature value (base64-decoded) | The token proves the signature existed at `genTime`; the same pattern as CAdES/JAdES signature timestamps |
| (ii) The signed payload | SHA-256 of the message bytes | Proves the payload existed, not that this key signed it then: a later signature over an old payload would inherit the old time |

**Decision: (i).** API, both SDKs:

- `verifyTimestampToken(token, signature, { trustAnchors, now? })` / `verify_timestamp_token(...)`: returns `{ status: 'valid', genTime, tsa }` or `{ status: 'invalid', reason }`. Checks: the token is a granted `TimeStampResp` or a bare `TimeStampToken` (CMS `SignedData` with `id-ct-TSTInfo`); the CMS signature verifies; the signer certificate carries the critical `id-kp-timeStamping` extended key usage and matches `ESSCertID`/`ESSCertIDv2`; the chain reaches one of the caller's `trustAnchors` (DER or PEM certificates) and every certificate is valid at `genTime`; `messageImprint` uses SHA-256, SHA-384 or SHA-512 and equals the hash of `signature`. Reasons: `token_malformed`, `imprint_mismatch`, `hash_algorithm_unsupported`, `signature_invalid`, `certificate_untrusted`, `certificate_invalid`.
- `verifySignatureAtTime` gains `timestampToken` + `tsaTrustAnchors`. When given, the SDK verifies the token and uses `genTime + accuracy` as `trustedTimeNotAfter`. A token that does not verify makes the result `invalid` with a new reason `timestamp_invalid`; it never degrades silently to "no evidence". `trustedTimeNotAfter` stays for callers with other evidence; passing both is an error.
- **Not in scope:** revocation of TSA certificates (OCSP/CRL needs network I/O and policy the caller owns; documented as the caller's responsibility, as with the trust anchors themselves), long-term archive timestamps, and requesting tokens. A pure `createTimestampRequest(signature)` that returns the DER `TimeStampReq` (nonce, `certReq: true`) is provided; sending it to a TSA is the caller's transport, so the SDK gains no new outbound network path.
- The token is an artifact next to the signature, not part of any signed bytes: no Agent-DID wire change.

### D-11c. Dependencies

| Option | TypeScript | Python |
|---|---|---|
| **(i) Maintained libraries, Python as an extra** | `pkijs` (BSD-3-Clause; pure JS on WebCrypto; RFC 3161 and CMS parsing, certificate chain validation) as a regular dependency | `rfc3161-client` 1.0.x (Trail of Bits, used by `sigstore-python`; Rust core over `cryptography`) as the optional extra `agent-did-sdk[timestamps]`; calling the API without it raises an error naming the extra |
| (ii) Hand-written ASN.1 on `@noble/curves` / `cryptography` | Own DER parser, ECDSA via `@noble/curves`, RSA via `node:crypto` | Own parser on `asn1crypto` + `cryptography` |
| (iii) Both optional | `pkijs` as an optional peer dependency, loaded lazily | as (i) |

**Decision: (i).** Hand-written CMS and certificate-path code is the kind of new security-critical code ADR-002 chose not to write. `rfc3161-client` is an extra because it ships native wheels and has none for Windows ARM64, a platform WP-8 committed to documenting honestly; the base install stays unchanged. `pkijs` has no native code, so a peer dependency would only add a loading path to test. The crypto-hygiene rule is amended in CLAUDE.md: "RFC 3161 tokens: `pkijs` (TS) and `rfc3161-client` (Python) only; Ed25519 stays on `@noble`/`pynacl`."

### D-11d. Vectors and conformance claims

There are no official RFC 3161 test vectors. Plan:

- `scripts/record-timestamp-vectors.js`: requests tokens from two public TSAs (FreeTSA and DigiCert) over the SHA-256 of a fixed test signature and stores the responses with the TSA chains in `fixtures/timestamp-vectors.json`. Run once by a maintainer, not in CI; the request carries only a hash of test data.
- Negative vectors from a test TSA built with OpenSSL in the same script (wrong EKU, non-critical EKU, expired certificate, imprint over another value, SHA-1 imprint, tampered `genTime`, untrusted root).
- CI: both SDKs verify every vector, and `openssl ts -verify` checks the positive ones as an independent implementation (`ci-timestamp-vectors.yml`).
- Docs: "RFC 3161 timestamp tokens verified with `pkijs` / `rfc3161-client`, cross-checked with OpenSSL". No claim of RFC 3161 conformance of our own code: the parsing and path validation are the libraries'.

## Implementation notes (WP-49, 2026-11-15)

- **pkijs 3.4.x, not 4.x.** pkijs 4 is published as ECMAScript modules only, and the SDK ships CommonJS too; 3.4.x ships both and depends on `asn1js` (pinned as a direct dependency, since the module imports it) and `@noble/hashes` 1.x, which the SDK already uses.
- **Reasons and order.** The libraries report failures differently (`rfc3161-client` cannot tell a bad CMS signature from a bad path), so both SDKs run the same checks in the same order and report one reason each: `token_malformed` (not DER, not exactly one signer, signer certificate not embedded), `not_granted`, `hash_algorithm_unsupported`, `imprint_mismatch`, `not_a_timestamping_certificate`, `verification_failed` (CMS signature or path to an anchor at `genTime`). Only status 0 (`granted`) is accepted, as `rfc3161-client` does.
- **ESSCertID is not checked separately.** The signer certificate is the embedded certificate named by the signer's `issuerAndSerialNumber`, as `rfc3161-client` does; neither SDK compares the `signingCertificate(V2)` hash. Substituting a different certificate with the same issuer and serial needs a misissuing CA, and the path is still checked to the caller's anchors.
- **Trust anchor first.** When the token embeds a certificate with the same subject and key as an anchor (DigiCert embeds a cross-signed copy of its root), the TypeScript SDK drops the embedded copy so the path ends at the anchor; pkijs otherwise follows the cross-signature and fails.
- **Unsorted certificate sets.** DigiCert sends the token's `certificates` SET OF unsorted (valid BER, not DER), which `rfc3161-client` rejects. The Python SDK sorts that set before parsing: it is not covered by the CMS signature and keeps its length, so nothing verified changes. The sorting is permanent: upstream closed trailofbits/rfc3161-client#339 (2026-11-15) as a duplicate of #333, not planned, because RFC 3161 requires DER and the library rejects non-conforming responses by design. Without it, Python could not verify tokens from DigiCert, Sectigo or GlobalSign.
- **Recording.** The fixture was recorded on 2026-11-15; the recording script ran four times that day while it was being fixed, each time sending only the SHA-256 of a TEST-ONLY signature. `openssl ts -verify` checks the chain at the current time by default, so the cross-check passes `-attime` with each token's `genTime`.
- **Witness sources.** Only `WebvhDIDDocumentSource` fetches `did-witness.json` (`getDidWitnessFileByReference`); a log with witnessed entries served through another source fails closed. The Python SDK removes witnessing with `REMOVE_WITNESSES` (its update API uses `None` for "unchanged"), where TypeScript uses `null`. `did-webvh` 1.0.1 checks an entry only against the rule in force before it; the Python adapter adds the `didwebvh-ts` rule (an entry that switches witnessing on is approved under its own rule) so both SDKs accept the same logs.

## Consequences

- did:webvh logs with witnesses resolve instead of being rejected; logs without witnesses behave as before. A witnessed DID costs one extra fetch per resolution.
- `verifySignatureAtTime` can answer `valid` instead of `indeterminate` for signatures made before a key retirement, with evidence the SDK checked itself.
- New public API in both SDKs (snapshots regenerated with this ADR as the reason), one new TS dependency, one Python extra.
- No change to signed bytes, document content or HTTP signatures: the wire freeze re-pin only gains new fixture files.
- RFC-001 §6.6.7 (trusted time), the did:webvh section (witnesses) and ADR-002 condition 7 change; the `[RFC]` issue comes first.
