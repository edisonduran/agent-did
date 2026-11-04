# Sprint 1 Adversarial Review - Crypto and Signing Surfaces

> **Status: historical.** This review covers the state of 2026-05-08. A later maturity review found issues in surfaces it did not examine; they were remediated in `1.0.0-rc.2` and `1.0.0-rc.3`. The conclusion "no release-blocking findings" below applies to the reviewed state only. See the [post-rc.3 addendum](#addendum-post-rc3-remediation-and-threat-model) and [Threat-Model.md](Threat-Model.md).

Fecha: 2026-05-08

## Scope and Inputs

This review was executed against the release-critical signing and verification paths for core `1.0.0`, using the repository adversarial-review prompt/task as guidance:

- `.github/prompts/bmad-review-adversarial-general.prompt.md`
- `_bmad/core/tasks/review-adversarial-general.xml`

Primary code reviewed:

- `sdk/src/core/AgentIdentity.ts`
- `sdk-python/src/agent_did_sdk/core/identity.py`
- `sdk/src/core/identity-composition.ts`
- `sdk-python/src/agent_did_sdk/core/identity_composition.py`
- `sdk/src/core/http-security.ts`
- `sdk-python/src/agent_did_sdk/core/http_security.py`

## Outcome

- Release-blocking findings: `0`
- Findings remediated in this branch: `4`
- Accepted or documented non-blocking findings: `6`

No finding in the current reviewed state blocks the Sprint 1 release train for core `1.0.0`.

## Findings

| ID | Severity | Surface | Finding | Disposition |
|---|---|---|---|---|
| A-01 | High | TS SSRF guard | The TypeScript HTTP target validator did not classify IPv6-mapped loopback/link-local hosts as private or reserved, leaving a bypass path for `::ffff:` forms. | Fixed in this branch. `sdk/src/core/http-security.ts` now normalizes IPv6-mapped IPv4 tails, with regression coverage in TS and Python tests. |
| A-02 | Medium | HTTP anti-replay evidence | Sprint 1 evidence did not explicitly prove verifier rejection beyond a `60s` skew boundary even though the verifier had the control. | Fixed in this branch with explicit TS and Python tests for `maxCreatedSkewSeconds=60`. |
| A-03 | Medium | HTTP anti-replay evidence | Sprint 1 evidence did not explicitly exercise the documented verifier-side nonce-cache pattern for duplicate request rejection. | Fixed in this branch with TS and Python tests that model the documented nonce-cache boundary. |
| A-04 | Medium | Lifecycle / historical verification | Sprint 1 evidence did not explicitly prove three rotation cycles on the canonical `did:webvh` path while preserving historical verification of the oldest key. | Fixed in this branch with TS and Python three-cycle regression tests. |
| A-05 | Medium | HTTP anti-replay design boundary | Duplicate-nonce rejection is not stateful inside the SDK verifier itself; it depends on caller-owned verifier cache discipline. | Accepted for `1.0.0`. This is an explicit design boundary already documented in `docs/Anti-Replay-HTTP-Signatures.md`; tests now make that boundary visible instead of implicit. |
| A-06 | Medium | Resolver / revocation freshness | Revocation and emergency rotation semantics still depend on resolver freshness and operator cache TTL choices. A stale resolver can delay rejection even when signing code is correct. | Accepted for `1.0.0`. The risk is already documented in `docs/RFC-001-A2A-Identity-Composition-Contract.md` and is treated as an operator hardening concern, not a core release blocker. |
| A-07 | Low | Verifier policy defaults | The default skew tolerance remains `300s`, which is generous for irreversible operations and could be too wide for some production policies. | Accepted for `1.0.0`. Callers can already override `maxCreatedSkewSeconds`; release guidance should prefer stricter values for sensitive paths. |
| A-08 | Low | Parser hardening | The HTTP signature parser/verifier paths still lack property-based or fuzz coverage for malformed `Signature` / `Signature-Input` dictionaries. | Addressed after this review by M-14: property tests and nightly fuzzing of the `Signature` / `Signature-Input` parsers (`ci-fuzz.yml`). Historical row, kept for traceability. |
| A-09 | Low | Verification policy strictness | The verifier intentionally hard-fails unsupported signing algorithms by skipping non-`ed25519` candidates instead of negotiating broader algorithm support. | Accepted for `1.0.0`. This is a deliberate compatibility floor consistent with the current release scope. |
| A-10 | Low | Historical verification semantics | Historical verification still relies on retained deactivated keys in resolved document/history state; external persistence and cache-eviction policy remain part of the trust boundary. | Accepted for `1.0.0`. The repo now has explicit multi-cycle regression coverage, but long-term persistence policy remains an implementation concern. |

## Review Notes

1. The current branch resolves the only finding that rose to high severity in the reviewed code path: IPv6-mapped SSRF handling on the TypeScript side.
2. The reviewed HTTP-signature implementation is intentionally stateless at verification time. That is defensible for `1.0.0`, but only because the nonce-cache responsibility is made explicit and now covered by release evidence.
3. The reviewed identity-composition helpers in TS and Python remain consistent on deterministic failure reasons and signing-purpose enforcement.
4. The remaining findings are hardening and operational-policy items, not reasons to block Sprint 1 completion.
## Addendum: post-rc.3 remediation and threat model

Added with M-15. The original findings above are unchanged. This addendum records what later work closed and where the end-to-end analysis now lives. Wording is deliberately neutral; the public advisory for the `rc.2` release is [GHSA-g97p-4qrw-9hvf](https://github.com/edisonduran/agent-did/security/advisories/GHSA-g97p-4qrw-9hvf).

| Work item | Surface | Outcome | Released in |
|---|---|---|---|
| M-01 | Controller key generation at creation | Keys come from a CSPRNG or an explicit signer; nothing is derived from public data. See the advisory. | `1.0.0-rc.2` |
| M-02 | `did:webvh` log format and verification | Logs are did:webvh v1.0 and verified in full on resolution and import. Proven against the DIF test suite in CI. | `1.0.0-rc.3` |
| M-03 | Lifecycle operations | Update, rotation and revocation are controller-signed log entries. | `1.0.0-rc.3` |
| M-04 | Canonicalization | RFC 8785 (JCS) in both SDKs, with shared vectors. | `1.0.0-rc.3` |
| M-05 | HTTP signatures | RFC 9421 profile with `NonceStore`, checked against Appendix B.2.6 and independent implementations. | `1.0.0-rc.3` |
| M-06 | Resolver integrity | `documentRef` hash verified; integrity failures never fall back. | `1.0.0-rc.3` |
| M-07 | Metadata commitments | Salted (`hash://hmac-sha256/`). | `1.0.0-rc.3` |
| M-14 | Parser robustness | Property tests and nightly fuzzing of the signature parsers, `did.jsonl` and multibase. Closes A-08 for the parsers. | `1.0.0-rc.4` train |

### Disposition of A-05 to A-10 against the threat model

The accepted findings are carried into [Threat-Model.md](Threat-Model.md):

| Finding | Where it appears |
|---|---|
| A-05 nonce cache boundary | Flow 4. The SDK now ships a `NonceStore` interface and an in-memory default; multi-instance verifiers still need a shared store. |
| A-06 resolver freshness | Flows 3 and 6, including the rollback caveat that did:webvh authenticates history but not currency. |
| A-07 skew default | Flow 4. |
| A-09 algorithm floor | Flow 4 (`alg="ed25519"` is part of the required profile). |
| A-10 historical verification | Flow 6. |

### Not covered by this review or by the original findings

The threat model records residual risks that no earlier review tracked: controller key compromise has no in-protocol recovery until pre-rotation is exposed, log hosts can roll back or withhold entries, `created` is signer-asserted, and resolver size and time bounds are unproven. These feed the scope of the independent review (M-16).
