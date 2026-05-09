# Sprint 1 Adversarial Review - Crypto and Signing Surfaces

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
| A-08 | Low | Parser hardening | The HTTP signature parser/verifier paths still lack property-based or fuzz coverage for malformed `Signature` / `Signature-Input` dictionaries. | Deferred post-`1.0.0`. This is a real hardening opportunity but not a blocker after the current regression coverage additions. |
| A-09 | Low | Verification policy strictness | The verifier intentionally hard-fails unsupported signing algorithms by skipping non-`ed25519` candidates instead of negotiating broader algorithm support. | Accepted for `1.0.0`. This is a deliberate compatibility floor consistent with the current release scope. |
| A-10 | Low | Historical verification semantics | Historical verification still relies on retained deactivated keys in resolved document/history state; external persistence and cache-eviction policy remain part of the trust boundary. | Accepted for `1.0.0`. The repo now has explicit multi-cycle regression coverage, but long-term persistence policy remains an implementation concern. |

## Review Notes

1. The current branch resolves the only finding that rose to high severity in the reviewed code path: IPv6-mapped SSRF handling on the TypeScript side.
2. The reviewed HTTP-signature implementation is intentionally stateless at verification time. That is defensible for `1.0.0`, but only because the nonce-cache responsibility is made explicit and now covered by release evidence.
3. The reviewed identity-composition helpers in TS and Python remain consistent on deterministic failure reasons and signing-purpose enforcement.
4. The remaining findings are hardening and operational-policy items, not reasons to block Sprint 1 completion.