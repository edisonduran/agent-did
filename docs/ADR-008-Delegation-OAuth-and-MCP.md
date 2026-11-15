# ADR-008: Delegation, the OAuth bridge and MCP

- **Status:** Accepted (2026-11-15)
- **Deciders:** Maintainer
- **Applies from:** `1.0.0-rc.5`
- **Discussion:** `[RFC]` issue to be opened after the maintainer accepts the options

## Context

RFC-001 already fixes *which key* may sign a delegation or exercise one: §6.2.1.3 maps the artifact kind `delegation` to `capabilityDelegation` and `invocation` to `capabilityInvocation`, both SDKs expose that table, and documents can list those relationships (`additionalVerificationRelationships`). What is missing is everything around it:

1. **No delegation artifact.** There is no format in which a DID grants another DID a scoped, expiring authority, no rule for a chain of such grants, and no verifier for it. The relationship table names APS `AuthorityDelegationV1` as an example, but Agent-DID has no format of its own, so two Agent-DID implementations cannot exchange a delegation.
2. **No way to exercise one over HTTP.** The request profile of §6.5 always requires `assertionMethod` and carries no authority beyond "this request comes from this DID".
3. **No bridge to OAuth.** Most APIs an agent calls, and every MCP server that requires authorization, speak OAuth 2.x. An agent with a DID still needs a separate client secret or key pair to get an access token.

External state, checked on 2026-11-15:

- **MCP authorization** (revision 2026-07-28) is OAuth 2.1 with Protected Resource Metadata (RFC 9728), Resource Indicators (RFC 8707) and, as the preferred client registration, OAuth Client ID Metadata Documents (CIMD, `draft-ietf-oauth-client-id-metadata-document-00`): the `client_id` is an `https` URL to a JSON document the authorization server fetches; clients "MAY use `private_key_jwt`" with a `jwks` or `jwks_uri` in that document. Dynamic Client Registration is deprecated. The stable auth extension **OAuth Client Credentials** (2026-07-28) is the machine-to-machine path and recommends JWT client authentication (RFC 7523, `private_key_jwt`). MCP servers MUST NOT accept or pass on tokens other than their own; nothing forbids an additional request signature.
- **RFC 7523bis** (`draft-ietf-oauth-rfc7523bis-09`, March 2026, submitted to the IESG): the client assertion's `aud` MUST be the authorization server's issuer identifier as its only value; clients MUST type it `typ: client-authentication+jwt`; servers SHOULD NOT reject untyped assertions.
- **RFC 9864** (October 2025) deprecates the polymorphic JOSE `alg` `EdDSA` in favour of `Ed25519`. Authorization server support for `Ed25519` is still uncommon; A2A 1.0 Agent Card signatures (ADR-006 D-9a) use `EdDSA`.
- **Authorization Capabilities (ZCAP)**: W3C CCG draft v0.4, dormant and restarted in the CCG in April 2026. It is the model the DID Core relationships `capabilityDelegation` / `capabilityInvocation` come from: a capability names an `invocationTarget`, a `controller` (who may invoke or delegate it), optional `allowedAction` and `expires`, and a `parentCapability`; a delegated capability carries a Data Integrity proof with `proofPurpose: capabilityDelegation` and a `capabilityChain`. The DIF Delegated Authorization task force found ZCAP and UCAN to be the only reviewed formats with chained delegation. UCAN is DAG-CBOR / JWT based and uses `did:key` principals.
- The SDKs already implement `eddsa-jcs-2022` Data Integrity proofs (ADR-006 D-8d, `AgentMetadataCredential`) and check them against the W3C `vc-di-eddsa` vectors in CI.

## Decision

Options per item; the recommended option is in bold. The maintainer accepted the recommended option of every item on 2026-11-15.

### D-12a. Delegation artifact

| Option | Format | Proof | Fit |
|---|---|---|---|
| **(i) ZCAP-shaped capability** | JSON object with ZCAP v0.4 member names (`id`, `parentCapability`, `invocationTarget`, `controller`, `allowedAction`, `expires`) and the `https://w3id.org/zcap/v1` context | One `eddsa-jcs-2022` Data Integrity proof, `proofPurpose: capabilityDelegation`, `capabilityChain` | Same relationship names as DID Core and RFC-001 §6.2.1.3; reuses the D-8d proof code; JSON, no JSON-LD processing (JCS) |
| (ii) VC 2.0 `AgentDelegationCredential` | Credential issued by the delegator about the delegate | `eddsa-jcs-2022`, `proofPurpose: assertionMethod` | Reuses D-8d almost unchanged, but a VC is a claim, not an authority: chaining and attenuation would be ours alone, and the proof purpose would contradict §6.2.1.3 |
| (iii) JWT (UCAN-like, or RFC 8693 `act` claims) | Signed JWT | JWS `EdDSA` | Familiar to OAuth stacks; UCAN is DAG-CBOR in its current version and `did:key` oriented; RFC 8693 tokens are issued by an authorization server, not by the agent |
| (iv) Own JSON format | Signed with the payload signature profile (§6.6) | Agent-DID signature | Simplest code; nobody else can read it |

**Decision: (i).** Profile, both SDKs and RFC-001 (new §6.7):

- **Root.** A chain starts at a root capability that is never signed: `id` = `urn:zcap:root:` + percent-encoded `invocationTarget`, `controller` = the DID(s) the *verifier* configures as owner of that target (`rootControllers`, keyed by target URL). The resource server decides who may grant access to its resources; a chain whose root has no configured controller is rejected.
- **Delegated capability.** REQUIRED: `@context` (`["https://w3id.org/zcap/v1"]` plus nothing else), `id` (`urn:uuid:…`), `parentCapability` (the parent `id`), `invocationTarget` (absolute `https` URL in the normalized form of §6.5 item 4), `controller` (the delegate DID), `expires` (RFC 3339), `proof`. OPTIONAL: `allowedAction` (non-empty list of strings; for HTTP these are request methods). No other members.
- **Proof.** One `DataIntegrityProof`, `cryptosuite: eddsa-jcs-2022`, `proofPurpose: capabilityDelegation`, `verificationMethod` a DID URL of the parent's `controller`, `created`, and `capabilityChain`: the list of ancestor `id`s from the root, whose last element is the full parent capability object when the parent is not the root (as ZCAP v0.4). The signing key MUST be an active Ed25519 key listed under the delegator's `capabilityDelegation`.
- **Attenuation, checked at every link.** `invocationTarget` equals the parent's, or extends the parent's path after a `/` (`https://api.example/files` → `https://api.example/files/reports`); `allowedAction` is a subset of the parent's (absent = everything the parent allows); `expires` is not later than the parent's. Maximum chain length (delegated capabilities after the root): verifier option, default 5, hard maximum 10.
- **Key state.** Every proof is evaluated against the delegator's DID document *when the chain is verified* (as §4.4 and §6.5), not at `created`: a deactivated or revoked delegation key, a deactivated DID or a key moved out of `capabilityDelegation` invalidates every capability below it. Revocation of a single capability: none in 1.0 (no status list); issuers keep `expires` short. This is stated as a limitation.
- **API.** `createCapability` / `create_capability` (delegate from the root or from a held capability), `verifyCapabilityChain` / `verify_capability_chain` (typed result with reason codes: `malformed_capability`, `unsupported_proof`, `chain_too_long`, `root_controller_unknown`, `attenuation_violation`, `expired`, `did_resolution_failed`, `did_deactivated`, `key_purpose_violation`, `key_not_authorized`, `signature_invalid`).
- **No conformance claim with ZCAP**: "aligned with the ZCAP v0.4 data model" only, since there is no ZCAP test suite. The `eddsa-jcs-2022` code keeps its existing vc-di-eddsa check.

### D-12b. Exercising a capability over HTTP (invocation)

| Option | Shape |
|---|---|
| **(i) Optional covered header in the §6.5 profile** | New header `Agent-DID-Capability`, a Dictionary keyed by signature label like `Agent-DID`; the member is a Byte Sequence holding the JCS bytes of the capability being invoked (its chain is inside its proof). When a signature covers `"agent-did-capability";key="<label>"` (after the required components), it is an `invocation`: the key MUST be under `capabilityInvocation` (not `assertionMethod`), the `Agent-DID` DID MUST be the capability's `controller`, the request URL MUST equal the `invocationTarget` or extend its path after a `/`, the method MUST be in `allowedAction` when present, and the chain MUST verify (D-12a). Same `tag="agent-did"`. |
| (ii) Separate profile with its own tag (`agent-did-invoke`) | Domain separation by tag; a verifier configured for plain requests rejects invocations outright |
| (iii) ZCAP's own `Capability-Invocation` header and invocation proof | Defined on top of the older draft-cavage HTTP signatures, not RFC 9421 |

**Decision: (i).** A plain §6.5 verifier that does not know the header still sees a valid identity signature when the key is also under `assertionMethod`, and an invocation-aware verifier gets the authority from the same signature. The member stays bounded: the verifier rejects a header over 8 KiB (`capability_too_large`) before parsing. Verification result gains `capability` (the verified leaf) and the invocation reasons above. This is an additive wire element: it must be in rc.5 because the wire freezes there.

### D-12c. OAuth bridge (the agent's DID key as OAuth client credential)

| Option | `client_id` | Where the authorization server gets the key | Needs DID support in the AS |
|---|---|---|---|
| (i) `client_id` = the DID | `did:webvh:…` | Resolves the DID | Yes; no authorization server does this today, and MCP requires an `https` `client_id` for CIMD |
| **(ii) CIMD or pre-registration, keys exported from the DID document; plus an Agent-DID-aware verifier** | `https` CIMD URL (MCP default) or a pre-registered id | `jwks` / `jwks_uri` built from the DID document | No; an AS that knows Agent-DID can verify against the DID instead |
| (iii) Token exchange: the agent presents a capability (D-12a) to the AS for an access token (RFC 8693 / RFC 7523 JWT bearer grant) | any | DID + capability chain | Yes, and a profile of our own on top |

**Decision: (ii); (iii) deferred** (it needs an authorization server profile nobody implements; the capability chain of D-12a already works directly against a resource server). Both SDKs:

- `createClientAssertion` / `create_client_assertion({ clientId, issuer, lifetimeSeconds? })`: JWS compact, header `alg` (D-12e), `typ: client-authentication+jwt`, `kid` = DID URL of the signing key; claims `iss` = `sub` = `clientId`, `aud` = `issuer` (the AS issuer identifier, single string, never the token endpoint), `jti` (128 random bits), `iat`, `exp` (default 60 s, maximum 300 s). The key MUST be under `authentication` (artifact kind `authentication`, §6.2.1.3): client authentication is proving control of the DID.
- `buildClientJwks` / `build_client_jwks(didDocument)`: a JWKS (`OKP`/`Ed25519`, `kid` = DID URL, `use: sig`) of the active `authentication` keys, for a CIMD `jwks`, a `jwks_uri` or pre-registration. On key rotation the operator republishes it; the docs say so, because an AS caches it.
- `buildClientMetadataDocument` / `build_client_metadata_document({ clientId, clientName, did, … })`: a CIMD document with `token_endpoint_auth_method: private_key_jwt`, `jwks` from the DID and an `agent_did` member naming the DID (an extension member, ignored by authorization servers that do not know it).
- `verifyClientAssertion` / `verify_client_assertion(jwt, { issuer, clientId, did })` for an authorization server or MCP server that knows Agent-DID: checks typ (accepts absent, per 7523bis), `aud` sole value = `issuer`, `iss` = `sub` = `clientId`, `exp`/`iat` with clock skew, lifetime ≤ 300 s, `jti` through the existing `NonceStore`, `kid` a DID URL of `did`, key active under `authentication` of the resolved document. Reasons in the style of §6.2.1.1.
- **The SDKs do not run OAuth flows** (no token requests, no discovery): they produce and check the assertion and the metadata. Transport stays in the integration (D-12d) or the caller.
- No conformance claim with RFC 7523 / 7523bis / CIMD beyond "aligned with"; the CI job decoding our assertions with an independent JOSE library (`jose` in TS, `PyJWT`/`joserfc` in Python, test-only) is the evidence for "standard JWS".

### D-12d. MCP scope (what WP-51 builds)

| Option | Deliverable |
|---|---|
| (i) Docs only | A guide: CIMD + `private_key_jwt` with the D-12c helpers, request signing as an extra layer |
| **(ii) New Python integration `integrations/mcp`** on the official `mcp` Python SDK | Client: an `httpx.Auth` that gets tokens through the OAuth Client Credentials extension with a DID client assertion and signs each MCP HTTP request (§6.5, optionally with a capability, D-12b); server: an ASGI middleware that verifies the request signature (and capability) and exposes the verified DID to tool handlers; helpers to serve the CIMD document and JWKS. Governance rows, CI job, README, no claim of MCP conformance |
| (iii) (ii) plus a TypeScript integration on `@modelcontextprotocol/sdk` | Same for TS |

**Decision: (ii)** for rc.5, TS integration tracked for after 1.0. Five of the six integrations are Python, the SDK parity rule covers the SDKs (both get D-12c), and a second MCP integration doubles the maintenance before anyone uses the first. The OAuth part works with any MCP server that implements the Client Credentials extension; the request-signature part needs an Agent-DID-aware server and is optional.

### D-12e. JOSE algorithm name

| Option | Emit | Accept |
|---|---|---|
| **(i) `EdDSA` by default, `Ed25519` on request** | `EdDSA` (option `jwsAlg: 'Ed25519'`) | both, always with an Ed25519 key |
| (ii) `Ed25519` only (RFC 9864) | `Ed25519` | both |

**Decision: (i).** Authorization servers that accept Ed25519 assertions today almost all expect `EdDSA`, and the Agent Card signature (D-9a) emits `EdDSA`. A verifier never accepts any other curve: `EdDSA` with a non-Ed25519 key is rejected.

### D-12f. Vectors

- `fixtures/delegation-vectors.json`: deterministic keys and `created`/`expires`; positive chains of length 1–3 and one negative per reason of D-12a; invocation requests (D-12b) in `fixtures/interop-vectors.json` (HTTP section) with negatives for each invocation reason. Both SDKs, `interop:check`, wire-freeze re-pin (new files only).
- `fixtures/oauth-client-assertion-vectors.json`: fixed `iat`/`jti`, byte-exact JWS from both SDKs; negatives for `aud` as a list, token endpoint as `aud`, wrong `typ`, lifetime > 300 s, key not under `authentication`, `alg` with a wrong curve.
- Generator: `scripts/regenerate-delegation-vectors.js`.

## Implementation notes (WP-50, 2026-11-15)

- **Reasons.** Capability chains add `delegator_mismatch` (a proof not made by the parent's `controller` or a root controller) and `expired` to the list of D-12a; invocation adds `capability_missing`, `capability_too_large`, `invoker_not_controller`, `target_mismatch` and `action_not_allowed`, and keeps every §6.5 reason. The order is in RFC-001 §6.7 and §6.8.
- **Invocation order.** The cheap checks on the capability field (covered, size, form, invoker, target) run before the signature is checked, so a request with a bad capability costs no resolution; the chain is verified after the signature and the method last, against the chain's effective `allowedAction` (the last one set along the chain).
- **One verifier pipeline.** Both SDKs run invocation through the same request verifier as `verifyHttpRequestSignatureDetailed`, with an extension that sets the relationship to `capabilityInvocation` and adds the checks before and after the signature; the identity verifier is unchanged and ignores `Agent-DID-Capability`.
- **SDK documents.** The reference SDKs list the agent key under `authentication` and `assertionMethod` and add `capabilityDelegation` / `capabilityInvocation` only on request, so an invocation signed with that key also passes the identity verifier. This is the behaviour D-12b describes, not a leak: the capability grants nothing there.
- **Test-only JOSE libraries.** `jose` 5.10.0 (TypeScript; the 6.x line is published as ECMAScript modules only, which the Jest setup does not load) and `PyJWT[crypto]` 2.12.1 (Python) verify our assertions and sign assertions we verify, with `alg` `EdDSA`. They are dev dependencies only.
- **JSON numbers.** Python accepts an integral float (`1.0`, `1e9`) where an integer is required, as ECMAScript reads it, and rejects `NaN` / `Infinity`, so both SDKs give the same reason for the same assertion.
- **Vectors.** `fixtures/delegation-vectors.json` (23 chains, 8 targets, 8 field values, one signed invocation, 2 + 27 client assertion cases) is generated without the SDKs by `scripts/regenerate-delegation-vectors.js`, run in `interop:check` and pinned in the wire freeze.

## Consequences

- RFC-001 gains §6.7 (capabilities and invocation) and §6.8 (OAuth client authentication), and §6.5 item 2 gains the optional covered `agent-did-capability` component. `[RFC]` issue first (governance).
- New public API in both SDKs (snapshots regenerated with this ADR as the reason); no new runtime dependency (JWS and Data Integrity use existing code; JOSE libraries are test-only).
- Documents only need `capabilityDelegation` / `capabilityInvocation` when the agent delegates or invokes; nothing changes for agents that do not.
- New wire elements, all additive and optional: the capability format, the `Agent-DID-Capability` header and the client assertion profile. They enter the rc.5 freeze.
- Not in scope for 1.0: per-capability revocation, token exchange with capabilities (D-12c iii), a TypeScript MCP integration, caveats beyond target/action/expiry.
