# Deprecation and Breaking Change Policy

## Purpose

Agent-DID has now frozen the public contract for the `1.0.0-rc.1` release train. That is late enough that compatibility rules must be explicit even though the final stable tag is still pending release validation.

This policy defines how the project communicates deprecations, breaking changes, and support expectations across:

- the RFC-001 specification
- the TypeScript SDK (`@agentdid/sdk`)
- the Python SDK (`agent-did-sdk`)
- repository-shipped integrations and examples

## Current Compatibility Phase

Agent-DID is currently in the **`1.0.0-rc.1` release-candidate phase**.

That means:

- RFC-001 text is treated as Stable for this release train
- the SDK public APIs, DID document shape, and runtime verification contract are expected to remain frozen
- remaining repo changes before `v1.0.0` should be limited to bugfixes, documentation corrections, packaging, CI hardening, and release operations
- if a public-contract change is still required, maintainers should cut another prerelease rather than slipping a breaking change into the active RC

## Versioning Expectations

### RC changes before `v1.0.0`

During the RC phase:

- fixes should preserve backward compatibility for the frozen public contract
- any intentional diff in the signature-level API snapshot, required DID document format, or default verification semantics is a release-contract change, not a routine bugfix
- deferred EVM/on-chain profile work may evolve independently, but it does not redefine the core `1.0` compatibility floor unless it changes the RFC, the shipped SDK API, or the web-native verification contract

### Historical pre-1.0 note

Before the `1.0.0-rc.1` freeze, minor releases could include breaking changes during Public Review. That exception no longer applies to the RC branch.

### Patch releases

Patch releases after `1.0.0` must not intentionally introduce breaking changes.

Typical patch-release work includes:

- bug fixes
- documentation corrections
- test-only changes
- internal refactors with no public behavior change
- low-risk security hardening that does not change public APIs or wire behavior

### Minor releases

Minor releases after `1.0.0` add backward-compatible functionality.

Typical minor-release work includes:

- additive APIs or helpers that do not break the existing signature-level public surface
- new optional integration capabilities
- new compatibility profiles or adapters that do not alter the core `did:webvh` contract
- editorial or operational updates that accompany backward-compatible feature growth

When a minor release adds public functionality, maintainers should update release notes and migration guidance when adoption steps are needed.

### Major releases

Major releases are required for incompatible changes, including:

- intentional diffs in the signature-level API snapshots
- changes to DID document requiredness or semantics
- breaking changes to verification defaults, signing semantics, or lifecycle behavior
- incompatible package renames, import-path changes, or bootstrap-surface changes

## Deprecation Window

When a non-security breaking change can be staged safely, the project aims to follow this pattern:

1. Mark the feature or behavior as deprecated in documentation and release notes.
2. Keep it available for at least one subsequent minor release when practical.
3. Remove it in a later minor release together with migration notes.

This is a target, not an absolute guarantee. Some fixes cannot safely wait, especially when security or spec correctness is involved.

## Security and Correctness Exceptions

The project may ship an immediate breaking change without a deprecation window when necessary to:

- fix a security vulnerability
- close a signature forgery, replay, or verification bypass path
- correct behavior that makes one SDK disagree with the RFC or the other SDK
- repair a public example or integration that teaches unsafe usage

In those cases, maintainers will still document:

- what changed
- why it changed immediately
- how to migrate

Recent example: SDK signature verification now enforces DID verification-relationship binding by default. Agent payload and HTTP signatures require `assertionMethod`, and a key listed only under another relationship such as `keyAgreement` fails with `key_purpose_violation`. Documents that previously placed signing keys only in `authentication` should add the appropriate signing relationship.

## What Counts as a Breaking Change

The following should be treated as breaking unless explicitly documented otherwise:

- changing method names, parameter names, or required fields in the TS or Python SDKs
- changing a public symbol in a way that changes the signature-level API snapshot (`sdk/public-api.signature.snapshot.txt` or `sdk-python/public-api.signature.snapshot.txt`)
- changing DID document field semantics or requiredness
- changing HTTP signature header semantics, covered components, or verification defaults
- changing revocation, key rotation, or resolution behavior in a way that can flip a previous pass to a fail
- changing canonical serialization rules used by signing or verification
- changing package names, import paths, or integration bootstrap APIs
- changing the core `did:webvh` release contract to depend on deferred EVM/on-chain profile contracts, ABIs, or deployment metadata

After `1.0.0`, any intentional diff in the signature-level public API snapshot must be treated as a **major-version** change unless the symbol is explicitly out of the public contract.

Changes limited to deferred EVM/on-chain profile contracts, ABIs, deployment metadata, or audit artifacts do **not** by themselves alter the core `1.0` compatibility contract unless they also change the RFC, the shipped SDK surface, or the release-critical web-native verification semantics.

## Communication Rules

When a deprecation or breaking change happens, maintainers should update the relevant sources of truth in the same PR:

- `README.md`
- package or integration `README.md`
- `docs/RFC-001-Agent-DID-Specification.md` when the change is normative
- parity matrices, review checklists, implementation checklists, or maturity docs when the change alters governance claims
- changelog or release notes for the published package(s)

## Support Window

Until v1.0, the project supports the **latest published version** of each package line.

- TypeScript: latest `@agentdid/sdk`
- Python: latest `agent-did-sdk`
- Integrations: current repository `main`

Older versions may receive critical fixes at maintainer discretion, but contributors and adopters should assume that the latest published version is the supported baseline.

## RFC Change Handling

Normative RFC feedback should be submitted through the RFC feedback issue template or GitHub Discussions.

When a normative change is accepted:

1. the RFC version or status note should be updated
2. conformance fixtures and tests should be updated
3. both SDKs should be aligned before the change is considered complete
4. migration impact should be documented if the change is not backward compatible

## Goal

The goal of this policy is not to freeze the project too early. The goal is to make change legible, predictable, and reviewable while Agent-DID matures in public.