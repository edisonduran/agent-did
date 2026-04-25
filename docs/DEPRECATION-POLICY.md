# Deprecation and Breaking Change Policy

## Purpose

Agent-DID is in a pre-1.0 Public Review phase. That is the right time for strong feedback, but it is also the moment when maintainers need to be explicit about how change is handled.

This policy defines how the project communicates deprecations, breaking changes, and support expectations across:

- the RFC-001 specification
- the TypeScript SDK (`@agentdid/sdk`)
- the Python SDK (`agent-did-sdk`)
- repository-shipped integrations and examples

## Current Compatibility Phase

Agent-DID is currently **pre-1.0** and under **Public Review**.

That means:

- the RFC can still evolve based on community feedback
- the SDKs are usable today, but some public APIs and wire-level expectations may still change
- maintainers will prefer compatibility when possible, but correctness, interoperability, and security take priority over short-term stability

## Versioning Expectations

### Patch releases

Patch releases should not intentionally introduce breaking changes.

Typical patch-release work includes:

- bug fixes
- documentation corrections
- test-only changes
- internal refactors with no public behavior change
- low-risk security hardening that does not change public APIs or wire behavior

### Minor releases

Before v1.0, **minor releases may include breaking changes** when one of the following is true:

- the RFC changes during Public Review
- an interoperability defect must be corrected
- a security issue requires a behavior change
- an API surface is still experimental and needs simplification

When a minor release contains a breaking change, maintainers will document it explicitly in release notes and, when practical, provide migration guidance.

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

## What Counts as a Breaking Change

The following should be treated as breaking unless explicitly documented otherwise:

- changing method names, parameter names, or required fields in the TS or Python SDKs
- changing DID document field semantics or requiredness
- changing HTTP signature header semantics, covered components, or verification defaults
- changing revocation, key rotation, or resolution behavior in a way that can flip a previous pass to a fail
- changing canonical serialization rules used by signing or verification
- changing package names, import paths, or integration bootstrap APIs

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
- Integrations: current repository `master`

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