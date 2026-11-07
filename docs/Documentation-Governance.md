# Documentation Governance

## Objective

Define how this repository keeps documentation live, consistent, and aligned with the real project state.

## Core Rule

Documentation in this repository is treated as a live description of the current project state, not as an implicit historical snapshot.

If a change updates shipped functionality, roadmap completion, CI coverage, maturity level, or integration availability, the affected live documentation must be updated in the same PR.

## Canonical Sources Of Truth

1. `README.md`
Project-wide current status, open roadmap items, available integrations, and contributor-visible CI surface.

2. Package and integration `README.md` files
Public capabilities, installation guidance, examples, runtime coverage, and scope boundaries for that package.

3. Feature governance docs in `docs/`
Implementation checklists, review checklists, parity matrices, maturity assessments, and design documents that define whether a roadmap item is in progress, completed, or only pending maintenance.

4. `.github/workflows/`
The canonical source for what CI actually validates.

## Downstream Narrative Documents

Training materials, manuals, strategic assessments, and other narrative artifacts are downstream documents.

They must align with the canonical sources above and must not invent a conflicting project state.

## Conflict Resolution Rule

If two live documents disagree, the conflict must be resolved in the same PR instead of leaving both versions in circulation.

Release versions are checked mechanically: `npm run check:version-consistency` (CI — Version Consistency) fails when a live document names a release that the package manifests do not declare, when it calls an unpublished release "published", or when the manifests of the release train disagree with each other. When a doc gains a new statement about the current version, add a rule for it in `scripts/check-version-consistency.js`.

## Update Triggers

Update the relevant live documentation when a change affects any of the following:

- project-wide status
- roadmap completion or reopening
- CI coverage or workflow scope
- integration availability or maturity claims
- public package capabilities, examples, or installation guidance
- training or strategic material that states what is currently implemented

## Integration Governance Notes

### LangChain Integrations

Changes under `integrations/langchain/**` or `integrations/langchain-python/**` must update not only the affected package `README.md`, but also the LangChain governance artifacts when the change alters examples, parity expectations, security posture, observability claims, or release-facing behavior.

At minimum, review and update when needed:

- `docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md`
- `docs/F1-03-LangChain-Integration-Parity-Review-Checklist.md`

This rule exists because LangChain TS and Python are governed as a parity pair in this repository, not as isolated packages.

## Historical Documents

If the team decides not to keep a document current, it must be explicitly labeled as historical with a visible date or scope boundary.
