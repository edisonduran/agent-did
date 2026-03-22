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

## Update Triggers

Update the relevant live documentation when a change affects any of the following:

- project-wide status
- roadmap completion or reopening
- CI coverage or workflow scope
- integration availability or maturity claims
- public package capabilities, examples, or installation guidance
- training or strategic material that states what is currently implemented

## Historical Documents

If the team decides not to keep a document current, it must be explicitly labeled as historical with a visible date or scope boundary.
