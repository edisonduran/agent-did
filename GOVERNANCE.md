# Governance

How decisions are made in Agent-DID, who can merge and release, and how someone becomes a maintainer. This document describes what the project does today; where it says "goal", the project is not there yet.

## Status

- **One maintainer today** ([@edisonduran](https://github.com/edisonduran), see [`.github/CODEOWNERS`](.github/CODEOWNERS)). Every merge and every release depends on that person. This is a known risk, not a design goal.
- **Goal: at least two maintainers** with merge rights and with admin access to the project's assets (below), so that no single absence stops reviews, security fixes or releases. The process to add one is in [Becoming a maintainer](#becoming-a-maintainer).

## Roles

| Role | Who | What they can do |
|---|---|---|
| **Contributor** | Anyone | Open issues and pull requests, review, take part in `[RFC]` discussions. |
| **Reviewer** | Contributors who review regularly | Their approvals count as input; they do not merge. |
| **Maintainer** | Listed in `CODEOWNERS` | Merge, release, triage security reports, decide on normative changes together with the other maintainers. |

## How decisions are made

- **Ordinary changes** (bug fixes, tests, docs, CI, dependencies): a pull request that passes CI and is approved by a maintainer.
- **Normative changes** (anything that changes [RFC-001](docs/RFC-001-Agent-DID-Specification.md) text, signature bases, canonicalization, hash URIs, DID log formats or verification rules):
  1. Start with an issue using the `[RFC]` template ([`rfc-feedback`](.github/ISSUE_TEMPLATE/rfc-feedback.yml)), stating the problem, the proposed change and the compatibility impact.
  2. Discuss in the issue. Maintainers decide when the discussion has converged; objections are answered in the issue, not dismissed.
  3. The change lands in **both SDKs in the same pull request**, with updated shared vectors, an entry in [`docs/RFC-001-CHANGELOG.md`](docs/RFC-001-CHANGELOG.md) and [`CHANGELOG.md`](CHANGELOG.md), and migration guides. See [CLAUDE.md](CLAUDE.md) and the [deprecation policy](docs/DEPRECATION-POLICY.md) for the compatibility rules.
  4. Wire or format changes are breaking and go into a new release candidate, never into an already published one.
- **Public API changes**: the public API snapshots are regenerated deliberately, with the reason explained in the pull request. A snapshot is never regenerated only to make a check pass.
- **Disagreement between maintainers**: discuss in the pull request or issue. If there is no agreement, the change does not land; the proposer may narrow it. With a single maintainer the maintainer decides and writes the reasoning in the pull request.
- **Conformance claims** (did:webvh, RFC 9421, RFC 8785 and others) are made only when a CI job verifies them against the specification's official vectors or an independent implementation, as recorded in the [External Conformance Matrix](docs/External-Conformance-Matrix.md).

## Merging

- Everything goes through a pull request from a branch; Conventional Commits are used.
- CI must be green. Workflows and release automation (`/.github/`) and `SECURITY.md` are owned by maintainers in `CODEOWNERS`.
- **Goal once there are two maintainers:** a maintainer does not merge their own normative, API or release-automation change without another maintainer's approval.

## Releases

- All packages of a release train are versioned together and released from one tag (`v1.0.0-rc.N`, later `v1.0.0`); see [`docs/RELEASE-1.0-CRITERIA.md`](docs/RELEASE-1.0-CRITERIA.md) and [`docs/SDK-Release-Checklist.md`](docs/SDK-Release-Checklist.md).
- Packages are published by the `Publish 1.0 Release Train` workflow (npm provenance, PyPI trusted publishing). Some npm operations need two-factor authentication from a maintainer's own machine.
- The stable `v1.0.0` is gated by the criteria in the release-criteria document, including a 30-day green window of the core workflows.

## Security

Vulnerabilities are reported privately and handled as described in [SECURITY.md](SECURITY.md). Unpatched vulnerabilities are never described in public commits, pull requests, issues or tracked docs. A fix ships with an advisory when users must act on it; the decision is the maintainers'.

## Project assets and continuity

The project depends on assets that, today, a single person administers. The goal is that at least two maintainers hold admin access to each:

| Asset | Used for |
|---|---|
| GitHub repository and its settings (branch protection, secrets, environments) | Merges, CI, releases |
| npm organization `@agentdid` | Publishing the TypeScript packages |
| PyPI projects (`agent-did-*`) and their trusted-publisher configuration | Publishing the Python packages |
| Domain `agent-did.org` | The JSON-LD context URL, project contact addresses |
| Security contact mailbox | Receiving vulnerability reports |

## Becoming a maintainer

A contributor can be proposed by any maintainer after a sustained record of useful contributions and reviews, including at least some changes to the specification or to both SDKs, and a demonstrated care for compatibility and security. The proposal is made in a private discussion among the maintainers and, if accepted, the new maintainer is added to `CODEOWNERS` and receives the access above. The reasons for the decision are not published about the people involved.

A maintainer who is inactive for six months, or who asks to step down, is moved to emeritus status: their name is kept in the project's history and their access is removed.

## Code of conduct

All participation follows the [Code of Conduct](CODE_OF_CONDUCT.md). Conduct reports go to the address in that document.

## Changing this document

Through a pull request. Changes to the decision rules need the approval of every maintainer.
