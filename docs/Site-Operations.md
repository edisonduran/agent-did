# agent-did.org Site Operations

**Status:** Stable · **Audience:** Maintainers

`agent-did.org` serves the few URLs that Agent-DID documents and security reporters depend on. Every file comes from this repository; nothing is edited on the host.

| URL | Source | Notes |
|---|---|---|
| `https://agent-did.org/v1` | `contexts/v1.jsonld`, byte for byte | JSON-LD context ([ADR-003](ADR-003-JSON-LD-Context-and-agentMetadata.md), RFC-001 §4.1.1). Immutable: a change is `contexts/v2.jsonld` at `/v2`. `Content-Type: application/ld+json`, CORS open. |
| `https://agent-did.org/vocab` | `site/vocab.html` | Human-readable index of the `https://agent-did.org/vocab#` terms. |
| `https://agent-did.org/a2a/identity/v1` | `site/a2a/identity/v1.html` | The A2A extension URI ([composition contract](RFC-001-A2A-Identity-Composition-Contract.md) §3). |
| `https://agent-did.org/.well-known/security.txt` | `site/.well-known/security.txt` | RFC 9116, clearsigned with the key in `SECURITY.md`. Its signed text is `.github/security/security.txt`. |
| `https://agent-did.org/` | `site/index.html` | Links to the repository and the URLs above. |

Response headers are in `site/_headers`. `scripts/build-site.js` assembles `site-dist/` and refuses to build when the context does not match its pin or the signed `security.txt` does not match its source or has expired.

## Hosting: Cloudflare Pages

The domain is registered at Cloudflare, which also runs its e-mail routing (`security@`, `conduct@`). The site is a Cloudflare Pages project connected to the GitHub repository:

| Setting | Value |
|---|---|
| Production branch | `main` |
| Build command | `node scripts/build-site.js` |
| Build output directory | `site-dist` |
| Root directory | (repository root) |
| Build watch paths (include) | `site/*`, `contexts/*`, `.github/security/*`, `scripts/build-site.js` |
| Preview deployments | none (only `main` is deployed) |
| Custom domain | `agent-did.org` (apex), `www.agent-did.org` redirecting to the apex |

The build needs no `npm install` and no secrets. Adding the custom domain creates the DNS records; the existing MX and TXT records of e-mail routing are not touched.

GitHub Pages is not used because it cannot set `Content-Type` for the extensionless path `/v1`.

## Checks

- `npm run check:site`: builds the site and verifies the `security.txt` signature with `gpgv` against `.github/security/agent-did-security.asc` and the fingerprint `SECURITY.md` publishes. Runs in CI (`ci-site.yml`) on every change to the sources.
- `npm run check:site:live`: also fetches the deployed site and checks that it serves the repository bytes and media types, and that `security.txt` does not expire within 30 days. Runs weekly and on demand (`ci-site.yml`, job `live`). A failure means the deployment drifted or the file must be renewed.

## Renewing or changing security.txt

`security.txt` expires on the date in its `Expires` field (RFC 9116 §2.5.5). Before that date, or whenever a field changes:

1. Edit `.github/security/security.txt` (keep LF line endings; `.gitattributes` enforces them on checkout).
2. Sign it with the security key (the passphrase is asked for):

   ```bash
   gpg --local-user 9C56A73951F49EB7F4FEFF4310377F82E83D3A8A --clearsign \
     --output site/.well-known/security.txt .github/security/security.txt
   ```

3. `npm run check:site`, then commit both files in one pull request.

When the OpenPGP key itself is renewed (`gpg --quick-set-expire`), export it again to `.github/security/agent-did-security.asc` in the same pull request.

## Release checklist entry

Before a release that names `https://agent-did.org/v1` or a new context version: the `live` job of `ci-site.yml` is green on `main`.
