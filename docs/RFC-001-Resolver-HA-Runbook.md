# RFC-001 Universal Resolver — High Availability Runbook

## 1. Production Profile

| Aspect | Target |
|---|---|
| DID Document sources | ≥ 3 endpoints per source type |
| `did:webvh` log topology | Primary `did.jsonl` URL plus at least 2 candidate mirror URLs or equivalent gateway mappings |
| Deployment zones | Multi-zone (min. 2 AZ or regions) |
| Cache layer | Distributed (Redis/Memcached) with TTL ≤ 300 s |
| Health check interval | ≤ 30 s |

---

## 2. SLO / SLA

| Metric | Target |
|---|---|
| Availability | ≥ 99.9 % (monthly) |
| Resolution latency p95 | ≤ 750 ms |
| Resolution latency p99 | ≤ 1500 ms |
| Cache hit rate | ≥ 70 % after warm-up |
| MTTR | ≤ 30 min |

---

## 3. Signals & Alerts

| Signal | Threshold | Alert Severity |
|---|---|---|
| Error rate (5xx) | > 1 % over 5 min | Critical |
| Latency p95 | > 750 ms for 5 min | Warning |
| Latency p99 | > 1500 ms for 5 min | Critical |
| Cache hit rate | < 50 % for 10 min | Warning |
| Source health check failure | 2 consecutive | Critical |
| Certificate expiry | < 14 days | Warning |

---

## 4. HA Drill Procedure

### 4.1 Objective

Validate failover behavior for the canonical resolver path by simulating a primary-source failure and verifying continuity.

### 4.2 Steps

1. **Baseline**: Record current metrics (latency, availability, cache hit rate).
2. **Simulate failure**: Disconnect or block traffic to the primary DID document source (for `did:webvh`, this means the primary `did.jsonl` candidate URL).
3. **Observe**: Verify resolver falls back to a secondary source / candidate URL. The SDK resolvers fail over per request: they try the candidate URLs in order and move on after an HTTP error or timeout, without a background health check. A health check interval applies only if the deployment adds its own health checks in front of the sources.
4. **Validate**: Confirm resolution still succeeds and latency stays within SLO.
5. **Restore**: Re-enable primary source and verify normal traffic distribution.
6. **Document**: Record results, any anomalies, and corrective actions.

### 4.3 Manual External `did:webvh` Smoke

Use this manual/opt-in smoke when you want to validate the SDKs against a real published external `did:webvh` log without coupling the baseline conformance suite to third-party availability.

By default both wrappers now load the repo-managed manifest at `fixtures/external-smoke/webvh-public-targets.json` and resolve the default public target from the repository `main` branch through two candidate mirrors:

- canonical raw GitHub URL
- jsDelivr mirror URL

TypeScript / root wrapper:

```powershell
npm run smoke:webvh-external
```

Python wrapper:

```powershell
npm run python:smoke:webvh-external
```

Overrides remain available when you need to test another published target, a staging manifest, or a local/private mirror:

```powershell
$env:AGENTDID_WEBVH_EXTERNAL_TARGET = 'repo-main-support-bot'
$env:AGENTDID_WEBVH_EXTERNAL_MANIFEST = 'fixtures/external-smoke/webvh-public-targets.json'
$env:AGENTDID_WEBVH_EXTERNAL_URLS = 'https://publisher.example/agents/support-bot/did.jsonl,https://mirror.example/agents/support-bot/did.jsonl'
$env:AGENTDID_WEBVH_EXTERNAL_DID = 'did:webvh:QmExampleScid:publisher.example:agents:support-bot'
$env:AGENTDID_WEBVH_EXTERNAL_ALLOW_PRIVATE_TARGETS = '1'
```

Use `AGENTDID_WEBVH_EXTERNAL_ALLOW_PRIVATE_TARGETS=1` only for local development or controlled staging mirrors; leave it unset for normal public-network drills.

On Windows consoles that use a legacy code page (cp1252), set `PYTHONIOENCODING=utf-8` before the Python wrappers. Otherwise they fail when they print their status line, after the resolution itself has succeeded.

### 4.4 Dry Run With the Repository Tooling

A dry run walks through the steps in 4.2 with the tooling in this repository. It does not need a production deployment. It covers the SDK side of failover. It does not cover the deployment side: multi-zone placement, a distributed cache, alerting. Each operator validates those in its own environment.

| Step in 4.2 | Command | Expected result |
|---|---|---|
| Simulated drill | `npm run smoke:ha` and `cd sdk-python && python scripts/resolver_ha_smoke.py` | Primary returns 503, secondary 404, the tertiary serves the log; the drill visits all three in order and the second resolution is a cache hit. The weekly `resolver-ha-drill.yml` workflow runs the same two smokes. |
| 1. Baseline | `npm run smoke:webvh-external` and `npm run python:smoke:webvh-external` | The public target in `fixtures/external-smoke/webvh-public-targets.json` resolves from the raw GitHub URL. |
| 2–4. Primary failure | Set `AGENTDID_WEBVH_EXTERNAL_URLS` to a primary URL that returns 404 followed by the jsDelivr mirror, set `AGENTDID_WEBVH_EXTERNAL_DID` to the expected DID, run both wrappers | The DID resolves from the mirror. |
| Negative control | Set `AGENTDID_WEBVH_EXTERNAL_URLS` to the failing primary only | Both wrappers fail; there is no silent fallback to another source. |
| 5. Restore | Unset the overrides and run both wrappers | The DID resolves from the raw GitHub URL again. |
| 6. Document | Add a row to section 7 | — |

The SDK build must be current before the TypeScript commands (`npm --prefix sdk run build`). To check latency against section 2, time `WebvhDIDDocumentSource.getByReference` over a series of resolutions in each phase. The source has no cache, so every call fetches and verifies the log.

### 4.5 Frequency

- Quarterly in staging environment.
- Annually in production (scheduled maintenance window).

---

## 5. Incident Response

### Severity Classification

| Severity | Description | Response Time |
|---|---|---|
| P1 — Critical | Resolver completely unable to resolve DIDs | ≤ 15 min |
| P2 — High | Degraded performance (SLO breach) | ≤ 30 min |
| P3 — Medium | Partial impairment, workaround available | ≤ 2 h |
| P4 — Low | Cosmetic or non-impactful issue | Next business day |

### Escalation Chain

1. On-call engineer → 15 min
2. Team lead → 30 min
3. Architecture owner → 1 h

### Standard Recovery Actions

| Symptom | Action |
|---|---|
| All sources down | Serve from cache (stale-while-revalidate), engage provider support |
| Single source down | Automatic failover; validate fallback metrics |
| High latency | Check cache layer health, scale read replicas |
| Cache poisoning suspected | Flush cache, enable strict validation, investigate origin |

---

## 6. Compliance Evidence

For each audit cycle, collect and archive:

- Monthly SLO report (availability + latency percentiles).
- HA drill report (procedure + results + corrective actions).
- Incident post-mortems (if any P1/P2 occurred).
- Configuration snapshots (source endpoints, cache TTL, alert thresholds).
- Certificate rotation log.

---

## 7. Dry-Run Record

| Date (UTC) | Commit | Scope | Result | Anomalies and corrective actions |
|---|---|---|---|---|
| 2026-11-17 | `be7feee7` (`1.0.0-rc.5` + docs) | Procedure 4.4 on Windows 11, Node 20.12, Python 3.12, against the public `repo-main-support-bot` target | Pass. Simulated drill green in TS and Python. Baseline, primary failure (raw GitHub 404 → jsDelivr), negative control and restore behaved as expected in both SDKs. Resolution latency over 30 resolutions per phase (TS): baseline p95 32 ms, primary down p95 87 ms (p99 94 ms), restored p95 48 ms, all within the 750 ms / 1500 ms targets. | The Python wrappers failed on a cp1252 console when printing their status line; added the `PYTHONIOENCODING=utf-8` note to 4.3. Step 3 referred to a health check interval that the SDK resolvers do not have; reworded it to describe per-request failover. The two subsections numbered 4.3 were renumbered. |
