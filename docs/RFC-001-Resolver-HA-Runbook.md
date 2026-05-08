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
3. **Observe**: Verify resolver falls back to a secondary source / candidate URL within the health check interval.
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

### 4.3 Frequency

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
