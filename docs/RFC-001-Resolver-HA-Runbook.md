# RFC-001 Universal Resolver — High Availability Runbook

## 1. Production Profile

| Aspect | Target |
|---|---|
| DID Document sources | ≥ 3 endpoints per source type |
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

Validate failover behavior by simulating a primary-source failure and verifying continuity.

### 4.2 Steps

1. **Baseline**: Record current metrics (latency, availability, cache hit rate).
2. **Simulate failure**: Disconnect or block traffic to the primary DID document source.
3. **Observe**: Verify resolver falls back to secondary source within the health check interval.
4. **Validate**: Confirm resolution still succeeds and latency stays within SLO.
5. **Restore**: Re-enable primary source and verify normal traffic distribution.
6. **Document**: Record results, any anomalies, and corrective actions.

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
