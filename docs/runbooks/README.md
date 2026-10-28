# Forensiq Runbooks

> **Audience:** On-call SOC engineers and platform operators.  
> **Scope:** These runbooks cover Forensiq's own platform health, not customer-security investigations.

---

## Index

| Runbook | When to use |
|---|---|
| [RB-01 Restore from backup](rb-01-restore-from-backup.md) | MongoDB data loss or corruption |
| [RB-02 Rotate secrets](rb-02-rotate-secrets.md) | Scheduled rotation or suspected compromise |
| [RB-03 Re-run ingestion for a gap](rb-03-rerun-ingestion-gap.md) | Alerts missing for a time window |
| [RB-04 Regroup incidents](rb-04-regroup-incidents.md) | Badly grouped incidents after a rule change |
| [RB-05 Disable a bad rule](rb-05-disable-bad-rule.md) | High false-positive rule causing alert storm |

---

## Quick-reference: health endpoints

| Probe | URL | Checks |
|---|---|---|
| Liveness | `GET /api/v1/health/live` | Process alive (no I/O) |
| Readiness | `GET /api/v1/health/ready` | MongoDB reachable |
| Metrics | `GET /metrics` | Prometheus text format |

## Quick-reference: key metrics to watch

| Metric | Alert threshold |
|---|---|
| `forensiq_ingest_lag_seconds` | > 300 s (5 min) |
| `forensiq_ingest_cycle_errors_total` (rate) | > 0 in last 5 min |
| `forensiq_ti_errors_total` (rate) | > 3 in last 5 min |
| `forensiq_investigation_failed_total` (rate) | > 5 in last 10 min |
| `forensiq_poller_is_leader` | No process == 1 for > 120 s |
| `forensiq_investigation_queue_depth` | > `INVESTIGATION_CONCURRENCY` (3) sustained |
