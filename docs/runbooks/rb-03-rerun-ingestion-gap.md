# RB-03 — Re-run Ingestion for a Gap

**Severity:** P2 — data completeness  
**Owner:** Platform on-call  

---

## When to use this runbook

- The Splunk poller was down for a period and alerts for that window are missing.
- MongoDB was restored from backup and there is a data gap between the backup time and the incident.
- Ingestion cursor was accidentally advanced too far.

---

## How the ingestion cursor works

The `ingestion_state` collection stores a document with `_id: "cursor:<org_id>:splunk"` 
containing the ISO timestamp of the newest event successfully ingested.  
The next cycle will query Splunk for events **after** that timestamp (minus the overlap window).

To re-ingest a gap, you move the cursor back and restart the poller.

---

## Steps

### 1 — Identify the gap

Check the `ingestion_runs` collection for the failing period:

```javascript
// mongosh
db = db.getSiblingDB('forensiq');
db.ingestion_runs.find(
  { started_at: { $gte: ISODate("2026-10-27T00:00:00Z") } },
  { started_at: 1, status: 1, alerts_new: 1, fetched: 1 }
).sort({ started_at: 1 });
```

Look for runs with `status: "error"` or gaps where `fetched == 0` unexpectedly.

### 2 — Stop the poller

```bash
# Scale API down so there is only one poller attempt during recovery
kubectl scale deployment forensiq-api --replicas=1 -n forensiq
```

### 3 — Move the cursor back

```javascript
// mongosh — set cursor to the START of the gap
db.ingestion_state.updateOne(
  { _id: "cursor:default:splunk" },
  { $set: { ts: "2026-10-27T00:00:00+00:00", truncated: false } }
);
// Also update the legacy key if it exists:
db.ingestion_state.updateOne(
  { _id: "last_ingested" },
  { $set: { ts: "2026-10-27T00:00:00+00:00" } }
);
```

> **Warning:** Setting the cursor back may produce duplicate alerts for the overlap period.
> The ingestion pipeline uses upserts so duplicates are idempotent — they will update 
> `count` and `last_seen` but not create new alert documents.

### 4 — Restart the API / poller

```bash
kubectl rollout restart deployment/forensiq-api -n forensiq
```

The poller will start a new cycle immediately on boot. Watch the logs:

```bash
kubectl logs -l app=forensiq-api -n forensiq -f | grep -E "ingestion_complete|ingestion_cycle_failed"
```

### 5 — Verify

```bash
# Check Prometheus for new alerts ingested
curl -s http://localhost:8000/metrics | grep forensiq_ingest_alerts_new_total

# Check lag is back to normal (< 300 s)
curl -s http://localhost:8000/metrics | grep forensiq_ingest_lag_seconds
```

### 6 — Restore original replica count

```bash
kubectl scale deployment forensiq-api --replicas=2 -n forensiq
```

---

## Notes

- The overlap window (`FORENSIQ_INGEST_OVERLAP_SECONDS`, default 120 s) means even a normal restart will 
  re-query the last 2 minutes. You only need this runbook for gaps longer than the overlap.
- If the Splunk index was also down during the gap, raw events may be permanently lost. 
  Forensiq can only ingest what Splunk has.
