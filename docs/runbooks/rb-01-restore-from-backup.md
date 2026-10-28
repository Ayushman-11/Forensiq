# RB-01 — Restore MongoDB from Backup

**Severity:** P0 — data loss  
**Owner:** Platform on-call  
**Last tested:** _(fill in after first DR exercise)_

---

## When to use this runbook

- MongoDB replica set is down and cannot self-recover.
- Data corruption detected (e.g. alerts collection returns garbage, schema version mismatch).
- Accidental mass deletion of documents.

---

## Pre-requisites

- Access to the backup storage location (S3 bucket / NFS share defined in `BACKUP_S3_BUCKET` env var).
- `mongorestore` binary installed on the restore host (same MongoDB version as production).
- The MongoDB admin password from the secret manager.

---

## Steps

### 1 — Identify the target backup

```bash
# List available snapshots (S3 example)
aws s3 ls s3://$BACKUP_S3_BUCKET/forensiq/mongodb/ --recursive | sort | tail -20
```

Choose the most recent snapshot **before** the incident. Note the path, e.g.  
`forensiq/mongodb/2026-10-27T03:00:00Z/forensiq.archive.gz`

### 2 — Stop the poller and API (prevent writes during restore)

```bash
# Scale down the API deployment (Kubernetes example)
kubectl scale deployment forensiq-api --replicas=0 -n forensiq

# Or with docker compose:
docker compose stop api
```

### 3 — Download the backup

```bash
aws s3 cp s3://$BACKUP_S3_BUCKET/forensiq/mongodb/2026-10-27T03:00:00Z/forensiq.archive.gz \
    /tmp/forensiq.archive.gz
```

### 4 — Restore

```bash
mongorestore \
  --uri="$MONGO_URI" \
  --authenticationDatabase=admin \
  --gzip \
  --archive=/tmp/forensiq.archive.gz \
  --drop           # drops existing collections before restore
```

> **Warning:** `--drop` removes existing data. Confirm this is intentional.

### 5 — Verify

```bash
mongosh "$MONGO_URI" --eval "
  db = db.getSiblingDB('forensiq');
  print('alerts:', db.alerts.countDocuments());
  print('incidents:', db.incidents.countDocuments());
  print('audit_logs:', db.audit_logs.countDocuments());
"
```

Check the readiness probe:

```bash
curl -sf http://localhost:8000/api/v1/health/ready | jq .
# Expected: {"status":"ready","mongo":"ok","version":"0.1.0"}
```

### 6 — Restart services

```bash
kubectl scale deployment forensiq-api --replicas=2 -n forensiq
# Or:
docker compose start api
```

### 7 — Post-restore actions

- Notify the SOC team of the data gap window (backup time → incident time).
- Create an incident ticket with: backup used, data-loss window, RCA timeline.
- Re-run ingestion manually for the gap window (see [RB-03](rb-03-rerun-ingestion-gap.md)).

---

## Rollback

If the restore made things worse, repeat from step 1 using an earlier snapshot.

---

## RPO / RTO targets

_(Fill in agreed targets after the first DR exercise.)_

| Target | Value |
|---|---|
| RPO (data loss) | < 1 hour |
| RTO (service restored) | < 4 hours |
