# RB-04 — Regroup Incidents

**Severity:** P3 — analyst experience  
**Owner:** Platform on-call  

---

## When to use this runbook

- A detection rule change caused alerts to be grouped into the wrong incidents.
- An incident contains unrelated alerts (false positive grouping).
- An incident is missing alerts that should belong to it.

---

## How incident grouping works

Incidents are created and updated in `services/correlation.py`. The grouping key is derived
from the combination of `rule_name`, `org_id`, and a time window. Alerts within the same
window and rule are linked to the same incident.

The `ingestion_state` collection tracks the grouping cursor (same as the alert cursor).

---

## Option A — Regroup a single incident via the UI

1. Navigate to **Incidents** in the Forensiq dashboard.
2. Open the affected incident.
3. _(Future)_ Use the **Merge / Split** action (tracked as 2.4 in production-readiness.md).

> **Note:** Manual merge/split is not yet implemented. Use Option B below.

---

## Option B — Direct MongoDB surgery (use with care)

### Step 1 — Identify the affected alerts

```javascript
// mongosh
db = db.getSiblingDB('forensiq');

// Find alerts that were grouped into the wrong incident
db.alerts.find(
  { incident_id: ObjectId("<wrong_incident_id>") },
  { _id: 1, rule_name: 1, source_ip: 1, created_at: 1 }
);
```

### Step 2 — Re-assign alerts to the correct incident

```javascript
// Move specific alert IDs to the correct incident
db.alerts.updateMany(
  { _id: { $in: [ObjectId("<alert_id_1>"), ObjectId("<alert_id_2>")] } },
  { $set: { incident_id: ObjectId("<correct_incident_id>") } }
);
```

### Step 3 — Update incident alert counts

```javascript
// Recount open alerts for both incidents
const wrongId = ObjectId("<wrong_incident_id>");
const rightId = ObjectId("<correct_incident_id>");

for (const incId of [wrongId, rightId]) {
  const openCount = db.alerts.countDocuments({
    incident_id: incId,
    status: { $in: ["New", "Investigating"] }
  });
  db.incidents.updateOne(
    { _id: incId },
    { $set: { open_alert_count: openCount } }
  );
}
```

### Step 4 — Write an audit log entry

```javascript
db.audit_logs.insertOne({
  entity_type: "incident",
  action: "manual_regroup",
  actor: "ops-runbook-RB-04",
  org_id: "default",
  created_at: new Date(),
  detail: "Manually reassigned alerts due to rule change. See incident ticket #..."
});
```

---

## Prevention

After any detection rule change that affects grouping keys:
1. Review the last 24 hours of new incidents in the dashboard.
2. If grouping looks wrong, run this runbook within the same shift.
3. Document the rule change and its grouping impact in the deployment changelog.
