# RB-02 — Rotate Secrets

**Severity:** P1 — security  
**Owner:** Platform on-call + Security team  
**Last tested:** _(fill in after first rotation exercise)_

---

## When to use this runbook

- Scheduled rotation (recommended: every 90 days for `SECRET_KEY`; every 30 days for API keys).
- Suspected credential compromise (leaked `.env`, exposed in logs, repository push).
- Team member offboarding.

---

## Secrets inventory

| Secret | Env var | Where stored | Rotation impact |
|---|---|---|---|
| JWT signing key | `FORENSIQ_SECRET_KEY` | Secret manager | All active sessions are invalidated |
| Splunk password | `FORENSIQ_SPLUNK_PASSWORD` | Secret manager | Ingestion stops until updated |
| VirusTotal key | `FORENSIQ_VT_API_KEY` | Secret manager | TI enrichment degraded until updated |
| AbuseIPDB key | `FORENSIQ_ABUSEIPDB_API_KEY` | Secret manager | TI enrichment degraded until updated |
| xAI / Grok key | `FORENSIQ_XAI_API_KEY` | Secret manager | AI investigations fail until updated |
| MongoDB admin password | (MongoDB internal) | Secret manager | Requires coordinated replica-set update |

---

## Steps — JWT `SECRET_KEY` rotation

> Users will be logged out when the new key takes effect. Warn them first.

### 1 — Generate a new key

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 2 — Update the secret manager

```bash
# Example: AWS Secrets Manager
aws secretsmanager update-secret \
    --secret-id forensiq/SECRET_KEY \
    --secret-string "<new-key>"
```

### 3 — Rolling restart of the API (zero-downtime)

```bash
kubectl rollout restart deployment/forensiq-api -n forensiq
kubectl rollout status deployment/forensiq-api -n forensiq
```

### 4 — Verify

```bash
# A login must succeed with the new key
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@forensiq.local","password":"..."}' | jq .access_token
```

---

## Steps — API key rotation (VT / AbuseIPDB / xAI)

1. Generate or obtain the new key from the provider's console.
2. Update the secret manager entry.
3. Rolling restart (same as above).
4. Watch `forensiq_ti_errors_total` in Prometheus — errors should drop to zero within one poll cycle.

---

## Steps — Splunk password rotation

1. Change the password in Splunk first (`Settings → Users`).
2. Update `FORENSIQ_SPLUNK_PASSWORD` in the secret manager.
3. Rolling restart.
4. Watch `forensiq_ingest_cycle_errors_total` — must return to zero.

---

## Emergency: suspected leak

1. Immediately revoke/regenerate the compromised credential at the source.
2. Update the secret manager.
3. Force-restart **all** API pods (not rolling – revoke immediately):
   ```bash
   kubectl delete pods -l app=forensiq-api -n forensiq
   ```
4. Review audit logs for any actions taken while the credential was exposed.
5. File a security incident ticket with timeline.
