# Forensiq: Production-Readiness Change List

**Date:** 2026-10-28
**Baseline:** branch `feat/phase1b-incidents` (includes Phase 0 honesty pass, Phase 1 triage workflow, Phase 1b incidents)
**Companion:** [2026-10-28-product-audit.md](2026-10-28-product-audit.md) (the original teardown)

This list covers what must change before Forensiq can hold real security telemetry and be relied on by a SOC team. Each item says what is wrong today, what to change, and how to tell it is done. Effort: **S** under 2 days, **M** 2 to 5 days, **L** over a week.

"Verified" means I read the code or config for this list. "From audit" means it was found during the earlier end-to-end test and not re-checked here.

---

## 0. What is already done

| Area | Status | Where |
|---|---|---|
| No simulated threat-intel verdicts; feed errors give no verdict | Done | PR #15 |
| Real system health; fabricated UI numbers removed | Done | PR #15 |
| `.local` / `.internal` email logins | Done | PR #15 |
| Close with verdict and note, assignment, bulk actions, SLA clocks, role gates, audit trail | Done | PR #17 |
| MTTA/MTTR, rule precision, backlog aging | Done | PR #17 |
| Incident grouping | Done | branch `feat/phase1b-incidents` |
| Case management (2.4) | Done | branch `case_management` |
| Response actions (2.5) | Done | branch `response_actions` |
| UTC timestamps serialised with offset | Done | PR #17 |

Everything below is still open.

---

## 1. Blockers: do not put real data in until these are fixed

### 1.1 Container and deployment (Verified)

| Problem | Change | Effort |
|---|---|---|
| `Dockerfile` copies only `pyproject.toml` and `app/`. `config/noise.yaml` is never copied, and the API loads it at startup, so the container should fail to boot. (The `rules/` directory will have the same problem once the YAML rule engine lands.) | Copy `config/` and `rules/`; add a container smoke test to CI that boots the image and calls `/health`. | S |
| Runs as root, single stage, installs build tools and `libpq-dev` (Postgres is not used), no `HEALTHCHECK`, installs the project in editable mode. | Multi-stage build, non-root user, slim runtime image, `HEALTHCHECK` on a readiness endpoint, pinned base image digest, install from a lockfile. | M |
| `docker-compose.yml` is development-only: `--reload`, `FORENSIQ_ENV=development`, MongoDB and Redis published on host ports with no authentication, no frontend service, no TLS. | Separate `compose.prod.yml` (or Helm chart): no published DB ports, MongoDB authentication and TLS, secrets from files or a secret manager, frontend service, reverse proxy with TLS. | M |
| No dependency lockfile for the backend (only `pyproject.toml` ranges). Builds are not reproducible. | Generate and commit a lockfile (`uv lock` or `pip-compile --generate-hashes`); install with `--require-hashes` in the image. | S |
| `celery`, `redis`, `sqlalchemy` are declared dependencies, but nothing in the running app uses them (`models/incident.py` imports SQLAlchemy and is dead code). Redis is in compose and `.env.example` for nothing. | Remove the dead dependencies and `models/incident.py`, or actually use Redis (see 1.5). | S |

### 1.2 Authentication and sessions (Verified for storage and WebSocket; rest from audit)

| Problem | Change | Effort |
|---|---|---|
| Access token and a 7-day refresh token live in `localStorage`. Any XSS becomes a week-long account takeover. | Refresh token in an `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/auth/refresh`; access token in memory only; CSRF protection on the refresh endpoint. | M |
| The investigation WebSocket takes the token in the URL query string (`?token=`), which ends up in proxy and access logs. | Short-lived single-use WebSocket ticket from an authenticated `POST`, or the `Sec-WebSocket-Protocol` path the server already supports. | S |
| No MFA or SSO. | OIDC login (Entra ID, Okta, Google) with group-to-role mapping; TOTP as a fallback for local accounts. Disable local passwords when SSO is on. | L |
| Users can only be created by a CLI script. No way to list, disable, change a role, reset a password, or force sign-out. | Admin user-management screen and API; session list with revoke; password policy and rotation for local accounts. | M |
| No account-takeover alerting. | Audit and alert on new-device sign-in, role change, repeated lockouts. | S |

### 1.3 Application hardening (Verified: no security headers, no API-wide rate limit)

| Problem | Change | Effort |
|---|---|---|
| No security headers on either app. | Strict `Content-Security-Policy` (no inline scripts), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, frame protection; `Strict-Transport-Security` at the proxy. Set in `next.config.ts` and as FastAPI middleware. | S |
| Rate limiting exists only for login. Search, bulk actions, PDF generation and investigations are unthrottled. | Per-user and per-IP limits (for example `slowapi` backed by Redis); tighter limits on `/search`, `/alerts/bulk`, report endpoints, and investigation starts. Request body size limits. | M |
| `SPLUNK_VERIFY_SSL` defaults to `false`; CORS allows all methods and headers with credentials. | Default to verifying TLS with a configurable CA bundle; refuse to start in production with verification off. Restrict CORS methods and headers; add `TrustedHostMiddleware`. | S |
| Production start-up checks cover only the secret key and Splunk password. | Extend the check to: no wildcard CORS, DEBUG off, MongoDB URI not unauthenticated localhost, TLS on, a real LLM or TI configuration warning. | S |
| Secrets come from `.env` files. | Read from a secret manager (Vault, AWS/Azure/GCP), support key rotation for `SECRET_KEY` (accept the previous key for one TTL). | M |

### 1.4 Data durability and governance (Verified: no `audit_logs` index; rest from audit)

| Problem | Change | Effort |
|---|---|---|
| MongoDB runs standalone, unauthenticated by default, with no backup. | Replica set with authentication and TLS; automated backups with a tested restore; documented RPO and RTO. | M |
| `audit_logs` has no index and no retention policy, and is a plain writable collection. | Index `(org_id, entity_type, entity_id, created_at)`; append-only via a restricted role; export to an external store (S3 object lock, or SIEM); retention policy. | M |
| No retention for `investigation_jobs`, `alert_notes`, `alerts`, or raw events. Raw events can contain personal data. | Per-collection retention settings, TTL indexes, a redaction option for raw events, a documented erase-on-request procedure. | M |
| Schema changes are applied ad hoc at startup (`ensure_indexes`). | Versioned migrations with a recorded schema version; refuse to start on an unknown newer version. | M |
| Incident grouping, SLA targets and noise policy live in code or YAML with no change history. | Store policy in the database with an audit trail, or require changes through reviewed pull requests with a deploy. | M |

### 1.5 Reliability of investigations (Verified for the in-process state; rest from audit)

| Problem | Change | Effort |
|---|---|---|
| `POST /investigate` uses FastAPI `BackgroundTasks`. A restart mid-run loses the job and leaves the alert stuck in "Investigating" forever. | Durable job queue (arq or Celery on Redis, or a MongoDB job table with a worker and a reaper). Retries with backoff; a stuck-job reaper on boot; one active run per alert (idempotency key). | L |
| WebSocket subscribers, event history and active runs are kept in memory in the API process (`InvestigationStreamManager`). With more than one API worker, a viewer connects to a process that is not running the job. | Publish pipeline events through Redis pub/sub (or similar) and have workers, not API processes, run pipelines. | M |
| Opening the WebSocket starts an investigation when `auto_start` is true. Viewing a "New" alert spends compute and, with an LLM, money. | Make the WebSocket observe-only; starting a run is an explicit `POST`. | S |
| The statistics endpoints swallow all errors and return empty data, so an outage looks like a quiet day. | Return a 5xx with a request id; have the UI show an error state. | S |
| The poller is a single instance guarded by a database lease. This is correct but untested under failure. | Chaos tests: kill the holder mid-cycle, clock skew, database partition. Metrics for lease holder and ingestion lag. | M |

### 1.6 CI/CD and supply chain (Verified: no `.github` directory)

The 435 backend tests and the frontend build run only on a developer machine.

| Change | Effort |
|---|---|
| GitHub Actions: `pytest`, `ruff`, `mypy`, `eslint`, `tsc`, `next build`, container build and boot smoke test; required status checks on `main`. | M |
| Dependabot or Renovate; `pip-audit` and `npm audit`; secret scanning; SAST (CodeQL or Semgrep); container image scan (Trivy). | S |
| Fix the existing lint and type debt so the checks can be required: 13 ESLint errors, about 450 ruff findings, `mypy` currently cannot run. | M |
| Staging environment with seeded data, release tags, changelog, rollback procedure. | M |

### 1.7 Observability and operations

| Change | Effort |
|---|---|
| Separate liveness and readiness endpoints (readiness checks MongoDB, not the SIEM; SIEM state belongs in the dashboard). | S |
| JSON logs at INFO with request ids on every line; never log alert payloads or tokens (the debug-logging leak is fixed, but add a test that guards it). | S |
| Prometheus metrics: ingest lag, alerts per cycle, TI error rate per feed, investigation duration and failures, LLM latency and cost, queue depth, API latency. OpenTelemetry traces across the agent graph. | M |
| Alerts on the platform itself: ingest lag over threshold, TI feed failing, queue backlog, poller lease lost, SLA breach count. | S |
| Runbooks: restore from backup, rotate secrets, re-run ingestion for a gap, regroup incidents, disable a bad rule. | M |

---

## 2. Product gaps that block real SOC use

### 2.1 Notifications: nothing tells a human an alert exists (Verified: no notification code)

A SOC tool that must be watched to be useful will be missed overnight. This is the largest functional gap after the items above.

- Notify on new critical alerts, SLA breaches (acknowledge and resolve), unassigned criticals after N minutes, and escalations.
- Channels: email, Slack/Teams webhook, PagerDuty/Opsgenie; per-user and per-role routing; quiet hours and on-call schedules.
- **Effort: L.**

### 2.2 Detection quality

| Problem | Change | Effort |
|---|---|---|
| Only a small set of hard-coded rules fires on this data. A YAML rule engine exists on `feat/stage2-rules-eval` but is not on `main`, and needs a rebase over the ingestion and streaming changes. | Rebase and merge it; add rule metadata, owners, test cases and a "last fired" view. | L |
| ATT&CK data is hand-typed, with known errors (T1071.004 tagged as Execution; technique names shown as "Technique T1071.004"). The matrix is a curated subset. | Load the official ATT&CK STIX bundle; validate every rule's technique and tactic against it; pin and show the ATT&CK version. | M |
| The `dns_suspicious_query` rule labels GitHub, pastebin and bit.ly lookups "DNS Tunneling". Live data showed 0% precision on it. | Redefine as "suspicious domain lookup" with severity by context, or tune using the verdict data now being collected. | S |
| Risk scores saturate at 100 on every critical alert. | Re-score from severity, asset criticality, indicator confidence and rarity; show a "why this score" breakdown; calibrate against labelled verdicts. | L |
| The correlation agent still matches on common values with no time window and no rarity weighting. | Time-windowed, rarity-weighted, self-excluding correlation; reuse the incident keys. | M |
| Alert de-duplication (300 s bucket) did not prevent duplicates across overlapping ingest windows. | Deterministic fingerprint (rule, host, key fields, bucket) with a unique index. | M |
| Mimikatz command lines are not mapped to credential dumping (T1003). | Add command-line technique rules for common tools; test against Atomic Red Team data. | M |

### 2.3 AI investigation

| Change | Effort |
|---|---|
| Structured LLM output with a JSON schema; every claim cites an evidence id from the alert or enrichment; reject answers that cite nothing. | M |
| Store model, prompt version and token cost with every run; keep a history of runs instead of overwriting results. | M |
| Containment advice is always "suggested"; any automated action requires human approval. | S |
| Evaluation harness: a labelled alert set (Atomic Red Team plus benign baselines) scored for verdict precision and recall on every release; block releases that regress. | L |
| Prompt-injection hardening: alert text (command lines, hostnames, DNS names) is attacker-controlled and goes into LLM prompts. Delimit and escape it; never let model output trigger actions directly; test with injected samples. | M |
| Cost and rate controls per tenant: daily cap, circuit breaker on provider errors. | S |

### 2.4 Case management

**Status: implemented.** `services/cases.py`, `services/ticketing.py`, `services/sla.py`, `services/sla_monitor.py`, `endpoints/incidents.py`, `endpoints/policies.py`; tests in `tests/test_case_management.py`.

- [x] Incident-level notes, timeline, owner and status. The incident keeps a case `status` (open, in_progress, resolved, closed) separate from the derived `state`. Resolving needs a note and no open member alerts (a SOC manager can force). `GET /incidents/{id}/notes|timeline`, `POST .../notes|status|owner`.
- [x] Merge and split incidents manually; pin an alert to an incident (`POST .../merge|split|pin`, `DELETE .../pin/{alert}`). Each needs a reason. Curated incidents and pinned alerts survive `rebuild`; automatic grouping may add alerts to a curated incident but never absorbs it.
- [x] Link to external tickets and sync status. Jira Cloud and ServiceNow, configured by server settings only (`FORENSIQ_JIRA_*`, `FORENSIQ_SERVICENOW_*`). Link by key or create; pull status on demand or every `TICKET_SYNC_INTERVAL_SECONDS`, mapping it to the case status; our status changes are posted back as a comment. Unconfigured systems report `not_configured`; nothing is simulated.
- [x] Configurable SLA targets per tenant: `GET/PUT /policies/sla`, versioned and audited (manager/admin). Alert lists, alert detail, dashboard and incident detail all use them.
- [x] Escalation policy: `GET/PUT /policies/escalation`. Per severity and per breach (`ack_breach`, `resolve_breach`): notify, reassign to a named active user, mark Escalated. The SLA monitor, now started with the app, applies each once per alert and audits it.
- Not done: pushing incident status to Jira/ServiceNow *workflow transitions* (they differ per project, so only comments are written); an admin UI for the two policies (API only).
- **Effort: L.**

### 2.5 Response actions

**Status: implemented** (`services/response_actions.py`, `services/response_connectors.py`, `endpoints/response.py`, UI at `/response`; tests in `tests/test_response_actions.py`). The approval workflow it needed is part of this work.

- [x] Connectors: EDR isolate (CrowdStrike Falcon `contain` / `lift_containment`), IdP disable user (Okta suspend + clear sessions / unsuspend), firewall block (a webhook gateway you run in front of PAN-OS, FortiGate, a cloud security group, etc.; payload documented in `FirewallWebhook`). Endpoints and credentials come from server settings only. An unconfigured connector refuses with 503; nothing is simulated.
- [x] Approval step: request, then a **different** SOC manager or admin approves (four eyes, no self-approval), then execute within `RESPONSE_APPROVAL_TTL_MINUTES`. Unapproved requests expire after `RESPONSE_REQUEST_TTL_HOURS`. Approvers are notified through the existing channels (`response_approval_requested`).
- [x] Audit: every step (`response.requested|approved|rejected|cancelled|dry_run|executed|execution_failed|rolled_back|expired`) goes to the audit log and, when linked, the incident timeline.
- [x] Dry run: always available, no approval needed, read-only against the target (CrowdStrike and Okta look the target up and say whether it would change; the firewall gateway has no read-only mode and says so). A preview is attached to every request.
- [x] Rollback for all three actions (lift isolation, re-enable user, unblock IP), SOC manager or admin, with a note. A failed rollback leaves the action in place and retryable.
- [x] Guardrails: live execution is **off by default** (`FORENSIQ_RESPONSE_LIVE_EXECUTION_ENABLED`); protected-targets list (`RESPONSE_PROTECTED_TARGETS`) checked at request and at execution; loopback/link-local/multicast/reserved IPs can never be blocked; ambiguous hostnames are refused; per-tenant circuit breaker (`RESPONSE_MAX_LIVE_PER_HOUR`); duplicate open requests refused.
- Not done: Entra ID, SentinelOne/Defender, PAN-OS/FortiGate native connectors (the webhook gateway covers firewalls generically); automatic triggering of actions from rules (everything is analyst-initiated by design); a per-severity or per-action approval policy.
- **Effort: L.**

### 2.6 Multi-tenancy

- Tenant scoping is applied through `scoped_query` and tested in places, but there is no tenant admin, no per-tenant configuration (Splunk connection, TI keys, noise policy), and one global poller.
- Add: tenant management, per-tenant secrets and SIEM settings, per-tenant poller scheduling, a cross-tenant isolation test suite that runs against every endpoint automatically.
- **Effort: L.**

### 2.7 Integrations

- A second SIEM (Sentinel or Elastic) through the existing `SIEMProvider` interface.
- More threat-intel sources (OTX, MISP, GreyNoise) with the corroboration rules already in place.
- Webhook and API for outbound events; API tokens for service accounts with scoped permissions.
- **Effort: L each.**

### 2.8 Reporting

- CSV and JSON export of alerts, incidents and audit logs; scheduled weekly summary; compliance export of analyst actions.
- **Effort: M.**

---

## 3. Scale and performance limits found

| Where | Limit | Fix |
|---|---|---|
| `GET /alerts` | Hard cap of 200 rows, no cursor. | Cursor pagination and virtualised table. |
| `GET /incidents` | Loads up to 1,000 incidents and all their alerts' status into memory per request. | Store open/closed counters on the incident and update them on every state change, or aggregate in the database; paginate. |
| `GET /dashboard/soc-metrics` | Reads every alert in the tenant on each request. | Aggregation pipeline, caching for 30 to 60 s, or pre-computed daily roll-ups. |
| `GET /alerts/stats/mitre` | Only reads the first 500 alerts, so counts are wrong past that. | Aggregate in the database. |
| Dashboard | Polls several endpoints every 30 s per open tab. | Server-sent events or a single summary endpoint with caching. |
| Investigations | Auto-investigation concurrency is fixed at 3 per process. | Queue with worker autoscaling; per-tenant fairness. |
| Ingestion | Single poller, 30 s interval, rules evaluated in Python. | Measure with a 100x data load; push more filtering into the SPL prefilter. |

Add a load test (k6 or Locust) with realistic volumes (100k alerts, 50 analysts) and set budgets in CI.

---

## 4. Engineering quality

| Item | Effort |
|---|---|
| **Frontend has no tests** (verified: none found). Add Vitest and React Testing Library for the triage dialog, queue and incident pages; Playwright end-to-end tests for login, triage, bulk close, regroup. | L |
| Share API types: generate TypeScript types from the FastAPI OpenAPI schema instead of hand-written types that can drift. | M |
| Accessibility audit (WCAG 2.1 AA): icon-only buttons need labels, focus management in dialogs, colour-only status cues, keyboard traps. | M |
| Error boundaries and an offline/API-down state in the app shell; consistent empty and error states. | S |
| Narrow-screen layout: the investigation modal and tables overflow below about 600 px. Decide whether mobile is supported. | M |
| Remove repository clutter: planning documents in the root, `raw_alert.json`, stray `test_*.py` in `backend/`, duplicate `setup_splunk_alerts.py`. Fix the README (`requirements.txt` does not exist; Next.js version badge; missing `run_project.ps1`). | S |
| Replace `datetime.utcnow()` and mixed naive/aware datetimes with one convention; pydantic `ConfigDict` migration; remove blanket `except Exception` (46 occurrences). | M |
| Write architecture docs, an API reference, a threat model, and an operations guide. | M |

---

## 5. Security and compliance

- Independent penetration test and threat model before the first customer. The SPL guard, tenant scoping and the new role gates deserve targeted review.
- Authorisation test suite: every endpoint × every role × cross-tenant, generated from the route table, so a new endpoint cannot ship unprotected.
- Dependency and licence inventory (SBOM) per release.
- Data-protection review: what personal data is in raw events, where it is stored and for how long, subprocessors (VirusTotal, AbuseIPDB and the LLM provider receive indicators and possibly alert text).
- SOC 2 / ISO 27001 mapping if customers will ask: access reviews, change management, logging, incident response for Forensiq itself.
- Disaster-recovery exercise with a recorded result.

---

## 6. Suggested order

| Phase | Contents | Rough effort |
|---|---|---|
| **A. Safe to run** | 1.1 container fixes, 1.3 headers/rate limits/TLS defaults, 1.6 CI, 1.7 health and logging | 2 to 3 weeks |
| **B. Safe to trust** | 1.2 cookie tokens and WebSocket tickets, user admin, 1.4 MongoDB auth, backups, audit index and retention, 1.5 durable job queue | 4 to 5 weeks |
| **C. Useful at 3 a.m.** | 2.1 notifications, 2.4 incident notes and configurable SLAs, 1.2 SSO and MFA | 4 to 5 weeks |
| **D. Detection you can defend** | 2.2 rule engine merge, ATT&CK from STIX, rescoring, correlation and dedup fixes, 2.3 evaluation harness and injection hardening | 5 to 6 weeks |
| **E. Scale and polish** | Section 3 fixes and load tests, section 4 frontend tests and accessibility, multi-tenant admin, second SIEM | 6+ weeks |
| **F. Assurance** | Penetration test, DR exercise, compliance mapping | 3 to 4 weeks, can overlap E |

## 7. Exit criteria: "production-ready" means all of these are true

1. A clean checkout builds a container, passes CI, boots in staging and passes smoke tests.
2. No secrets in the repository or images; MongoDB authenticated and encrypted; backup restore tested within the last 90 days.
3. Tokens are not readable by page scripts; SSO or MFA is on for all human accounts.
4. A restart or crash during an investigation loses nothing and leaves no alert stuck.
5. A critical alert reaches a human within 5 minutes without anyone watching the dashboard.
6. Every analyst action is in an append-only audit trail that can be exported.
7. Every verdict the product shows can be traced to evidence, and the evaluation harness shows precision and recall that meet an agreed target.
8. The authorisation test suite passes for every endpoint, role and tenant.
9. A load test at agreed volumes meets latency budgets, and the dashboards and alerts for the platform itself are live.
10. A penetration test has no open high or critical findings.
