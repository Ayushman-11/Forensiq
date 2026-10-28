# Forensiq: End-to-End Product & Engineering Audit

**Date:** 2026-10-28
**Build audited:** `main` @ local main merged with `origin/main` (713b999, PRs #9 to #14), worktree `D:\forensiq\Forensiq-main`
**Environment:** live Splunk (localhost:8089), MongoDB 8.3 (isolated DB `forensiq_audit`), VirusTotal key set, AbuseIPDB and xAI keys **not** set
**Method:** fresh DB, bootstrap users, boot API + poller + Next.js prod build, drive UI as admin, API battery as `soc_analyst`, read the code behind every finding.

---

## Verdict

Forensiq is a good **demo** and an unsafe **product**. The plumbing is better than most student SOC projects: 383 green tests, a real SPL guard, tenancy scoping, refresh-token rotation, a lease-based poller. But the parts an analyst actually trusts (threat-intel verdicts, risk scores, recommendations, health status) are partly **fabricated**, and the core SOC loop of *triage, decide, close, report* **cannot be completed in the UI**.

A real SOC lead would stop the evaluation within 10 minutes, at the point where the tool tells them to block `raw.githubusercontent.com` at the perimeter and isolate three hosts because of a mock rule that treats every `185.*` IP as Russian malware.

**Score against an industry-grade SOC/SOAR bar (Splunk SOAR, Sentinel, Tines, Torq, Dropzone, Prophet):**

| Area | Score /10 | One-line reason |
|---|---|---|
| Detection quality | 3 | 2 of 15 rule types fired; FP-prone DNS rule; no tuning loop |
| Enrichment / TI trust | 1 | Mock verdicts presented as real; fall back to mock on API error |
| Triage UX | 2 | No disposition, notes, assignment, bulk actions, or grouping in UI |
| AI investigation | 3 | Deterministic fallback labelled "Grok AI"; scores saturate at 100 |
| Case management | 0 | No incidents/cases; 48 alerts → 48 separate "cases" |
| Platform / reliability | 5 | Lease poller good; BackgroundTasks lose jobs; debug log firehose |
| Security | 6 | Solid SPL guard + RBAC basics; tokens in localStorage; L1 can suppress criticals |
| Engineering hygiene | 5 | Tests good; 452 ruff issues; 13 ESLint errors; README install broken |

---

## P0: Trust-destroying defects (fix before anyone else sees it)

### P0-1. Threat intel fabricates malicious verdicts
`backend/app/agents/ioc_agent.py:79-140`
- With no AbuseIPDB key, **every IP starting `45.`, `47.`, `104.`, `185.`, `194.` is "malicious, score 85, country RU, 64 reports"**. `104.16.0.0/12` is Cloudflare. `185.199.108-111.133` is GitHub; the audit run flagged all four as malicious.
- The VT mock hard-codes `raw.githubusercontent`, `pastebin`, `bit.ly` as malicious and **hash prefixes `ba4038fd`, `097ce576`**, which are the hashes in your own test data. This is test-fitting inside production code.
- **On any API error (timeout, 429, 5xx) the code silently falls back to the mock** (`VirusTotal (Error Fallback)`). A VT rate-limit therefore *creates* malicious verdicts.
- Result: 15/48 alerts carried mock TI and all scored risk 100.

**Fix:** delete the mocks from the runtime path. Missing key returns `status: "not_configured"`; error returns `status: "error"`, and neither feeds risk. Keep mocks only in tests (respx).

### P0-2. "1 engine out of 92" = malicious → "block raw.githubusercontent.com"
`ioc_agent.py:175`: `if malicious > 0: reputation = "malicious"`. VT returned `malicious:1, harmless:58`. The recommendation agent then wrote:
> "Block confirmed malicious domain 'raw.githubusercontent.com' on perimeter firewalls and EDR."

That instruction breaks every developer, package manager, and CI runner in the org.
**Fix:** threshold on ratio and count (e.g. `malicious >= 3 && ratio >= 5%`), add a popularity allowlist (Tranco top-10k, cloud/CDN ASNs, Microsoft/Google/GitHub ranges), and **never** say "confirmed" unless ≥2 independent sources agree.

### P0-3. Recommendations are inverted relative to the threat
- Real Mimikatz credential dump (`Invoke-Mimikatz -DumpCreds`): *"Verify whether the command line execution is part of authorized IT administrative tasks."*
- DNS lookups of github/pastebin/bit.ly: *"Active multi-host threat detected! Immediately isolate host … and peer systems."*

The "multi-host" verdict comes from correlation (`services/correlation.py`) joining on **ubiquitous values** (`process_name=powershell.exe`, common domains) with **no time window** and no prevalence weighting. Every alert correlates with every other alert, so every blast radius becomes "multi_host". The peer list even repeats the host itself (`forensiq-e2e-c, attackdata, forensiq-e2e-b` for an alert on `forensiq-e2e-b`).
**Fix:** correlate within ±N hours; weight by rarity (a value seen on >X% of hosts contributes 0); exclude self; require ≥1 high-signal key (rare hash, rare external IP, same user + lateral logon).

### P0-4. The dashboard lies
`frontend/src/app/page.tsx:215-290`
- System Health panel is **four hard-coded strings**: `Splunk "Connected"`, `Ingestion "Healthy"`, `AI Agents "Operational"`, `Threat Intel "Connected"`. They showed green while AbuseIPDB and the LLM were unconfigured.
- `Total: {totalVolume || 119} events` and `{ai_confidence_avg ?? 94}%`: literal fake fallbacks. The audit saw "Total: 119 events" next to "No telemetry recorded in past 24h".
- "AI Confidence Avg 91%" averages a field set by **deterministic rules** (`engine: "deterministic_fallback"`); there was no AI.
- MITRE panel: "Hits: 126" for 48 alerts (one alert counted under several techniques with no explanation); "Enterprise v14" hard-coded (current ATT&CK is v16+).
- `/api/v1/dashboard/ingestion-health` already exists and returns real data. **Nothing calls it.**

### P0-5. Analysts cannot finish a single alert in the UI
Backend has `PATCH /disposition`, `POST/GET /notes`, `GET /audit`. **`grep` finds zero frontend callers.** There is no Close / Escalate / Suppress / False-positive button, no notes, no audit trail view, no owner. The alert queue is a read-only list with an "Investigate" button.

### P0-6. "AI" claims that are false
- The investigation modal says *"Scoring threat impact… via Grok AI engine"* when `risk_assessment.engine = "deterministic_fallback"`.
- The admin page offers *"OpenAI GPT-4o / Anthropic Claude 3.5 Sonnet"*. The backend only supports xAI.
- Admin **"Save Configuration" is a no-op**: `handleSave` sets `saved=true` for 3 s and calls no API (`app/admin/page.tsx:16-19`). The "Authenticated" SIEM badge is hard-coded.

In a security product, UI text that misstates the system's own state is a credibility failure with auditors and customers, not a cosmetic issue.

---

## P1: Product gaps that block real SOC use

### Triage & case management
1. **No incident/case object.** 33 PowerShell alerts on 3 hosts within minutes should be 1-3 incidents. Instead the Investigations page lists 48 "cases" with identical titles.
2. **Duplicate alerts:** `DNS – raw.githubusercontent.com on forensiq-e2e-b` appears twice, and the same holds per host. Dedup (`normalization/dedup.py`, 300 s bucket) does not survive re-ingest or overlap windows.
3. **No disposition taxonomy.** "close" carries no verdict (True Positive / Benign True Positive / False Positive / Duplicate). Without it you cannot measure precision per rule, which is the main metric that drives detection tuning.
4. **No state machine.** Analyst can `suppress` then `close` an already suppressed alert; no transition validation; no required note.
5. **RBAC gap:** `soc_analyst` (L1) can **suppress a critical alert with no note** (verified via API). Suppression of high/critical should require `soc_manager` or a 4-eyes approval.
6. **No assignment, SLA, MTTA/MTTR, aging, or escalation timers.** A dashboard with "MTTD" but no ownership is decoration.
7. **No bulk actions, saved filters, keyboard triage, or column sorting** on the queue.
8. **Row click does nothing**; only the small "View" button opens detail.
9. Re-clicking **Investigate on an Investigated alert re-runs and overwrites** results in 0.4 s with no confirmation and no diff/versioning.

### Detection
10. Main still runs the hard-coded `services/detection_rules.py`. Only `suspicious_powershell_execution` and `dns_suspicious_query` fired on a dataset that also contains credential dumping and persistence.
11. `dns_suspicious_query` labels `raw.githubusercontent.com`, `pastebin.com`, `bit.ly` as "DNS Tunneling". Those lookups are not tunneling, and the rule as written is a guaranteed FP generator.
12. Severity saturation: 33/48 critical, 0 high, risk 100 on every critical. A score that is always 100 tells the analyst nothing.
13. MITRE mapping bugs: `T1071.004` tagged tactic **"Execution"** (should be Command and Control) and named `"Technique T1071.004"`. Titles render as `"[CRITICAL] [CRITICAL] Malicious PowerShell…"` in Reports.
14. `created_at` holds **event time** (29 days ago) while `detected_at` holds ingest time. The 24h activity chart keys on `created_at`, so it showed "no telemetry" right after 48 alerts landed.

### Reliability
15. `POST /investigate` uses FastAPI `BackgroundTasks`. A restart mid-run leaves the job `pending` and the alert stuck in `Investigating` forever. No retry, no reaper, no idempotency (two clicks = two concurrent runs).
16. **Opening the WebSocket starts an investigation** (`auto_start=True` default, `investigation_ws.py`). Viewing a "New" alert therefore triggers a pipeline run and, once an LLM is configured, spends money.
17. `/stats/*` endpoints swallow every exception and return `[]` / zeros (`alerts.py:96,124,192`), so outages render as "quiet day".
18. `/stats/mitre` reads only the first 500 alerts, so counts become wrong past 500.
19. `DEBUG=true` turns on root DEBUG logging. pymongo then logs **every command with full documents** (600 KB in 30 s during the audit), which leaks alert payloads into logs and buries real errors. Pin third-party loggers to WARNING regardless of DEBUG.
20. Naive `datetime.utcnow()` mixed with aware datetimes in several endpoints, a timezone bug waiting to happen.

### Security
21. Access + **7-day refresh token in `localStorage`**: any XSS becomes a week-long account takeover. Move refresh to an `HttpOnly; Secure; SameSite=Strict` cookie, keep access in memory.
22. WebSocket accepts the token in the **query string** (`?token=`), which ends up in proxy and access logs. Prefer the `Sec-WebSocket-Protocol` path the code already supports, or a short-lived WS ticket.
23. `create_admin_user.py` takes `--password` on the command line (shell history, process list). Prompt with `getpass`.
24. Bootstrap script accepts any email string, but login enforces `EmailStr`, which **rejects `.local`, `.test`, `.internal` domains**. Most AD shops use `corp.local`, so the admin you create cannot log in. Verified during audit.
25. No login MFA/SSO (OIDC/SAML), which enterprise buyers expect from day one.
26. No security headers / CSP on the Next.js app.

---

## P2: UX, polish & hygiene

- Alerts table **overflows horizontally at 1440 px** (header counts cut off); investigation modal overflows at ~580 px.
- Dozens of icon-only buttons with no `aria-label` (screen readers announce bare "button").
- Identical titles across rows; show the distinguishing field (command line excerpt, query, user) as a subtitle.
- Role label `admin` → "**Splunk Admin**" (`lib/roles.ts:4`) is wrong: it is a Forensiq admin.
- Nav items "AI Extraction" and "Raw Logs" are developer debug views, not analyst workflows. Fold them into the alert detail.
- README: `pip install -r requirements.txt` → **file does not exist** (use `pip install -e ".[dev]"`); `run_project.ps1` referenced but missing; "Next.js 15" badge but app is on 16.3.
- Root clutter: `implementation_plan.md`, `progress.md`, `project_status_report.md`, `DEVELOPMENT_PLAN.md`, `design.md`, `raw_alert.json`, `test_*.py` at backend root, `verify_live_siem.py`, `setup_splunk_alerts.py` duplicate of `scripts/`.
- Lint: **ruff 452** (46 blind `except Exception`, 32 unused imports); **ESLint 13 errors** (setState-in-effect, `any`); mypy cannot run (package-base config).
- `pyproject` declares `celery`, `redis`, `sqlalchemy` but none is used (dead deps; Redis appears in `.env.example` too).
- No CI pipeline in repo (no `.github/workflows`), so the 383 tests do not gate merges.

---

## What is genuinely good (keep it)

- SPL guard: blocked `| rest`, `outputlookup`, `delete`, `sendemail`, `index=_internal`, `index=*` in the audit battery.
- Refresh token rotation with reuse rejection (second use → 401).
- Tenant scoping applied consistently through `scoped_query`; tests cover cross-tenant reads.
- Mongo-lease poller with heartbeat; bounded investigation concurrency.
- Error responses return a request ID instead of stack traces.
- PDF generator escapes user content before ReportLab markup.
- 383 backend tests, ~41 s, all green.

---

## Roadmap to industry grade

Ordered so each phase is shippable and the product never gets *less* honest.

### Phase 0: Honesty pass (1 week). **Do this first.**
- [ ] Remove TI mocks + error fallback from runtime; surface `not_configured` / `error` states in UI.
- [ ] VT/AbuseIPDB thresholds + popularity/infra allowlist; "confirmed" requires 2 sources.
- [ ] Wire System Health to real checks (`/health` deep check: Splunk auth, Mongo, last ingestion lag, TI key status + last success, LLM status) and `/dashboard/ingestion-health`.
- [ ] Delete every literal fallback number (`119`, `94`); show "—" and an empty state.
- [ ] UI states which engine produced each result ("Rules engine" vs "LLM: grok-x"); remove fake provider options; remove or wire the admin Save.
- [ ] Fix the `.local` email lockout (use a permissive validator and lowercase emails; validate the same way in the bootstrap script).

### Phase 1: Close the SOC loop (2-3 weeks)
- [ ] Alert detail page (`/alerts/[id]`, deep-linkable) with: disposition buttons + **verdict taxonomy** (TP / BTP / FP / Duplicate), mandatory note on close/suppress, notes thread, audit timeline, assignee.
- [ ] Status state machine enforced server-side; suppress/close of high+critical requires `soc_manager`.
- [ ] Queue: assignment, sort, saved views, bulk close/assign, keyboard shortcuts (`j/k`, `e` escalate, `c` close).
- [ ] **Incidents:** group alerts by (host|user) + time window + shared rare IOC into a case; analysts work cases, not alerts.
- [ ] SLA clocks + MTTA/MTTR/precision-per-rule on the dashboard (computed from verdicts).

### Phase 2: Detection & scoring quality (2-3 weeks)
- [ ] Land the YAML rule engine (`feat/stage2-rules-eval`). It needs a rebase onto the new main (PRs #9 to #14 touched ingestion/streaming).
- [ ] Rule metadata: ATT&CK ID + tactic validated against the official STIX bundle (fixes T1071.004 → C2, names, v16).
- [ ] Re-score: severity × asset criticality × IOC confidence × rarity; calibrated so 100 is rare. Add a "why this score" breakdown.
- [ ] Correlation: time-windowed, rarity-weighted, self-excluded.
- [ ] Fix dedup across overlapping ingest windows (deterministic fingerprint on rule+host+key fields+bucket, unique index).
- [ ] Separate `event_time` vs `detected_at` everywhere; charts use the right one.
- [ ] Rule tuning loop: FP verdicts feed an exclusion suggestion per rule.

### Phase 3: Reliable AI investigation (2 weeks)
- [ ] Move investigations to a durable queue (arq/Celery on Redis, or a Mongo job table with a reaper). Idempotency key per alert; stuck-job recovery on boot.
- [ ] WS = observe only; starting a run is an explicit POST.
- [ ] LLM output: structured JSON schema, cite evidence IDs for every claim, refuse actions without evidence; model + prompt version stored per run; versioned investigation history (no overwrite).
- [ ] Human-in-the-loop for any containment recommendation; "suggested", never "confirmed".
- [ ] Eval harness: labelled alert set (Atomic Red Team + benign baselines) → precision/recall of verdicts per release. This becomes your headline metric.

### Phase 4: Enterprise hardening (ongoing)
- [ ] Auth: OIDC SSO, MFA, HttpOnly refresh cookie, WS tickets, CSP/security headers, user/role admin UI, SCIM later.
- [ ] Observability: JSON logs at INFO with third-party loggers capped, OpenTelemetry traces across the agent graph, Prometheus metrics (ingest lag, TI error rate, LLM latency/cost).
- [ ] CI: GitHub Actions running pytest + ruff + mypy + eslint + `next build`; block merge on red. Dependabot.
- [ ] Packaging: docker-compose for full stack (API, worker, web, Mongo, Redis) with health checks; `.env` validation on boot that fails loud in prod.
- [ ] Data: retention/TTL policy per collection, PII redaction in raw events, export/backup.
- [ ] Integrations beyond Splunk (Sentinel/Elastic via the existing `SIEMProvider`), SOAR actions (EDR isolate, IdP disable user) behind approval gates.

---

## Appendix: Evidence log

| # | Check | Result |
|---|---|---|
| 1 | `git merge origin/main` into local main | Clean; 23 files, +3860/-541 |
| 2 | `pytest` | 383 passed, 3 warnings, 41 s |
| 3 | `ruff check app` | 452 issues |
| 4 | `eslint src` | 13 errors, 82 warnings |
| 5 | `next build` | Success |
| 6 | Login `admin@forensiq.test` (created by bootstrap script) | 422 "special-use or reserved name" |
| 7 | Poller first cycle | 48 alerts ingested, 48 auto-investigated, 15 with mock TI |
| 8 | Recommendation on DNS alert | "Block confirmed malicious domain 'raw.githubusercontent.com'" |
| 9 | Recommendation on Mimikatz alert | "Verify whether … authorized IT administrative tasks" |
| 10 | Dashboard | "Total: 119 events" + "No telemetry in past 24h"; health all green with TI/LLM unconfigured |
| 11 | Analyst `POST /alerts/ingest` | 403 (correct) |
| 12 | Analyst suppress critical, no note | 200 (gap) |
| 13 | Suppressed → close | 200 (no state machine) |
| 14 | SPL `| rest`, `outputlookup`, `delete`, `_internal`, `index=*` | All rejected (good) |
| 15 | Refresh token reuse | 200 then 401 (good) |
| 16 | PDF report | 200, application/pdf, 14 KB |
| 17 | Frontend callers of disposition/notes/audit | 0 |
