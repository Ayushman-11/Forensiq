# Forensiq USP Pipeline Redesign: Data Layer, Ingestion, Agents, Evaluation

Date: 2026-10-06
Status: Draft for review

## 1. Goals

Make Forensiq's core value measurable and trustworthy:

- **A. Demonstrable AI value:** an evaluation harness that scores the pipeline against real attacks (Atomic Red Team) executed on a lab host and collected through Splunk.
- **B. Real SOC usability:** clean, normalized, deduplicated data so analysts and agents work on signal, not noise.

Constraints:

- **No mock layer.** All data comes from real Splunk telemetry and real threat-intel APIs. If an external source is unavailable the result is `unknown`, never a fabricated verdict. The hardcoded "malicious" prefixes in `ioc_agent.py` are removed.
- Lab: Splunk (index `windows`) receiving Sysmon, Windows Security and PowerShell logs; Invoke-AtomicRedTeam on a lab machine. Free-tier VirusTotal and AbuseIPDB keys (rate-limited).

## 2. Problems this addresses (from the 2026-10-06 audit)

- Brute-force alerts share one ID (`_event_id` has no `_cd` on `stats` rows), so all but the first are dropped.
- Ingestion advances its cursor even when rules fail, caps at 100 rows without pagination, and races on find-then-insert.
- Enrichment fabricates verdicts and caches them; unbounded concurrency hits VT limits.
- LLM output is trusted for the risk score and sees attacker-controlled text unmarked.
- Agent nodes are not failure-isolated (only correlation is).
- Investigation persistence is duplicated in three places (stream, background task, poller); a client disconnect leaves jobs stuck in `running`.
- Correlation matches on weak keys (process name, `SYSTEM`) with no time window or ranking.
- IOC extraction is duplicated and incomplete (private ranges, benign domains, TLD whitelist).

## 3. Architecture overview

```
Splunk ──► ingestion (cursor, pagination)
             │ raw rows
             ▼
        normalization/  mappers → CanonicalEvent → noise suppression → dedup/aggregation
             │ CanonicalEvent stream
             ▼
        detection/  Sigma-style YAML rules → alerts (+ raw_events kept)
             │
             ▼
        InvestigationService.run(alert)
          context → enrichment → correlation → mitre → timeline → risk → recommendation
             │ typed Evidence passed between agents
             ▼
        MongoDB (alerts, investigation_jobs, ingestion_runs)

eval/  runs atomics on lab host → waits for Splunk → runs the same pipeline → scores vs labels
```

## 4. Data layer: `app/normalization/`

- `canonical.py`: Pydantic `CanonicalEvent`
  - Identity: `event_id`, `ts` (UTC-aware), `host`, `user`, `event_code`, `source`.
  - Process: `process`, `parent`, `command_line`, `image_hash`.
  - Network: `src_ip`, `dst_ip`, `dst_port`, `domain`.
  - Other: `registry_key`, `logon_type`, `raw_ref` (pointer to the original Splunk row), `cleaning_notes[]`.
- `mappers/`: one mapper per source. Sysmon (1, 3, 11, 13, 22), Security (4624, 4625, 4648, 4688), PowerShell 4104. Each handles its source quirks: strip `DOMAIN\` prefixes, lowercase hostnames, treat `-` and empty as `None`, parse `Hashes=MD5=...,SHA256=...` into a dict, parse timestamps once to UTC-aware datetimes.
- `ioc.py`: the single IOC extractor. Uses the `ipaddress` module for private/reserved/link-local/loopback detection, a public-suffix-list check for domains (no hardcoded TLD list), URL extraction and defang handling. Replaces both existing extractors.
- `noise.py` plus `config/noise.yaml`: data-driven suppression (benign domains such as `*.microsoft.com` and `*.windowsupdate.com`, known-good process/parent pairs, the lab host's own forwarder traffic). Every suppressed event is counted with a reason; nothing is dropped silently.
- `dedup.py`: events sharing `(rule, host, user, key fields)` within a time bucket collapse into one alert carrying `count`, `first_seen`, `last_seen`. `event_id` is a hash of those stable keys, which fixes the brute-force collision. Aggregation rules (for example failed logons) are evaluated here rather than via a Splunk `stats` row.

Rules of the layer: raw rows are retained in `raw_events`; each cleaning step records what it changed so the evidence trail can show it.

## 5. Ingestion and detection

### 5.1 Ingestion (`services/ingestion.py`)

- **Cursor** per (tenant, source) stores `last_event_time` from the newest event actually processed, not wall-clock "now". Each cycle re-queries with an overlap window (`INGEST_OVERLAP_SECONDS`, default 120) so late-indexed events are caught. Stable IDs make the overlap safe.
- **Pagination**: loop with `offset` until exhausted, bounded by `INGEST_MAX_PAGES`.
- **Success-gated cursor**: the cursor advances only when the whole cycle succeeds; failures are recorded and retried next cycle.
- **One broad query per source** filtered by the union of relevant event codes (1 to 2 Splunk jobs per cycle instead of one per rule). Rules are evaluated locally on `CanonicalEvent`.
- **Idempotent writes**: `update_one(..., {"$setOnInsert": doc}, upsert=True)`.
- **Single poller**: a Mongo lease document with TTL so only one worker polls.
- **Health**: an `ingestion_runs` collection records fetched, kept, suppressed and alerted counts, lag and errors per cycle; the dashboard reads from it.
- New settings: `INGEST_OVERLAP_SECONDS`, `INGEST_MAX_PAGES`, `RULES_DIR`.

### 5.2 Detection (`app/detection/` plus `rules/*.yaml`)

- Sigma-style subset: `id`, `title`, ATT&CK `technique` and `tactic`, `severity`, `logsource`, `detection` (matchers `contains`, `endswith`, `re`, `all`, `any`), `falsepositives`, and an optional `aggregate: {count, within, by}`.
- A small in-repo matcher compiles YAML into a predicate over `CanonicalEvent`. The supported subset is documented; there is no Sigma backend dependency.
- Port the 8 existing rules first, then add roughly 10 to 15 covering the atomics under test: credential dumping, LOLBin download, schtasks, event log clearing, Defender tampering.

## 6. Agents

### 6.1 Shared contract

- `AgentState` carries typed `Evidence(id, source_agent, kind, summary, event_refs[], confidence)`. Agents append evidence; downstream claims (risk, recommendation) must cite evidence IDs so the UI can show "why".
- Every node is wrapped in `safe_node()`: on exception it logs, appends to `agent_errors[]`, returns partial state, and the pipeline continues. The final report marks degraded stages.

### 6.2 Agents

1. **Context**: works from `CanonicalEvent`; reconstructs the process tree from Sysmon parent/child chains; pulls a 5-minute neighborhood of events (same host and user) from Splunk so later agents see surrounding activity.
2. **Enrichment**: bounded concurrency (semaphore) with a token-bucket limiter per provider. HTTP 429 triggers backoff then `unknown` with `error="rate_limited"`; 404 on a hash means `unknown / not_seen`. Only successful lookups are cached; `unknown` gets a short TTL. Private, reserved and allowlisted indicators are never sent to third parties.
3. **Correlation**: entity-keyed (hash, IOC, host, user) within a time window, scored by recency, entity weight (hash/IOC above host above user) and shared technique. Process names and system accounts are not match keys. Output includes the matched entity and score; top N only.
4. **MITRE**: technique from the rule plus evidence-based heuristics. The 18-entry catalog is replaced by the real ATT&CK STIX bundle (bundled JSON plus a sync script) for names, tactics and URLs. Each mapping carries evidence IDs and a confidence level.
5. **Timeline**: real timestamps from the neighborhood events, not the alert time repeated for synthetic rows. Phases derive from the technique tactic.
6. **Risk**: an evidence-weighted deterministic score is computed first. The LLM supplies narrative and an adjustment of at most +/-15, validated against a Pydantic schema. Alert text in the prompt is delimited as untrusted data. The LLM cannot lower the score below a deterministic floor (confirmed-malicious IOC, credential-dumping technique). Invalid or missing LLM output falls back to the deterministic result and is logged.
7. **Recommendation**: playbook templates keyed by technique, tailored by the LLM; each checklist step cites evidence.

### 6.3 Orchestration

`InvestigationService.run(alert, on_event)` is the single entry point, replacing the three duplicated copies. It owns job state, cancellation (a client disconnect marks the job `cancelled`, never stuck in `running`) and persistence. The SSE endpoint and the poller both call it.

### 6.4 LLM provider

Grok stays behind a small interface with a timeout and one retry.

## 7. Evaluation harness: `backend/eval/`

- `atomics.yaml`: scenario list. Each entry: atomic ID (for example `T1059.001-1`), expected technique, tactic, minimum severity, `expected_alert: true`, cleanup command.
- `run_atomics.ps1`: runs on the lab machine via Invoke-AtomicRedTeam; writes `runs/<run_id>.json` with host, start and end timestamps and exit status; always runs cleanup.
- `baseline_windows.yaml`: idle periods on the lab host labeled benign; any alert inside is a false positive.
- `score.py`: per run, waits for Splunk indexing (polls until the event count stabilizes), pulls the window from Splunk, runs the real pipeline, compares with labels.

Metrics:

- Detection recall and false-positive rate on baseline windows.
- Technique accuracy (exact and parent-technique match).
- Noise reduction (raw events versus alerts after suppression and dedup).
- Severity agreement with the expected minimum.
- Evidence grounding (share of risk and recommendation claims with valid citations).
- LLM value (deterministic-only versus deterministic plus LLM).
- Per-stage and total latency; degraded-run rate.

Output: `eval/results/<date>.json` plus a generated markdown table, stamped with the git SHA for before/after comparison.

Safety: the runner executes only atomics on the explicit allowlist, refuses to run unless the host name matches the configured lab host, always runs cleanup, and excludes destructive atomics (disk wipe, ransomware simulation).

## 8. Testing

- Unit: mappers, IOC extraction, noise rules, dedup and ID stability, rule matcher, scoring floors, LLM schema failures, rate limiting.
- Integration: pipeline on real rows exported from the lab Splunk. The Splunk HTTP boundary may be faked only in unit tests; evaluation always runs against real Splunk and real threat-intel APIs.

## 9. Delivery stages

Each stage lands on its own branch and passes tests before the next.

1. **Data layer and ingestion**: normalization package, new cursor/pagination/idempotent ingestion, poller lease, ingestion health.
2. **Rules and eval baseline**: Sigma-style rules, evaluation harness, baseline metrics captured with the existing agents running on the new data layer.
3. **Agents**: shared contract, `safe_node`, `InvestigationService`, agent upgrades, rescored against the baseline.

## 10. Out of scope

Security hardening items from the audit (tenancy gaps, SPL search restrictions, auth rate limiting, error leakage, committed data dumps), reports, org management and the frontend. These follow separately.

## 11. Open risks

- Free-tier VT (4 requests per minute) bounds enrichment throughput; the evaluation must tolerate `unknown` results and report them honestly.
- Atomic behavior differs by Windows build; some atomics may not trigger telemetry, which is itself a measured result (recall).
- The STIX bundle adds repository size; bundle only the enterprise ATT&CK JSON.
