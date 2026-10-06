# Security Hardening Batch Design

Date: 2026-10-06
Status: Approved in chat by the project owner (30 minute access tokens; dumps untracked)

## Goal

Close the security and robustness gaps found in the 2026-10-06 audit so that `main` is safe to deploy:
no cross-tenant reads, no arbitrary SPL execution, no internal error leakage, brute-force-resistant login,
accurate audit trail, safe production defaults, and no sensitive data committed to the repository.

## Scope

### 1. Search (`POST /api/v1/search`)
- Role gate: `admin`, `soc_manager`, `soc_analyst`.
- SPL allowlist guard (`app/services/spl_guard.py`): the query must be one search expression followed by
  pipeline stages whose command is in `{search, where, table, stats, eval, fields, sort, head, tail, top, rare, dedup, spath, rex}`.
  Subsearches (`[`), macros (backtick), leading-pipe generating commands, inline `earliest=/latest=` modifiers,
  `index!=`, `index IN`, and any index outside `SPLUNK_ALLOWED_INDEXES` (default `["windows"]`) are rejected.
  If the search expression names no index, `index=<SPLUNK_DETECTION_INDEX>` is injected.
- Time range: relative values only (`-15m`, `-24h`, `-7d`), at most `SEARCH_MAX_RANGE_DAYS` (30); `latest_time` is `now` or relative.
- The MongoDB fallback is scoped to the caller's tenant.
- Each executed search is written to the audit log (query text truncated).
- The frontend posted to a dead path (`/api/v1/search/search`) and offered `index=sysmon` / `index=*` presets; fix both.

### 2. Tenant scoping and input validation (`/api/v1/alerts`)
- `GET /alerts/investigation/{job_id}` and `GET /alerts/stats/*` are tenant scoped.
- Alert list: `limit` 1..200, `search` regex-escaped and max 100 chars, `severity` and `status` validated against known values (422 otherwise).

### 3. Error handling
- Unhandled errors return `{"detail": "...", "request_id": "<id>"}` (and `X-Request-ID`); the real error is logged with the same id.
- Endpoints stop returning `str(exc)`; they raise `internal_error(...)` (HTTP 500, `detail="Internal server error (ref <id>)"`).
- SSE investigation errors and stored job errors are sanitized the same way.
- Fix `/alerts/ingest` turning its own 502 into a 500.

### 4. Authentication
- Login throttle in MongoDB (`login_attempts`, TTL on `expires_at`): 5 failures for an (email, client IP) pair lock that pair for 15 minutes
  (HTTP 429 + `Retry-After`); success clears the counter; unknown emails count too.
- Uniform timing: unknown emails still run one bcrypt verification against a dummy hash.
- Password length: at most 128 characters and 72 UTF-8 bytes (bcrypt limit) else 422.
- Access token default lifetime 30 minutes (the frontend `apiFetch` already refreshes on 401).
- Audit log records the real actor (`user["id"]`).

### 5. Configuration
- `DEBUG` defaults to `False`.
- `ENV=production` additionally requires: secret key of at least 32 characters and not the default, non-default `SPLUNK_PASSWORD`, `DEBUG=False`.
- New settings: `SPLUNK_ALLOWED_INDEXES`, `SEARCH_MAX_RANGE_DAYS`, `LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_MINUTES`.

### 6. Repository hygiene
- `backend/mongo_dump_json/` is untracked and git-ignored (the files stay on disk; the README share-by-zip flow is unchanged).
- Test fixture rows are pseudonymized (email, user/host names, machine SID, internal IP) by `scripts/export_fixture_rows.py` so regeneration stays clean.
- Git history is NOT rewritten; the admin password hash and telemetry remain in earlier commits. Rotating the admin password and, if desired, purging history are manual follow-ups.

## Out of scope
Stage 2 and 3 of the USP pipeline work, per-tenant rate limiting, organization management, RBAC redesign, Mongo/Redis network exposure in docker-compose, history rewrite.

## Testing
Every behavior above has a regression test (pytest, mongomock, FastAPI test apps with dependency overrides). Frontend: `tsc --noEmit` and `next build`.
