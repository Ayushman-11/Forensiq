# Security Hardening Batch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `main` safe to deploy: tenant-isolated reads, guarded Splunk search, no internal error leakage, brute-force-resistant login, accurate audit trail, safe production defaults, and no sensitive data tracked in git.

**Architecture:** Small, independent changes at the API edge. A new pure module (`spl_guard`) validates search queries; a new `errors` helper centralizes safe 500s; a Mongo-backed throttle protects login; configuration validation fails fast in production. No schema migrations.

**Tech Stack:** Python 3.11+, FastAPI, Motor/MongoDB (mongomock-motor in tests), Pydantic v2, bcrypt, pytest + pytest-asyncio; Next.js frontend (path/preset fix only).

**Spec:** `docs/superpowers/specs/2026-10-06-security-hardening-design.md`

## Global Constraints

- Run all backend commands from `D:\forensiq\Forensiq\backend` with `./venv/Scripts/python.exe` (Git Bash syntax).
- Existing tests (155 at plan start) must keep passing after every task. A test may be changed only where this plan says so, and the change is stated in the task.
- No mock data in tests beyond mongomock and FastAPI dependency overrides / Splunk-boundary fakes (same pattern as existing tests in `tests/test_auth_endpoints.py` and `tests/test_route_protection.py`).
- Never put internal exception text in an HTTP response body or SSE payload.
- Datetimes stored in Mongo by new code are naive UTC (`datetime.now(timezone.utc).replace(tzinfo=None)`), matching `app/services/lease.py`.
- End every commit message with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (verbatim).
- Do not commit `.superpowers/`.

## File Structure

| File | Responsibility |
|---|---|
| `app/core/errors.py` (new) | `new_request_id()`, `internal_error()` |
| `app/main.py` | global handler returns `request_id`; index guard already exists |
| `app/core/config.py` | new settings, safer defaults, production validation |
| `app/services/audit.py` | real actor id |
| `app/services/login_throttle.py` (new) | Mongo-backed login failure throttle |
| `app/api/v1/endpoints/auth.py`, `app/schemas/auth.py` | throttle, uniform timing, password caps |
| `app/services/spl_guard.py` (new) | `validate_search`, `validate_time_range`, `SPLRejected` |
| `app/api/v1/endpoints/search.py` | role gate, guard, scoped fallback, audit |
| `app/api/v1/endpoints/alerts.py` | safe errors, tenant scoping, input validation |
| `app/api/v1/endpoints/reports.py` | safe errors |
| `app/database/indexes.py` | TTL index for `login_attempts` |
| `scripts/export_fixture_rows.py`, `tests/fixtures/splunk_rows.json` | pseudonymization |
| `frontend/src/app/search/page.tsx` | correct path, valid presets |
| tests | `test_error_handling.py`, `test_config_hardening.py`, `test_audit_actor.py`, `test_login_throttle.py`, `test_spl_guard.py`, `test_search_endpoint.py`, `test_alerts_hardening.py`, `test_repo_hygiene.py` |

---

### Task 1: Safe error handling

**Files:**
- Create: `backend/app/core/errors.py`, `backend/tests/test_error_handling.py`
- Modify: `backend/app/main.py` (global handler), `backend/app/api/v1/endpoints/alerts.py`, `backend/app/api/v1/endpoints/reports.py`

**Interfaces:**
- Produces: `app.core.errors.new_request_id() -> str` (12 hex chars) and `app.core.errors.internal_error(event: str, exc: Exception, **context) -> HTTPException` (status 500, `detail == f"Internal server error (ref {id})"`, logs the real error with the same id).

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_error_handling.py`:

```python
import re
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from app.api.v1.endpoints import alerts as alerts_module
from app.core.errors import internal_error, new_request_id
from app.main import global_exception_handler


def test_internal_error_hides_exception_text_and_carries_ref():
    exc = internal_error("something_failed", RuntimeError("db password is hunter2"), alert_id="a1")
    assert isinstance(exc, HTTPException) and exc.status_code == 500
    assert "hunter2" not in exc.detail
    assert re.fullmatch(r"Internal server error \(ref [0-9a-f]{12}\)", exc.detail)


def test_request_ids_are_unique_hex():
    ids = {new_request_id() for _ in range(50)}
    assert len(ids) == 50 and all(re.fullmatch(r"[0-9a-f]{12}", i) for i in ids)


@pytest.mark.asyncio
async def test_global_handler_returns_request_id_without_leaking():
    app = FastAPI()
    app.add_exception_handler(Exception, global_exception_handler)

    @app.get("/boom")
    async def boom():
        raise RuntimeError("secret internal detail")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.get("/boom")
    assert resp.status_code == 500
    body = resp.json()
    assert "secret internal detail" not in resp.text
    assert re.fullmatch(r"[0-9a-f]{12}", body["request_id"])
    assert resp.headers["X-Request-ID"] == body["request_id"]


class _ExplodingDb:
    """Fake database whose every collection raises, to exercise the endpoint's error path."""

    def __getitem__(self, name):
        coll = AsyncMock()
        coll.find_one = AsyncMock(side_effect=RuntimeError("boom-secret"))
        return coll


@pytest.mark.asyncio
async def test_get_alert_500_does_not_leak_exception_text():
    with pytest.raises(HTTPException) as info:
        await alerts_module.get_alert("a1", db=_ExplodingDb(), user={"org_id": "default"})
    assert info.value.status_code == 500 and "boom-secret" not in info.value.detail


@pytest.mark.asyncio
async def test_ingest_502_is_not_rewrapped_as_500():
    class FakeService:
        errors = [{"stage": "fetch", "error": "splunk down"}]
        total_fetched = 0
        rules_run = 0

        def __init__(self, *a, **k):
            pass

        async def fetch_and_store_alerts(self):
            return []

    with patch.object(alerts_module, "IngestionService", FakeService):
        with pytest.raises(HTTPException) as info:
            await alerts_module.ingest_from_splunk(db=object(), _user={"org_id": "default", "role": "admin"})
    assert info.value.status_code == 502
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_error_handling.py -q`
Expected: FAIL (`ModuleNotFoundError: app.core.errors`).

- [ ] **Step 3: Implement the helper**

Create `backend/app/core/errors.py`:

```python
"""Safe error responses: log the real error server-side, return only a reference id."""

import uuid

from fastapi import HTTPException

from app.core.logging import logger


def new_request_id() -> str:
    return uuid.uuid4().hex[:12]


def internal_error(event: str, exc: Exception, **context) -> HTTPException:
    """Log `exc` with a fresh reference id and return a generic 500 for the caller to raise."""
    ref = new_request_id()
    logger.error(event, request_id=ref, error=str(exc), error_type=type(exc).__name__, **context)
    return HTTPException(status_code=500, detail=f"Internal server error (ref {ref})")
```

- [ ] **Step 4: Replace the global handler**

In `backend/app/main.py` add `from app.core.errors import new_request_id` to the imports and replace the existing `global_exception_handler` with:

```python
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global unhandled exception handler: generic body, real error logged under a request id."""
    ref = new_request_id()
    logger.error(
        "unhandled_exception", path=request.url.path, request_id=ref,
        error=str(exc), error_type=type(exc).__name__,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred.", "request_id": ref},
        headers={"X-Request-ID": ref},
    )
```

- [ ] **Step 5: Remove `str(e)` from endpoints**

In `backend/app/api/v1/endpoints/alerts.py` add `from app.core.errors import internal_error` and make these exact changes:

1. `list_alerts` — replace the `raise HTTPException(status_code=500, detail=f"Failed to fetch alerts: {str(e)}")` block with `raise internal_error("alerts_list_failed", e)`.
2. `get_alert`, `investigate_alert_stream` (outer handler), `investigate_alert`, `get_investigation_status` — each ends with `except Exception as e: raise HTTPException(status_code=500, detail=str(e))`; replace each with `raise internal_error("alerts_endpoint_failed", e, alert_id=alert_id)` (use `job_id=job_id` in `get_investigation_status`).
3. `ingest_from_splunk` — replace its `except Exception as e:` handler so the `HTTPException(502)` it raises is preserved:

```python
    except HTTPException:
        raise
    except Exception as e:
        raise internal_error("alerts_ingest_failed", e)
```

4. SSE stream error path (inside `sse_event_stream`'s `except Exception as e:`): create `ref = new_request_id()` (import it too), log with `ref` (`logger.error("investigation_stream_failed", request_id=ref, alert_id=alert_id, error=str(e))`), store `"error": "investigation_failed", "error_ref": ref` in the `investigation_jobs` update, and yield `{'job_id': job_id, 'alert_id': alert_id, 'error': f'Investigation failed (ref {ref})'}` instead of `str(e)`.
5. `run_investigation_background`'s failure handler stores `"error": str(e)`; change to `"error": "investigation_failed", "error_ref": ref` the same way (log the real error with `ref`).

In `backend/app/api/v1/endpoints/reports.py` add the same import and replace both `raise HTTPException(status_code=500, detail=f"... {str(exc)}")` lines with `raise internal_error("report_generation_failed", exc, alert_id=alert_id)` (keep the existing `logger.error` lines or drop them — `internal_error` logs).

- [ ] **Step 6: Run to verify pass and no regressions**

Run: `./venv/Scripts/python.exe -m pytest tests/test_error_handling.py -q` then `./venv/Scripts/python.exe -m pytest -q`
Expected: new tests PASS; full suite PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/app/core/errors.py backend/app/main.py backend/app/api/v1/endpoints/alerts.py backend/app/api/v1/endpoints/reports.py backend/tests/test_error_handling.py
git commit -m "fix(security): stop leaking exception text; return request ids; keep ingest 502"
```

---

### Task 2: Safe configuration defaults and production validation

**Files:**
- Modify: `backend/app/core/config.py`, `backend/.env.example`, `backend/tests/test_config.py`
- Create: `backend/tests/test_config_hardening.py`

**Interfaces:**
- Produces settings: `DEBUG` default `False`; `ACCESS_TOKEN_EXPIRE_MINUTES` default `30`; `SPLUNK_ALLOWED_INDEXES: List[str] = ["windows"]`; `SEARCH_MAX_RANGE_DAYS: int = 30`; `LOGIN_MAX_FAILURES: int = 5`; `LOGIN_LOCKOUT_MINUTES: int = 15`; module constant `DEFAULT_SPLUNK_PASSWORD = "ChangedPassword123!"`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_config_hardening.py`:

```python
import pytest

from app.core.config import DEFAULT_SECRET_KEY, DEFAULT_SPLUNK_PASSWORD, Settings

GOOD = dict(_env_file=None, ENV="production", SECRET_KEY="x" * 40, SPLUNK_PASSWORD="a-real-splunk-password", DEBUG=False)


def test_safe_defaults():
    s = Settings(_env_file=None)
    assert s.DEBUG is False
    assert s.ACCESS_TOKEN_EXPIRE_MINUTES == 30
    assert s.SPLUNK_ALLOWED_INDEXES == ["windows"]
    assert s.SEARCH_MAX_RANGE_DAYS == 30
    assert s.LOGIN_MAX_FAILURES == 5 and s.LOGIN_LOCKOUT_MINUTES == 15


def test_valid_production_settings_boot():
    assert Settings(**GOOD).ENV == "production"


@pytest.mark.parametrize("override", [
    {"SECRET_KEY": "short-secret"},
    {"SECRET_KEY": DEFAULT_SECRET_KEY},
    {"SPLUNK_PASSWORD": DEFAULT_SPLUNK_PASSWORD},
    {"DEBUG": True},
])
def test_production_rejects_insecure_values(override):
    with pytest.raises(ValueError):
        Settings(**{**GOOD, **override})


def test_development_is_not_blocked():
    s = Settings(_env_file=None, ENV="development", SECRET_KEY=DEFAULT_SECRET_KEY, DEBUG=True)
    assert s.DEBUG is True
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_config_hardening.py -q`
Expected: FAIL (`ImportError: DEFAULT_SPLUNK_PASSWORD`).

- [ ] **Step 3: Implement**

In `backend/app/core/config.py`:

1. Below `DEFAULT_SECRET_KEY` add `DEFAULT_SPLUNK_PASSWORD = "ChangedPassword123!"`.
2. Change `DEBUG` to `Field(default=False, description="Enable debug mode and verbose logs")`.
3. Change `ACCESS_TOKEN_EXPIRE_MINUTES` to `Field(default=30, description="Access token TTL in minutes")`.
4. Change `SPLUNK_PASSWORD`'s default to `DEFAULT_SPLUNK_PASSWORD`.
5. After `SPLUNK_DETECTION_INDEX` add:

```python
    SPLUNK_ALLOWED_INDEXES: List[str] = Field(
        default=["windows"], description="Indexes users may query through /search"
    )
    SEARCH_MAX_RANGE_DAYS: int = Field(default=30, description="Maximum lookback for /search queries")

    # Login throttling
    LOGIN_MAX_FAILURES: int = Field(default=5, description="Failed logins per email+IP before lockout")
    LOGIN_LOCKOUT_MINUTES: int = Field(default=15, description="Lockout duration in minutes")
```

6. Replace the `_reject_insecure_secret_in_production` validator with:

```python
    @model_validator(mode="after")
    def _reject_insecure_production_settings(self) -> "Settings":
        """Fail fast at startup if production runs with insecure defaults. Development/test are unaffected."""
        if self.ENV.lower() != "production":
            return self
        problems = []
        if self.SECRET_KEY == DEFAULT_SECRET_KEY:
            problems.append("FORENSIQ_SECRET_KEY must not be the insecure default development key")
        elif len(self.SECRET_KEY) < 32:
            problems.append("FORENSIQ_SECRET_KEY must be at least 32 characters")
        if self.SPLUNK_PASSWORD == DEFAULT_SPLUNK_PASSWORD:
            problems.append("FORENSIQ_SPLUNK_PASSWORD must not be the default")
        if self.DEBUG:
            problems.append("FORENSIQ_DEBUG must be false in production")
        if problems:
            raise ValueError("Refusing to start in production: " + "; ".join(problems))
        return self
```

In `backend/tests/test_config.py` the test `test_production_with_custom_secret_key_succeeds` now needs a non-default Splunk password: change its `Settings(...)` call to `Settings(_env_file=None, ENV="production", SECRET_KEY="a-real-unique-production-secret-key-value", SPLUNK_PASSWORD="a-real-splunk-password")` (this is the only existing test changed; the new requirement is the reason).

In `backend/.env.example` change the comment line `# JWT token TTLs (minutes) — defaults: access=1440 (24h), refresh=10080 (7d)` to `# JWT token TTLs (minutes) — defaults: access=30, refresh=10080 (7d)` and add `FORENSIQ_SPLUNK_ALLOWED_INDEXES=["windows"]` under the Splunk block.

- [ ] **Step 4: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_config_hardening.py tests/test_config.py tests/test_main_lifespan.py -q` then the full suite.
Expected: PASS. If a full-suite test relied on the old `DEBUG=True` default, set the value explicitly inside that test instead of reverting the default, and say so in your report.

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/config.py backend/.env.example backend/tests/test_config.py backend/tests/test_config_hardening.py
git commit -m "feat(security): safe config defaults, 30 minute access tokens, production validation"
```

---

### Task 3: Audit log records the real actor

**Files:**
- Modify: `backend/app/services/audit.py`
- Create: `backend/tests/test_audit_actor.py`

**Interfaces:** `record_audit(db, user, action, entity_type, entity_id, metadata=None)` unchanged; `actor_id` now `str(user["id"])` (falls back to `user["_id"]`, then `"system"`).

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_audit_actor.py`:

```python
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.audit import record_audit


@pytest.mark.asyncio
async def test_actor_id_is_the_authenticated_users_id():
    db = AsyncMongoMockClient()["audit_test"]
    await record_audit(db, {"id": "user-1", "email": "a@b.test", "org_id": "default"}, "alert.close", "alert", "a1")
    doc = await db["audit_logs"].find_one({})
    assert doc["actor_id"] == "user-1" and doc["actor_email"] == "a@b.test"


@pytest.mark.asyncio
async def test_legacy_underscore_id_and_system_fallbacks():
    db = AsyncMongoMockClient()["audit_test2"]
    await record_audit(db, {"_id": "legacy"}, "x", "alert", "a1")
    await record_audit(db, None, "y", "alert", "a2")
    docs = {d["action"]: d["actor_id"] async for d in db["audit_logs"].find({})}
    assert docs == {"x": "legacy", "y": "system"}
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_audit_actor.py -q`
Expected: FAIL (`actor_id` is `"system"`).

- [ ] **Step 3: Implement**

In `backend/app/services/audit.py` replace the `"actor_id"` line with:

```python
        "actor_id": str((user or {}).get("id") or (user or {}).get("_id") or "system"),
```

- [ ] **Step 4: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_audit_actor.py -q` then the full suite.
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/audit.py backend/tests/test_audit_actor.py
git commit -m "fix(audit): record the authenticated user id as actor"
```

---

### Task 4: Login throttle, uniform timing, password caps

**Files:**
- Create: `backend/app/services/login_throttle.py`, `backend/tests/test_login_throttle.py`
- Modify: `backend/app/api/v1/endpoints/auth.py`, `backend/app/schemas/auth.py`, `backend/app/database/indexes.py`

**Interfaces:**
- Consumes: settings `LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_MINUTES` (Task 2).
- Produces (`app.services.login_throttle`): `throttle_key(email: str, ip: str) -> str`; `async locked_for(db, key: str) -> int` (seconds until unlock, `0` when not locked); `async record_failure(db, key: str) -> None`; `async clear_failures(db, key: str) -> None`.
- Produces: `/auth/login` returns 429 with `Retry-After` while locked; 401 otherwise on bad credentials; 422 for passwords over 128 chars or 72 UTF-8 bytes.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_login_throttle.py`:

```python
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.v1.endpoints import auth as auth_module
from app.core.config import settings
from app.core.security import hash_password
from app.database.session import get_db
from app.services.login_throttle import clear_failures, locked_for, record_failure, throttle_key


@pytest.fixture
def db():
    return AsyncMongoMockClient()["throttle_test"]


@pytest.fixture
def app(db):
    app = FastAPI()
    app.include_router(auth_module.router, prefix="/auth")

    async def override_get_db():
        return db

    app.dependency_overrides[get_db] = override_get_db
    return app


@pytest.fixture
async def user(db):
    await db["users"].insert_one({"_id": "u1", "email": "analyst@forensiq.ai", "password_hash": hash_password("s3cret-pw"),
                                  "role": "soc_analyst", "is_active": True})


async def _login(app, email, password):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.post("/auth/login", json={"email": email, "password": password})


@pytest.mark.asyncio
async def test_lockout_after_max_failures_blocks_even_correct_password(app, user):
    for _ in range(settings.LOGIN_MAX_FAILURES):
        assert (await _login(app, "analyst@forensiq.ai", "wrong")).status_code == 401
    locked = await _login(app, "analyst@forensiq.ai", "s3cret-pw")
    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_success_clears_the_counter(app, user):
    for _ in range(settings.LOGIN_MAX_FAILURES - 1):
        await _login(app, "analyst@forensiq.ai", "wrong")
    assert (await _login(app, "analyst@forensiq.ai", "s3cret-pw")).status_code == 200
    for _ in range(settings.LOGIN_MAX_FAILURES - 1):
        assert (await _login(app, "analyst@forensiq.ai", "wrong")).status_code == 401


@pytest.mark.asyncio
async def test_unknown_emails_are_throttled_and_other_emails_unaffected(app, user):
    for _ in range(settings.LOGIN_MAX_FAILURES):
        assert (await _login(app, "ghost@forensiq.ai", "x")).status_code == 401
    assert (await _login(app, "ghost@forensiq.ai", "x")).status_code == 429
    assert (await _login(app, "analyst@forensiq.ai", "s3cret-pw")).status_code == 200


@pytest.mark.asyncio
async def test_unknown_email_still_runs_a_password_verification(app):
    with patch.object(auth_module, "verify_password", return_value=False) as spy:
        resp = await _login(app, "ghost@forensiq.ai", "whatever")
    assert resp.status_code == 401 and spy.call_count == 1


@pytest.mark.asyncio
async def test_overlong_passwords_are_rejected_with_422(app):
    assert (await _login(app, "a@forensiq.ai", "x" * 129)).status_code == 422
    assert (await _login(app, "a@forensiq.ai", "é" * 40)).status_code == 422  # 80 bytes


@pytest.mark.asyncio
async def test_expired_lock_resets_instead_of_relocking(db):
    key = throttle_key("a@b.test", "1.2.3.4")
    expired = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
    await db["login_attempts"].insert_one({"_id": key, "failures": 99, "expires_at": expired})
    assert await locked_for(db, key) == 0
    await record_failure(db, key)
    assert (await db["login_attempts"].find_one({"_id": key}))["failures"] == 1
    await clear_failures(db, key)
    assert await db["login_attempts"].find_one({"_id": key}) is None
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_login_throttle.py -q`
Expected: FAIL (`ModuleNotFoundError: app.services.login_throttle`).

- [ ] **Step 3: Implement the throttle**

Create `backend/app/services/login_throttle.py`:

```python
"""Mongo-backed login throttle keyed by (email, client IP). Documents expire via a TTL index on `expires_at`."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from app.core.config import settings

COLLECTION = "login_attempts"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # Mongo returns naive UTC


def throttle_key(email: str, ip: str) -> str:
    return hashlib.sha256(f"{email.strip().lower()}|{ip}".encode()).hexdigest()


async def locked_for(db, key: str) -> int:
    """Seconds until the key unlocks; 0 when not locked."""
    doc = await db[COLLECTION].find_one({"_id": key})
    if not doc or doc.get("failures", 0) < settings.LOGIN_MAX_FAILURES:
        return 0
    remaining = (doc["expires_at"] - _now()).total_seconds()
    return int(remaining) + 1 if remaining > 0 else 0


async def record_failure(db, key: str) -> None:
    now = _now()
    # The TTL monitor runs about once a minute, so drop an expired window explicitly before counting.
    await db[COLLECTION].delete_one({"_id": key, "expires_at": {"$lte": now}})
    await db[COLLECTION].update_one(
        {"_id": key},
        {"$inc": {"failures": 1}, "$set": {"expires_at": now + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)}},
        upsert=True,
    )


async def clear_failures(db, key: str) -> None:
    await db[COLLECTION].delete_one({"_id": key})
```

- [ ] **Step 4: Wire the login endpoint**

In `backend/app/api/v1/endpoints/auth.py`: add imports `import functools`, `from fastapi import Request`, `from app.core.security import hash_password`, `from app.services.login_throttle import clear_failures, locked_for, record_failure, throttle_key`, then add above the `login` route:

```python
@functools.lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """Valid bcrypt hash so unknown emails cost the same as a real verification."""
    return hash_password("forensiq-dummy-password-for-timing")
```

and replace the whole `login` function with:

```python
@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Authenticates a user by email/password and issues an access + refresh token pair."""
    email = req.email.strip().lower()
    ip = request.client.host if request.client else "unknown"
    key = throttle_key(email, ip)

    retry_after = await locked_for(db, key)
    if retry_after:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    user = await db["users"].find_one({"email": email})
    password_ok = verify_password(req.password, user["password_hash"] if user else _dummy_hash())
    if not user or not user.get("is_active", False) or not password_ok:
        await record_failure(db, key)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    await clear_failures(db, key)
    return await _issue_tokens(db, user_id=str(user["_id"]), email=user["email"], role=user["role"])
```

In `backend/app/schemas/auth.py` import `field_validator` and replace `LoginRequest` with:

```python
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("password")
    @classmethod
    def _bcrypt_byte_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("password must be at most 72 bytes")
        return value
```

In `backend/app/database/indexes.py` append to `ensure_indexes`:

```python
    await db["login_attempts"].create_index("expires_at", expireAfterSeconds=0)
```

and extend `tests/test_indexes_health.py::test_ensure_indexes_creates_expected_indexes` with an assertion that `login_attempts` has an index with `expireAfterSeconds == 0` (this one existing test gets one added assertion).

- [ ] **Step 5: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_login_throttle.py tests/test_auth_endpoints.py tests/test_indexes_health.py -q` then the full suite.
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/app/services/login_throttle.py backend/app/api/v1/endpoints/auth.py backend/app/schemas/auth.py backend/app/database/indexes.py backend/tests/test_login_throttle.py backend/tests/test_indexes_health.py
git commit -m "feat(security): login throttle with lockout, uniform timing and password caps"
```

---

### Task 5: SPL guard

**Files:**
- Create: `backend/app/services/spl_guard.py`, `backend/tests/test_spl_guard.py`

**Interfaces:**
- Produces (`app.services.spl_guard`):
  - `class SPLRejected(ValueError)` — message is safe to show to the caller.
  - `validate_search(query: str, *, allowed_indexes: Iterable[str], default_index: str) -> str` — returns the rebuilt query, always starting with `search ` and containing an allowed `index=`.
  - `validate_time_range(earliest: str, latest: str, max_days: int) -> None`.
  - `ALLOWED_COMMANDS: frozenset[str]`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_spl_guard.py`:

```python
import pytest

from app.services.spl_guard import ALLOWED_COMMANDS, SPLRejected, validate_search, validate_time_range

KW = dict(allowed_indexes=["windows"], default_index="windows")


def ok(q):
    return validate_search(q, **KW)


def test_adds_search_prefix_and_default_index():
    assert ok("EventCode=4625") == "search index=windows EventCode=4625"
    assert ok("search EventCode=1 | head 50") == "search index=windows EventCode=1 | head 50"


def test_explicit_allowed_index_is_kept_and_not_duplicated():
    out = ok('search index="windows" EventCode=3 | stats count by host | sort -count')
    assert out.count("index=") == 1 and out.startswith("search ")
    assert ok("index=WINDOWS | head 5").startswith("search index=WINDOWS")


@pytest.mark.parametrize("cmd", [
    "delete", "outputlookup x", "outputcsv x", "rest /services/server/info", "collect index=x", "sendemail to=a@b.c",
    "script foo", "map search=\"x\"", "tstats count", "makeresults", "inputlookup x", "loadjob 1", "dbxquery q", "run foo",
])
def test_disallowed_commands_are_rejected(cmd):
    with pytest.raises(SPLRejected):
        ok(f"search EventCode=1 | {cmd}")


def test_every_allowed_command_is_accepted():
    for cmd in sorted(ALLOWED_COMMANDS - {"search"}):
        ok(f"EventCode=1 | {cmd} host")


@pytest.mark.parametrize("q", [
    "| rest /services/x", "|makeresults", "EventCode=1 [ search index=other | fields host ]", "EventCode=1 `macro`",
    "index=other EventCode=1", "index=* EventCode=1", "index!=windows", "index IN (windows, other)",
    "index=windows OR index=secret", "index=windows | search index=other",
    "EventCode=1 earliest=-1y", "index=windows latest=+1d", "EventCode=1 _index_earliest=-5y",
    "", "   ", 'EventCode="unterminated', "x" * 4001, " | ".join(["head 1"] * 12),
    "EventCode=1 | head 5 | | head 2",
])
def test_bad_queries_are_rejected(q):
    with pytest.raises(SPLRejected):
        ok(q)


def test_quoted_pipes_and_brackets_are_data_not_syntax():
    out = ok('CommandLine="a | b [c]" | head 5')
    assert 'CommandLine="a | b [c]"' in out and out.endswith("| head 5")


def test_time_range_accepts_relative_within_limit():
    validate_time_range("-15m", "now", 30)
    validate_time_range("-24h", "now", 30)
    validate_time_range("-30d", "-5m", 30)


@pytest.mark.parametrize("earliest,latest", [
    ("-31d", "now"), ("-5w", "now"), ("2026-01-01T00:00:00", "now"), ("0", "now"), ("-1h", "+1h"),
    ("-5m", "-10m"), ("-0m", "now"), ("", "now"), ("-1h", "2026-01-01"), ("-1x", "now"),
])
def test_time_range_rejections(earliest, latest):
    with pytest.raises(SPLRejected):
        validate_time_range(earliest, latest, 30)
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_spl_guard.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

Create `backend/app/services/spl_guard.py`:

```python
"""Allowlist-based guard for user-supplied SPL. Rejects anything that is not a plain search + safe pipeline."""

from __future__ import annotations

import re
from typing import Iterable

ALLOWED_COMMANDS = frozenset(
    {"search", "where", "table", "stats", "eval", "fields", "sort", "head", "tail", "top", "rare", "dedup", "spath", "rex"}
)
MAX_QUERY_CHARS = 4000
MAX_PIPELINE_STAGES = 10

_QUOTED_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_INDEX_RE = re.compile(r'\bindex\s*(!=|=)\s*"?([^\s")|,]+)', re.I)
_INDEX_IN_RE = re.compile(r"\bindex\s+in\b", re.I)
_TIME_MODIFIER_RE = re.compile(r"\b(?:earliest|latest|_index_earliest|_index_latest)\s*=", re.I)
_SEARCH_PREFIX_RE = re.compile(r"(?is)^search(?:\s+(.*))?$")
_COMMAND_RE = re.compile(r"^([A-Za-z_]+)(?=\s|$)")
_REL_TIME_RE = re.compile(r"^-(\d+)(s|m|h|d|w)$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class SPLRejected(ValueError):
    """The query or time range is not allowed. The message is safe to return to the caller."""


def _split_pipeline(query: str) -> list[str]:
    """Split on `|` outside double quotes; reject subsearch brackets and macro backticks outside quotes."""
    segments: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    for ch in query:
        if in_quote:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
            continue
        if ch == '"':
            in_quote = True
            current.append(ch)
        elif ch in "[]`":
            raise SPLRejected("Subsearches and macros are not allowed")
        elif ch == "|":
            segments.append("".join(current))
            current = []
        else:
            current.append(ch)
    if in_quote:
        raise SPLRejected("Unterminated quote in query")
    segments.append("".join(current))
    return segments


def validate_search(query: str, *, allowed_indexes: Iterable[str], default_index: str) -> str:
    text = (query or "").strip()
    if not text:
        raise SPLRejected("Query must not be empty")
    if len(text) > MAX_QUERY_CHARS:
        raise SPLRejected(f"Query is longer than {MAX_QUERY_CHARS} characters")

    segments = _split_pipeline(text)
    if len(segments) > MAX_PIPELINE_STAGES:
        raise SPLRejected(f"Query has more than {MAX_PIPELINE_STAGES} pipeline stages")

    first = segments[0].strip()
    if not first:
        raise SPLRejected("Query must start with a search expression, not a command")
    prefix = _SEARCH_PREFIX_RE.match(first)
    body = (prefix.group(1) or "") if prefix else first

    for stage in segments[1:]:
        match = _COMMAND_RE.match(stage.strip())
        if not match:
            raise SPLRejected("Empty or malformed pipeline stage")
        if match.group(1).lower() not in ALLOWED_COMMANDS:
            raise SPLRejected(f"Command '{match.group(1).lower()}' is not allowed")

    allowed = {i.lower() for i in allowed_indexes}
    for part in [body, *segments[1:]]:
        if _TIME_MODIFIER_RE.search(_QUOTED_RE.sub('""', part)):
            raise SPLRejected("Inline earliest/latest modifiers are not allowed; use the time range fields")
        if _INDEX_IN_RE.search(part):
            raise SPLRejected("index IN (...) is not allowed")
        for operator, value in _INDEX_RE.findall(part):
            if operator == "!=":
                raise SPLRejected("index!= is not allowed")
            if value.lower() not in allowed:
                raise SPLRejected(f"Index '{value}' is not allowed")

    if not _INDEX_RE.search(body):
        body = f"index={default_index} {body}".strip()
    return " | ".join(["search " + body.strip(), *[s.strip() for s in segments[1:]]])


def _seconds(value: str, allow_now: bool) -> int:
    v = (value or "").strip()
    if allow_now and v == "now":
        return 0
    match = _REL_TIME_RE.match(v)
    if not match:
        raise SPLRejected(f"Unsupported time value '{v}'; use relative values such as -15m, -24h or -7d")
    return int(match.group(1)) * _UNIT_SECONDS[match.group(2)]


def validate_time_range(earliest: str, latest: str, max_days: int) -> None:
    start = _seconds(earliest, allow_now=False)
    end = _seconds(latest, allow_now=True)
    if start > max_days * 86400:
        raise SPLRejected(f"Time range exceeds {max_days} days")
    if start <= end:
        raise SPLRejected("earliest_time must be before latest_time")
```

- [ ] **Step 4: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_spl_guard.py -q`
Expected: PASS. If a parametrized case fails, fix the guard (never weaken the test) and report which case.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/spl_guard.py backend/tests/test_spl_guard.py
git commit -m "feat(security): allowlist SPL guard and time range validation"
```

---

### Task 6: Search endpoint (role gate, guard, tenant-scoped fallback, audit) and frontend path

**Files:**
- Modify: `backend/app/api/v1/endpoints/search.py`, `frontend/src/app/search/page.tsx`
- Create: `backend/tests/test_search_endpoint.py`

**Interfaces:**
- Consumes: `validate_search`, `validate_time_range`, `SPLRejected` (Task 5); settings `SPLUNK_ALLOWED_INDEXES`, `SPLUNK_DETECTION_INDEX`, `SEARCH_MAX_RANGE_DAYS`; `record_audit` (Task 3); `scoped_query`, `require_roles`, `get_current_user`.
- Produces: `POST /api/v1/search` — 400 with a safe message when the guard rejects; 403 for roles outside the three allowed; the SIEM receives the rebuilt query; the Mongo fallback only returns the caller's tenant.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_search_endpoint.py`:

```python
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user, get_siem_client
from app.api.v1.endpoints import search as search_module
from app.database.session import get_db


class FakeSiem:
    def __init__(self, fail=False):
        self.queries, self.fail = [], fail

    async def search(self, query, earliest_time, latest_time, limit):
        if self.fail:
            raise RuntimeError("splunk down")
        self.queries.append((query, earliest_time, latest_time, limit))
        return []


@pytest.fixture
def db():
    return AsyncMongoMockClient()["search_test"]


def make_app(db, siem, user):
    app = FastAPI()
    app.include_router(search_module.router, prefix="/search")

    async def _db():
        return db

    async def _siem():
        yield siem

    async def _user():
        return user

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_siem_client] = _siem
    app.dependency_overrides[get_current_user] = _user
    return app


async def post(app, **body):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.post("/search", json=body)


ANALYST = {"id": "u1", "email": "a@b.test", "role": "soc_analyst", "org_id": "default"}


@pytest.mark.asyncio
async def test_valid_query_reaches_siem_rewritten_with_index(db):
    siem = FakeSiem()
    resp = await post(make_app(db, siem, ANALYST), query="EventCode=4625 | head 5", earliest_time="-1h")
    assert resp.status_code == 200
    assert siem.queries[0][0] == "search index=windows EventCode=4625 | head 5"


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["index=* | delete", "EventCode=1 | outputlookup x", "| rest /services/x"])
async def test_dangerous_queries_are_rejected_before_reaching_siem(db, query):
    siem = FakeSiem()
    resp = await post(make_app(db, siem, ANALYST), query=query)
    assert resp.status_code == 400 and siem.queries == []
    assert "Traceback" not in resp.text


@pytest.mark.asyncio
async def test_time_range_over_limit_is_rejected(db):
    siem = FakeSiem()
    resp = await post(make_app(db, siem, ANALYST), query="EventCode=1", earliest_time="-90d")
    assert resp.status_code == 400 and siem.queries == []


@pytest.mark.asyncio
async def test_unknown_role_is_forbidden(db):
    resp = await post(make_app(db, FakeSiem(), {**ANALYST, "role": "guest"}), query="EventCode=1")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_search_is_audited(db):
    await post(make_app(db, FakeSiem(), ANALYST), query="EventCode=1")
    entry = await db["audit_logs"].find_one({"action": "search.execute"})
    assert entry["actor_id"] == "u1" and "EventCode=1" in entry["metadata"]["query"]


@pytest.mark.asyncio
async def test_mongo_fallback_is_tenant_scoped(db):
    base = {"severity": "high", "host": "h", "user": "u", "status": "New", "title": "powershell alert"}
    await db["alerts"].insert_many([
        {"_id": "a", "org_id": "acme", **base},
        {"_id": "b", "org_id": "other", **base},
    ])
    resp = await post(make_app(db, FakeSiem(fail=True), {**ANALYST, "org_id": "acme"}), query="powershell")
    assert resp.status_code == 200
    ids = {e["raw_payload"]["_id"] for e in resp.json()["events"]}
    assert ids == {"a"}
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_search_endpoint.py -q`
Expected: FAIL (role gate and guard missing; fallback unscoped).

- [ ] **Step 3: Implement**

In `backend/app/api/v1/endpoints/search.py`:

1. Update imports: `from app.api.deps import get_siem_client, get_db, require_roles`, add `from app.core.config import settings`, `from app.core.tenancy import scoped_query`, `from app.services.audit import record_audit`, `from app.services.spl_guard import SPLRejected, validate_search, validate_time_range`.
2. Replace the `execute_search` signature and the start of its body (everything from `@router.post("", ...)` through the `try: events = await siem.search(...)` call and its `return`) with:

```python
@router.post("", response_model=SearchResponse)
@router.post("/", response_model=SearchResponse)
async def execute_search(
    req: SearchRequest,
    siem: SIEMProvider = Depends(get_siem_client),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(require_roles("admin", "soc_manager", "soc_analyst")),
):
    """
    Executes a guarded search against the configured SIEM and returns normalized events.
    If Splunk is unavailable, falls back to searching the caller's tenant data in MongoDB.
    """
    try:
        validate_time_range(req.earliest_time, req.latest_time, settings.SEARCH_MAX_RANGE_DAYS)
        safe_query = validate_search(
            req.query,
            allowed_indexes=settings.SPLUNK_ALLOWED_INDEXES,
            default_index=settings.SPLUNK_DETECTION_INDEX,
        )
    except SPLRejected as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    try:
        await record_audit(db, user, "search.execute", "search", "splunk", {"query": safe_query[:500]})
    except Exception as exc:  # auditing must not make search unavailable, but must be visible in logs
        logger.error("search_audit_failed", error=str(exc))

    try:
        events = await siem.search(
            query=safe_query,
            earliest_time=req.earliest_time,
            latest_time=req.latest_time,
            limit=req.limit,
        )
        return SearchResponse(count=len(events), query=req.query, events=events)
    except Exception as e:
```

   (keep the existing `logger.warning("siem_search_fallback_to_mongodb", ...)` line and everything after it).
3. In the fallback, replace `cursor = db["alerts"].find(mongo_query).limit(req.limit)` with `cursor = db["alerts"].find(scoped_query(user, mongo_query) if mongo_query else scoped_query(user)).limit(req.limit)`.

In `frontend/src/app/search/page.tsx`: change `apiFetch('/api/v1/search/search', {` to `apiFetch('/api/v1/search', {`; change every preset query and the default `useState('search index=sysmon | head 50')` / placeholder so they use `index=windows` and never `index=*` (for example `'search index=windows EventCode=4625'`, `'search index=windows EventCode=1 | head 50'`, `'search index=windows EventCode=3 | head 50'`, `'search index=windows | head 50'`; delete the duplicate presets that only differed by `index=*`/`index=main`/`index=sysmon`, keeping labels meaningful). Keep the time-range options (`-15m`, `-1h`, `-24h`, `-7d` are all valid).

- [ ] **Step 4: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_search_endpoint.py tests/test_route_protection.py -q` then the full suite, then `cd ../frontend && npx tsc --noEmit` (expect no output).
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/v1/endpoints/search.py backend/tests/test_search_endpoint.py frontend/src/app/search/page.tsx
git commit -m "feat(security): guarded, role-gated, audited search with tenant-scoped fallback; fix frontend path"
```

---

### Task 7: Alerts tenant scoping and input validation

**Files:**
- Modify: `backend/app/api/v1/endpoints/alerts.py`
- Create: `backend/tests/test_alerts_hardening.py`

**Interfaces:**
- Produces: `GET /alerts/` — `limit` 1..200 (422 outside), `search` max 100 chars and regex-escaped, `severity` in `{critical, high, medium, low, all}` (case-insensitive), `status` in `{New, Investigating, Investigated, Investigation Failed, Closed, Escalated, Suppressed, all}` (case-insensitive, 422 otherwise); `GET /alerts/stats/by-rule`, `GET /alerts/stats/timeline` and `GET /alerts/investigation/{job_id}` take the authenticated user and are tenant scoped (404 for another tenant's job).

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_alerts_hardening.py`:

```python
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import alerts as alerts_module
from app.database.session import get_db


@pytest.fixture
def db():
    return AsyncMongoMockClient()["alerts_hardening"]


def make_app(db, org="acme"):
    app = FastAPI()
    app.include_router(alerts_module.router, prefix="/alerts")

    async def _db():
        return db

    async def _user():
        return {"id": "u1", "email": "a@b.test", "role": "soc_analyst", "org_id": org}

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    return app


async def get(app, path):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.get(path)


NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def alert(i, org, **kw):
    return {"_id": f"a{i}", "org_id": org, "title": f"alert {i}", "severity": "high", "host": "h", "user": "u",
            "status": "New", "created_at": NOW, "rule_name": "r1", **kw}


@pytest.mark.asyncio
async def test_regex_metacharacters_in_search_are_literal(db):
    await db["alerts"].insert_many([alert(1, "acme"), alert(2, "acme")])
    resp = await get(make_app(db), "/alerts/?search=.*")
    assert resp.status_code == 200 and resp.json() == []
    resp = await get(make_app(db), "/alerts/?search=alert 1")
    assert [a["_id"] for a in resp.json()] == ["a1"]


@pytest.mark.asyncio
@pytest.mark.parametrize("qs", ["limit=0", "limit=201", "limit=-5", "severity=catastrophic", "status=Hacked", f"search={'x' * 101}"])
async def test_invalid_list_parameters_are_rejected(db, qs):
    assert (await get(make_app(db), f"/alerts/?{qs}")).status_code == 422


@pytest.mark.asyncio
async def test_valid_filters_still_work_case_insensitively(db):
    await db["alerts"].insert_many([alert(1, "acme", severity="critical", status="Investigated"), alert(2, "acme")])
    resp = await get(make_app(db), "/alerts/?severity=CRITICAL&status=investigated&limit=200")
    assert [a["_id"] for a in resp.json()] == ["a1"]
    assert len((await get(make_app(db), "/alerts/?severity=all&status=all")).json()) == 2


@pytest.mark.asyncio
async def test_investigation_status_is_tenant_scoped(db):
    await db["investigation_jobs"].insert_many([
        {"_id": "mine", "alert_id": "a1", "org_id": "acme", "status": "complete"},
        {"_id": "theirs", "alert_id": "a9", "org_id": "other", "status": "complete"},
    ])
    app = make_app(db, "acme")
    assert (await get(app, "/alerts/investigation/mine")).status_code == 200
    assert (await get(app, "/alerts/investigation/theirs")).status_code == 404


@pytest.mark.asyncio
async def test_stats_endpoints_only_count_the_callers_tenant(db):
    await db["alerts"].insert_many([alert(1, "acme"), alert(2, "acme"), alert(3, "other"), alert(4, "other"), alert(5, "other")])
    by_rule = (await get(make_app(db, "acme"), "/alerts/stats/by-rule")).json()
    assert by_rule == [{"rule_name": "r1", "count": 2}]
    timeline = (await get(make_app(db, "acme"), "/alerts/stats/timeline")).json()
    assert sum(t["count"] for t in timeline) == 2
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_alerts_hardening.py -q`
Expected: FAIL (unscoped stats/job status, unescaped regex, no parameter validation).

- [ ] **Step 3: Implement**

In `backend/app/api/v1/endpoints/alerts.py`:

1. Add `import re` to the imports and, below the `NoteRequest` class, add:

```python
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_STATUSES = {
    s.lower(): s
    for s in ("New", "Investigating", "Investigated", "Investigation Failed", "Closed", "Escalated", "Suppressed")
}
```

2. Replace the `list_alerts` signature and filter-building block (from `async def list_alerts(` through the `if search:` block) with:

```python
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: str = Query(None, description="Filter by severity"),
    status: str = Query(None, description="Filter by status"),
    search: str = Query(None, max_length=100, description="Search in title or host"),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Fetches recent alerts from MongoDB with optional filtering."""
    conditions = []
    if severity and severity.lower() != "all":
        if severity.lower() not in VALID_SEVERITIES:
            raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(VALID_SEVERITIES)} or 'all'")
        conditions.append({"severity": severity.lower()})
    if status and status.lower() != "all":
        canonical = VALID_STATUSES.get(status.lower())
        if canonical is None:
            raise HTTPException(status_code=422, detail=f"status must be one of {sorted(VALID_STATUSES.values())} or 'all'")
        conditions.append({"status": canonical})
    if search:
        pattern = re.escape(search)
        conditions.append({"$or": [
            {"title": {"$regex": pattern, "$options": "i"}},
            {"host": {"$regex": pattern, "$options": "i"}},
        ]})
    try:
```

   and keep the rest of the existing `try:` body (the cursor loop and `except Exception as e: raise internal_error(...)` from Task 1) unchanged, removing the old `try:` / `conditions = []` lines that this replacement now covers.

3. `alerts_by_rule`: change the signature to `async def alerts_by_rule(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):` and the first pipeline stage to `{"$match": {"$and": [tenant_filter(user), {"rule_name": {"$exists": True, "$ne": None}}]}}`.
4. `alerts_timeline`: add the same `user` dependency and change its first stage to `{"$match": {"$and": [tenant_filter(user), {"created_at": {"$gte": twenty_four_hours_ago}}]}}`.
5. `get_investigation_status`: add `user: dict = Depends(get_current_user)` and change the lookup to `await db["investigation_jobs"].find_one(scoped_query(user, {"_id": job_id}))`.

- [ ] **Step 4: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_alerts_hardening.py tests/test_error_handling.py -q` then the full suite.
Expected: PASS. If the frontend's `status=New` call or other existing tests use a value outside the allowlist, report it instead of widening silently.

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/v1/endpoints/alerts.py backend/tests/test_alerts_hardening.py
git commit -m "fix(security): tenant-scope stats and job status; validate alert list parameters"
```

---

### Task 8: Untrack dumps and pseudonymize fixtures

**Files:**
- Modify: `backend/scripts/export_fixture_rows.py`, `backend/tests/fixtures/splunk_rows.json` (regenerated), `.gitignore`, `README.md`
- Create: `backend/tests/test_repo_hygiene.py`

**Interfaces:**
- Produces: `scripts/export_fixture_rows.py` applies `pseudonymize(text: str) -> str` to the fixture JSON before writing it; `backend/mongo_dump_json/` is not tracked by git (files remain on disk).

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_repo_hygiene.py`:

```python
import re
import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "splunk_rows.json"
ROOT = Path(__file__).resolve().parents[2]


def test_fixture_contains_no_personal_identifiers():
    text = FIXTURE.read_text(encoding="utf-8")
    assert not re.search(r"ayush", text, re.I)
    assert "@gmail.com" not in text
    assert not re.search(r"S-1-5-21-4283746528", text)
    assert "10.143.71.72" not in text


def test_pseudonymize_is_stable_and_case_preserving():
    import importlib.util
    spec = importlib.util.spec_from_file_location("export_fixture_rows", Path(__file__).parents[1] / "scripts" / "export_fixture_rows.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = mod.pseudonymize("AYUSH Ayush ayush ayushkumbhar1111@gmail.com S-1-5-21-4283746528-2832981674-120407787-1001 10.143.71.72 10.0.22621.3085")
    assert "LABUSER" in out and "Labuser" in out and "labuser" in out
    assert "analyst@example.test" in out
    assert "S-1-5-21-1000000000-2000000000-3000000000-1001" in out
    assert "10.0.0.5" in out
    assert "10.0.22621.3085" in out  # OS build numbers are not IP addresses


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_database_dumps_are_not_tracked():
    tracked = subprocess.run(["git", "ls-files", "backend/mongo_dump_json"], cwd=ROOT, capture_output=True, text=True).stdout
    assert tracked.strip() == ""
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_repo_hygiene.py -q`
Expected: FAIL (identifiers present, `pseudonymize` missing, dumps tracked).

- [ ] **Step 3: Add pseudonymization to the export script**

In `backend/scripts/export_fixture_rows.py` add `import re` and, above `main`, add:

```python
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SID_RE = re.compile(r"S-1-5-21-4283746528-2832981674-120407787")
_NAME_RE = re.compile(r"ayush[a-z0-9]*", re.I)


def _case_like(match: "re.Match[str]") -> str:
    word = match.group(0)
    if word.isupper():
        return "LABUSER"
    if word[0].isupper():
        return "Labuser"
    return "labuser"


def pseudonymize(text: str) -> str:
    """Replace personal identifiers from the lab machine with neutral stand-ins (applied before fixtures are written)."""
    text = _EMAIL_RE.sub("analyst@example.test", text)
    text = _SID_RE.sub("S-1-5-21-1000000000-2000000000-3000000000", text)
    text = text.replace("10.143.71.72", "10.0.0.5")
    return _NAME_RE.sub(_case_like, text)
```

and change the final write in `main` to `OUT.write_text(pseudonymize(json.dumps(rows, indent=2, ensure_ascii=False)), encoding="utf-8")`. Update the module docstring with one sentence: "Personal identifiers are pseudonymized; the source dump stays local and untracked."

- [ ] **Step 4: Untrack the dumps and regenerate the fixtures**

```bash
cd backend && ./venv/Scripts/python.exe scripts/export_fixture_rows.py
cd .. && printf '\n# Local database dumps (contain credentials hashes and real telemetry) - never commit\nbackend/mongo_dump_json/\n' >> .gitignore
git rm -r -q --cached backend/mongo_dump_json
git status --short | head
```

Expected: the five dump files show as `D` (index only, files remain on disk), `.gitignore` and the fixture show as modified.

- [ ] **Step 5: Update the README**

In the root `README.md` "Sharing Data with Team Members" section add: "`backend/mongo_dump_json/` is git-ignored and must never be committed (it contains password hashes and real telemetry); share it only as a zip over a private channel." In the "Regenerating test fixtures" line add "(requires a local `mongo_dump_json`; produced by `scripts/export_db.py`; identifiers are pseudonymized automatically)".

- [ ] **Step 6: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_repo_hygiene.py -q` then the full suite.
Expected: PASS. If a fixture-based test fails because a literal changed (for example an assertion containing the old username), update only that literal to the pseudonymized value and report it; do not weaken assertions.

- [ ] **Step 7: Commit**

```bash
git add .gitignore README.md backend/scripts/export_fixture_rows.py backend/tests/fixtures/splunk_rows.json backend/tests/test_repo_hygiene.py
git commit -m "chore(security): untrack database dumps; pseudonymize test fixtures"
```

(`git rm --cached` already staged the dump removals; they are included in this commit.)
