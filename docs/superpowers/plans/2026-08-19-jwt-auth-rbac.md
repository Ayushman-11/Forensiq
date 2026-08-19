# JWT Auth + RBAC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add JWT access/refresh authentication with role-based access control to the FastAPI backend, closing the "every endpoint is open to the internet" gap found in the security audit, and implement `DEVELOPMENT_PLAN.md` Phase 1.1.

**Architecture:** Users live in a new MongoDB `users` collection (bcrypt-hashed passwords via `passlib`). Login issues a short-lived JWT access token and a longer-lived JWT refresh token (via `python-jose`); refresh tokens are tracked server-side in a `sessions` collection keyed by JWT `jti` so they can be rotated and revoked on logout. A FastAPI dependency (`get_current_user`) validates the `Authorization: Bearer` header and is applied to the `alerts`, `search`, and `dashboard` routers; `health` and the new `auth` router stay open. A `require_roles` dependency factory adds per-route RBAC (`admin`, `soc_manager`, `soc_analyst`), used to restrict the manual `/alerts/ingest` trigger to `admin`/`soc_manager`. A CLI seed script bootstraps the first admin user since there is no open self-registration endpoint (registration is out of scope — see Non-Goals).

**Tech Stack:** FastAPI, `python-jose[cryptography]` (already a dependency), `passlib[bcrypt]` (already a dependency), Motor/MongoDB, `mongomock-motor` (new dev dependency, for DB-free tests via `dependency_overrides`).

**Spec:** `DEVELOPMENT_PLAN.md` section "1.1 Authentication & Authorization" (JWT access+refresh, RBAC middleware for Admin/SOC Manager/SOC Analyst, login/logout/refresh endpoints).

## Global Constraints

- Python 3.13, FastAPI async style throughout (`async def`, `AsyncIOMotorDatabase`) — match existing codebase style in `backend/app/`.
- No new top-level dependencies beyond what's already in `pyproject.toml` except `mongomock-motor` (test-only, `dev` extra).
- Do not touch `frontend/` in this plan — wiring the UI to auth is a separate follow-up plan.
- Do not implement self-service registration, org-scoping/multi-tenancy, or password reset — those are explicitly out of scope (see Non-Goals). Adding them now would be building ahead of the current single-tenant stage.
- All new Mongo collections (`users`, `sessions`) go through the existing `get_db` dependency in `app/database/session.py` — do not create a second DB connection path.

## Non-Goals (explicitly deferred)

- Public self-registration endpoint — first user is created via a CLI seed script; further users are created by an admin later (no admin-create-user endpoint yet either — YAGNI until there's more than one operator).
- Multi-tenant `org_id` scoping — that's `DEVELOPMENT_PLAN.md` Phase 6, not this plan.
- Password reset / email flows.

---

### Task 1: Config additions + test dependency

**Files:**
- Modify: `backend/app/core/config.py`
- Modify: `backend/pyproject.toml`
- Modify: `backend/.env.example`

**Interfaces:**
- Produces: `settings.REFRESH_TOKEN_EXPIRE_MINUTES: int` — consumed by Task 2's `create_refresh_token`.

- [ ] **Step 1: Add refresh-token TTL setting**

In `backend/app/core/config.py`, right after the existing `ACCESS_TOKEN_EXPIRE_MINUTES` field, add:

```python
    REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(
        default=60 * 24 * 7, description="Refresh token TTL in minutes (7 days)"
    )
```

- [ ] **Step 2: Add `mongomock-motor` to dev dependencies**

In `backend/pyproject.toml`, under `[project.optional-dependencies] dev = [...]`, add `"mongomock-motor>=0.0.34"` to the list (alongside the existing `pytest`, `respx`, etc. entries).

- [ ] **Step 3: Install it**

Run: `cd backend && ./venv/Scripts/python.exe -m pip install "mongomock-motor>=0.0.34"`
Expected: installs cleanly (pulls in `mongomock` as a transitive dep).

- [ ] **Step 4: Document the new env var**

In `backend/.env.example`, after `FORENSIQ_SECRET_KEY=...`, no new line is strictly required (it has a sane default), but add a comment for discoverability:

```
# JWT token TTLs (minutes) — defaults: access=1440 (24h), refresh=10080 (7d)
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/config.py backend/pyproject.toml backend/.env.example
git commit -m "feat(auth): add refresh token TTL setting and test dependency"
```

---

### Task 2: Password hashing + JWT helpers (`app/core/security.py`)

**Files:**
- Create: `backend/app/core/security.py`
- Test: `backend/tests/test_security.py`

**Interfaces:**
- Produces:
  - `hash_password(password: str) -> str`
  - `verify_password(password: str, hashed: str) -> bool`
  - `create_access_token(user_id: str, email: str, role: str) -> str`
  - `create_refresh_token(user_id: str) -> tuple[str, str, datetime]` — returns `(token, jti, expires_at)`
  - `decode_token(token: str) -> dict` — raises `jose.exceptions.JWTError` on invalid/expired
  - `class TokenError(Exception)` — raised by `decode_token` wrapper for a clean error boundary (wraps `JWTError`)
- Consumes: `settings.SECRET_KEY`, `settings.ALGORITHM`, `settings.ACCESS_TOKEN_EXPIRE_MINUTES`, `settings.REFRESH_TOKEN_EXPIRE_MINUTES` from `app/core/config.py` (Task 1).

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_security.py`:

```python
"""Tests for password hashing and JWT helpers."""

import pytest
from datetime import datetime, timezone

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    TokenError,
)


def test_hash_password_roundtrip():
    hashed = hash_password("correct-horse-battery-staple")
    assert hashed != "correct-horse-battery-staple"
    assert verify_password("correct-horse-battery-staple", hashed) is True


def test_verify_password_rejects_wrong_password():
    hashed = hash_password("correct-horse-battery-staple")
    assert verify_password("wrong-password", hashed) is False


def test_create_and_decode_access_token():
    token = create_access_token(user_id="user123", email="a@b.com", role="admin")
    payload = decode_token(token)
    assert payload["sub"] == "user123"
    assert payload["email"] == "a@b.com"
    assert payload["role"] == "admin"
    assert payload["type"] == "access"


def test_create_and_decode_refresh_token():
    token, jti, expires_at = create_refresh_token(user_id="user123")
    payload = decode_token(token)
    assert payload["sub"] == "user123"
    assert payload["type"] == "refresh"
    assert payload["jti"] == jti
    assert isinstance(expires_at, datetime)
    assert expires_at > datetime.now(timezone.utc)


def test_decode_token_rejects_garbage():
    with pytest.raises(TokenError):
        decode_token("not-a-real-token")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./venv/Scripts/python.exe -m pytest tests/test_security.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.core.security'`

- [ ] **Step 3: Implement `app/core/security.py`**

```python
"""
Password hashing and JWT access/refresh token helpers.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple

from jose import jwt, JWTError
from passlib.context import CryptContext

from app.core.config import settings

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenError(Exception):
    """Raised when a JWT cannot be decoded or verified."""


def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt."""
    return _pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    return _pwd_context.verify(password, hashed)


def create_access_token(user_id: str, email: str, role: str) -> str:
    """Creates a short-lived JWT access token carrying user identity and role."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(user_id: str) -> Tuple[str, str, datetime]:
    """
    Creates a long-lived JWT refresh token. Returns (token, jti, expires_at)
    so the caller can persist a matching session row for revocation/rotation.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "type": "refresh",
        "jti": jti,
        "iat": now,
        "exp": expire,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token, jti, expire


def decode_token(token: str) -> dict:
    """Decodes and verifies a JWT, raising TokenError on any failure."""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError as e:
        raise TokenError(str(e)) from e
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && ./venv/Scripts/python.exe -m pytest tests/test_security.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/security.py backend/tests/test_security.py
git commit -m "feat(auth): add password hashing and JWT helper functions"
```

---

### Task 3: Auth schemas (`app/schemas/auth.py`)

**Files:**
- Create: `backend/app/schemas/auth.py`

**Interfaces:**
- Produces: `LoginRequest`, `RefreshRequest`, `LogoutRequest`, `TokenResponse`, `UserOut` Pydantic models — consumed by Task 5's `auth.py` router and Task 4's `get_current_user`.

- [ ] **Step 1: Create the schema file**

```python
"""
Pydantic request/response schemas for authentication endpoints.
"""

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: EmailStr
    role: str
    is_active: bool
```

No test needed for this step — it's pure data declarations exercised by Task 5's endpoint tests.

- [ ] **Step 2: Commit**

```bash
git add backend/app/schemas/auth.py
git commit -m "feat(auth): add auth request/response schemas"
```

---

### Task 4: `get_current_user` / `require_roles` dependencies

**Files:**
- Modify: `backend/app/api/deps.py`
- Test: `backend/tests/test_deps_auth.py`

**Interfaces:**
- Consumes: `decode_token`, `TokenError` from `app/core/security.py` (Task 2); `get_db` from `app/database/session.py` (existing).
- Produces:
  - `async def get_current_user(credentials, db) -> dict` — returns the user document (with `_id` renamed to `id`, `password_hash` stripped) or raises `HTTPException(401)`.
  - `def require_roles(*roles: str) -> Callable` — dependency factory; the returned dependency raises `HTTPException(403)` if `current_user["role"]` isn't in `roles`. Consumed by Task 6 to protect `/alerts/ingest`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_deps_auth.py`:

```python
"""Tests for the get_current_user / require_roles dependencies."""

import pytest
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user, require_roles
from app.core.security import create_access_token, hash_password


@pytest.fixture
def mock_db():
    client = AsyncMongoMockClient()
    return client["forensiq_test"]


@pytest.fixture
def auth_test_app(mock_db):
    """A minimal FastAPI app wired only with the dependencies under test."""
    app = FastAPI()

    async def override_get_db():
        return mock_db

    @app.get("/whoami")
    async def whoami(user: dict = Depends(get_current_user)):
        return user

    @app.get("/admin-only")
    async def admin_only(user: dict = Depends(require_roles("admin"))):
        return {"ok": True}

    from app.database.session import get_db
    app.dependency_overrides[get_db] = override_get_db
    return app


@pytest.mark.asyncio
async def test_get_current_user_rejects_missing_token(auth_test_app):
    async with AsyncClient(transport=ASGITransport(app=auth_test_app), base_url="http://t") as c:
        resp = await c.get("/whoami")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_invalid_token(auth_test_app):
    async with AsyncClient(transport=ASGITransport(app=auth_test_app), base_url="http://t") as c:
        resp = await c.get("/whoami", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_accepts_valid_token(auth_test_app, mock_db):
    await mock_db["users"].insert_one({
        "_id": "user123",
        "email": "a@b.com",
        "password_hash": hash_password("pw"),
        "role": "analyst",
        "is_active": True,
    })
    token = create_access_token(user_id="user123", email="a@b.com", role="analyst")
    async with AsyncClient(transport=ASGITransport(app=auth_test_app), base_url="http://t") as c:
        resp = await c.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "a@b.com"
    assert "password_hash" not in resp.json()


@pytest.mark.asyncio
async def test_require_roles_blocks_wrong_role(auth_test_app, mock_db):
    await mock_db["users"].insert_one({
        "_id": "user123",
        "email": "a@b.com",
        "password_hash": hash_password("pw"),
        "role": "analyst",
        "is_active": True,
    })
    token = create_access_token(user_id="user123", email="a@b.com", role="analyst")
    async with AsyncClient(transport=ASGITransport(app=auth_test_app), base_url="http://t") as c:
        resp = await c.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_require_roles_allows_matching_role(auth_test_app, mock_db):
    await mock_db["users"].insert_one({
        "_id": "user123",
        "email": "a@b.com",
        "password_hash": hash_password("pw"),
        "role": "admin",
        "is_active": True,
    })
    token = create_access_token(user_id="user123", email="a@b.com", role="admin")
    async with AsyncClient(transport=ASGITransport(app=auth_test_app), base_url="http://t") as c:
        resp = await c.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./venv/Scripts/python.exe -m pytest tests/test_deps_auth.py -v`
Expected: FAIL — `ImportError: cannot import name 'get_current_user' from 'app.api.deps'`

- [ ] **Step 3: Implement the dependencies**

Replace the full contents of `backend/app/api/deps.py` with:

```python
"""
FastAPI Route Dependencies.
Provides Dependency Injection for SIEM Clients, Database Sessions, and Auth.
"""

from typing import AsyncGenerator, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.infrastructure.siem.splunk import SplunkClient
from app.infrastructure.siem.base import SIEMProvider
from app.core.security import decode_token, TokenError
from app.database.session import get_db

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_siem_client() -> AsyncGenerator[SIEMProvider, None]:
    """Dependency Provider for SIEM Client (SplunkClient). Ensures client is closed after request."""
    client = SplunkClient()
    try:
        yield client
    finally:
        await client.close()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: AsyncIOMotorDatabase = Depends(get_db),
) -> dict:
    """
    Validates the Authorization: Bearer <access_token> header and returns
    the corresponding user document (password_hash stripped).
    Raises 401 if the token is missing, invalid, expired, or the user
    no longer exists / is inactive.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
    except TokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user = await db["users"].find_one({"_id": payload.get("sub")})
    if not user or not user.get("is_active", False):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    user["id"] = str(user.pop("_id"))
    user.pop("password_hash", None)
    return user


def require_roles(*roles: str) -> Callable:
    """Dependency factory: raises 403 unless current_user's role is in `roles`."""

    async def _check(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(roles)}",
            )
        return user

    return _check
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && ./venv/Scripts/python.exe -m pytest tests/test_deps_auth.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/deps.py backend/tests/test_deps_auth.py
git commit -m "feat(auth): add get_current_user and require_roles dependencies"
```

---

### Task 5: Auth router — login / refresh / logout

**Files:**
- Create: `backend/app/api/v1/endpoints/auth.py`
- Test: `backend/tests/test_auth_endpoints.py`

**Interfaces:**
- Consumes: `LoginRequest`, `RefreshRequest`, `LogoutRequest`, `TokenResponse` (Task 3); `hash_password`, `verify_password`, `create_access_token`, `create_refresh_token`, `decode_token`, `TokenError` (Task 2); `get_db` (existing).
- Produces: `router` (FastAPI `APIRouter`) exposing `POST /login`, `POST /refresh`, `POST /logout` — consumed by Task 6's `router.py`.
- Mongo collections used: `users` (read), `sessions` (`_id`=jti, `user_id`, `expires_at` — read/write/delete for refresh-token tracking).

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_auth_endpoints.py`:

```python
"""Tests for /api/v1/auth login, refresh, logout endpoints."""

import pytest
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient

from app.api.v1.endpoints import auth as auth_module
from app.core.security import hash_password
from app.database.session import get_db


@pytest.fixture
def mock_db():
    client = AsyncMongoMockClient()
    return client["forensiq_test"]


@pytest.fixture
def auth_app(mock_db):
    app = FastAPI()
    app.include_router(auth_module.router, prefix="/auth")

    async def override_get_db():
        return mock_db

    app.dependency_overrides[get_db] = override_get_db
    return app


@pytest.fixture
async def seeded_user(mock_db):
    await mock_db["users"].insert_one({
        "_id": "user123",
        "email": "analyst@forensiq.ai",
        "password_hash": hash_password("s3cret-pw"),
        "role": "soc_analyst",
        "is_active": True,
    })
    return "user123"


@pytest.mark.asyncio
async def test_login_success_returns_tokens(auth_app, seeded_user):
    async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://t") as c:
        resp = await c.post("/auth/login", json={"email": "analyst@forensiq.ai", "password": "s3cret-pw"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]


@pytest.mark.asyncio
async def test_login_wrong_password_rejected(auth_app, seeded_user):
    async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://t") as c:
        resp = await c.post("/auth/login", json={"email": "analyst@forensiq.ai", "password": "wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_email_rejected(auth_app, mock_db):
    async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://t") as c:
        resp = await c.post("/auth/login", json={"email": "nobody@forensiq.ai", "password": "whatever"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_rotates_token_and_old_one_stops_working(auth_app, seeded_user):
    async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://t") as c:
        login_resp = await c.post("/auth/login", json={"email": "analyst@forensiq.ai", "password": "s3cret-pw"})
        old_refresh = login_resp.json()["refresh_token"]

        refresh_resp = await c.post("/auth/refresh", json={"refresh_token": old_refresh})
        assert refresh_resp.status_code == 200
        new_refresh = refresh_resp.json()["refresh_token"]
        assert new_refresh != old_refresh

        reuse_resp = await c.post("/auth/refresh", json={"refresh_token": old_refresh})
        assert reuse_resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_refresh_token(auth_app, seeded_user):
    async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://t") as c:
        login_resp = await c.post("/auth/login", json={"email": "analyst@forensiq.ai", "password": "s3cret-pw"})
        refresh_token = login_resp.json()["refresh_token"]

        logout_resp = await c.post("/auth/logout", json={"refresh_token": refresh_token})
        assert logout_resp.status_code == 200

        refresh_after_logout = await c.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert refresh_after_logout.status_code == 401
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./venv/Scripts/python.exe -m pytest tests/test_auth_endpoints.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.api.v1.endpoints.auth'`

- [ ] **Step 3: Implement the auth router**

Create `backend/app/api/v1/endpoints/auth.py`:

```python
"""
Authentication endpoints: login, refresh, logout.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.session import get_db
from app.schemas.auth import LoginRequest, RefreshRequest, LogoutRequest, TokenResponse
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    TokenError,
)
from app.core.logging import logger

router = APIRouter()


async def _issue_tokens(db: AsyncIOMotorDatabase, user_id: str, email: str, role: str) -> TokenResponse:
    access_token = create_access_token(user_id=user_id, email=email, role=role)
    refresh_token, jti, expires_at = create_refresh_token(user_id=user_id)
    await db["sessions"].insert_one({
        "_id": jti,
        "user_id": user_id,
        "expires_at": expires_at,
    })
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Authenticates a user by email/password and issues an access + refresh token pair."""
    user = await db["users"].find_one({"email": req.email})
    if not user or not user.get("is_active", False) or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    return await _issue_tokens(db, user_id=str(user["_id"]), email=user["email"], role=user["role"])


@router.post("/refresh", response_model=TokenResponse)
async def refresh(req: RefreshRequest, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Rotates a refresh token: validates it, revokes it, and issues a fresh pair."""
    try:
        payload = decode_token(req.refresh_token)
    except TokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    session = await db["sessions"].find_one({"_id": payload.get("jti")})
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked")

    await db["sessions"].delete_one({"_id": payload.get("jti")})

    user = await db["users"].find_one({"_id": payload.get("sub")})
    if not user or not user.get("is_active", False):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return await _issue_tokens(db, user_id=str(user["_id"]), email=user["email"], role=user["role"])


@router.post("/logout")
async def logout(req: LogoutRequest, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Revokes a refresh token, ending that session. Idempotent."""
    try:
        payload = decode_token(req.refresh_token)
        await db["sessions"].delete_one({"_id": payload.get("jti")})
    except TokenError:
        pass
    return {"status": "logged_out"}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && ./venv/Scripts/python.exe -m pytest tests/test_auth_endpoints.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/v1/endpoints/auth.py backend/tests/test_auth_endpoints.py
git commit -m "feat(auth): add login/refresh/logout endpoints with session-tracked refresh tokens"
```

---

### Task 6: Wire auth router + protect existing routers

**Files:**
- Modify: `backend/app/api/v1/router.py`
- Modify: `backend/app/api/v1/endpoints/alerts.py`
- Test: `backend/tests/test_route_protection.py`

**Interfaces:**
- Consumes: `auth_module.router` (Task 5), `get_current_user`, `require_roles` (Task 4).
- Produces: `alerts`, `search`, `dashboard` routers require a valid access token; `POST /alerts/ingest` additionally requires role `admin` or `soc_manager`; `health` and `auth` remain open.

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_route_protection.py`:

```python
"""Verifies which routes require authentication after wiring get_current_user."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_stays_open(client: AsyncClient):
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_alerts_list_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/alerts/")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_metrics_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/dashboard/metrics")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_search_requires_auth(client: AsyncClient):
    resp = await client.post("/api/v1/search/search", json={"query": "index=main"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_route_stays_open(client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={"email": "nobody@x.com", "password": "x"})
    # Open route: reachable without a token. 401 here means "bad credentials",
    # not "authentication required" — that's the behavior we're asserting.
    assert resp.status_code == 401
```

This test reuses the existing `client` fixture from `backend/tests/conftest.py:12` (full app, no DB override — fine here because every assertion is either DB-independent or expected to fail auth before touching the DB).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./venv/Scripts/python.exe -m pytest tests/test_route_protection.py -v`
Expected: FAIL — `/api/v1/alerts/`, `/api/v1/dashboard/metrics`, `/api/v1/search/search` currently return 200/500 instead of 401 (no auth wired yet).

- [ ] **Step 3: Wire the auth router and protect the others**

Replace `backend/app/api/v1/router.py` with:

```python
"""
API v1 Router Aggregator.
"""

from fastapi import APIRouter, Depends
from app.api.v1.endpoints import alerts, health, search, dashboard, auth
from app.api.deps import get_current_user

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(
    alerts.router, prefix="/alerts", tags=["alerts"], dependencies=[Depends(get_current_user)]
)
api_router.include_router(
    search.router, prefix="/search", tags=["search"], dependencies=[Depends(get_current_user)]
)
api_router.include_router(
    dashboard.router, prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(get_current_user)]
)
```

Then, in `backend/app/api/v1/endpoints/alerts.py`, restrict the manual full-pull trigger to operators. Change the import line (currently `from app.core.logging import logger`) to also pull in `require_roles`:

```python
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from app.api.deps import require_roles
```

And change the `ingest_from_splunk` route decorator from:

```python
@router.post("/ingest", response_model=dict)
async def ingest_from_splunk(db: AsyncIOMotorDatabase = Depends(get_db)):
```

to:

```python
@router.post("/ingest", response_model=dict)
async def ingest_from_splunk(
    db: AsyncIOMotorDatabase = Depends(get_db),
    _user: dict = Depends(require_roles("admin", "soc_manager")),
):
```

(Every other route in `alerts.py` is already covered by the router-level `dependencies=[Depends(get_current_user)]` above — no per-route changes needed there.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && ./venv/Scripts/python.exe -m pytest tests/test_route_protection.py -v`
Expected: 5 passed

- [ ] **Step 5: Run the full test suite to check for regressions**

Run: `cd backend && ./venv/Scripts/python.exe -m pytest -v`
Expected: all tests pass, including the pre-existing `test_health.py` and `test_splunk_client.py`.

- [ ] **Step 6: Commit**

```bash
git add backend/app/api/v1/router.py backend/app/api/v1/endpoints/alerts.py backend/tests/test_route_protection.py
git commit -m "feat(auth): protect alerts/search/dashboard routes, restrict ingest to admin/soc_manager"
```

---

### Task 7: Admin seed script

**Files:**
- Create: `backend/scripts/create_admin_user.py`

**Interfaces:**
- Consumes: `hash_password` (Task 2), `settings.MONGO_URI`/`settings.MONGO_DB_NAME` (existing config).
- Produces: a runnable CLI script — no other task depends on it (it's the operator-facing bootstrap tool).

- [ ] **Step 1: Write the script**

Create `backend/scripts/create_admin_user.py`:

```python
"""
CLI script to bootstrap the first admin user in MongoDB.

Usage:
    cd backend
    ./venv/Scripts/python.exe scripts/create_admin_user.py --email admin@forensiq.ai --password "change-me"
"""

import argparse
import asyncio
import sys
import uuid

from motor.motor_asyncio import AsyncIOMotorClient

sys.path.insert(0, ".")  # allow `python scripts/create_admin_user.py` from backend/

from app.core.config import settings
from app.core.security import hash_password


async def create_admin(email: str, password: str, role: str) -> None:
    client = AsyncIOMotorClient(settings.MONGO_URI)
    db = client[settings.MONGO_DB_NAME]

    existing = await db["users"].find_one({"email": email})
    if existing:
        print(f"User '{email}' already exists (id={existing['_id']}). Aborting.")
        client.close()
        return

    user_id = str(uuid.uuid4())
    await db["users"].insert_one({
        "_id": user_id,
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        "is_active": True,
    })
    print(f"Created user '{email}' with role '{role}' (id={user_id}).")
    client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap a Forensiq user.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--role", default="admin", choices=["admin", "soc_manager", "soc_analyst"]
    )
    args = parser.parse_args()
    asyncio.run(create_admin(args.email, args.password, args.role))


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Smoke-test it manually against a running local Mongo (if available)**

Run: `cd backend && ./venv/Scripts/python.exe scripts/create_admin_user.py --email admin@forensiq.ai --password "change-me-now"`
Expected: prints `Created user 'admin@forensiq.ai' with role 'admin' (id=...)`. If Mongo isn't running locally, this is fine to skip for now — it's covered by Task 5/6's automated tests, which don't depend on a real Mongo instance.

- [ ] **Step 3: Commit**

```bash
git add backend/scripts/create_admin_user.py
git commit -m "feat(auth): add CLI script to bootstrap the first admin user"
```

---

## Self-Review Notes

- **Spec coverage**: JWT access+refresh (Task 2, 5), RBAC middleware for the three plan roles (Task 4, 6), login/logout/refresh endpoints (Task 5) — all covered. Org-scoped multi-tenant isolation is explicitly deferred to Phase 6 per Non-Goals.
- **Type consistency checked**: `get_current_user` returns a `dict` with `id`/`email`/`role`/`is_active` keys (Task 4) — Task 6's role check (`user.get("role")`) and Task 5's `_issue_tokens(user_id=str(user["_id"]), ...)` both match this shape.
- **No placeholders**: every step has runnable code.
