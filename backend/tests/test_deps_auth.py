"""Tests for the get_current_user / require_roles dependencies."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient, ASGITransport
from jose import jwt as jose_jwt
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user, require_roles
from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token, hash_password


def _make_expired_access_token(user_id: str, email: str, role: str) -> str:
    """Test-local helper: builds an access token with `exp` in the past.

    `create_access_token` intentionally has no custom-expiry parameter (Task 5
    depends on its documented signature), so we mint the expired token
    directly with jose, signed the same way decode_token expects.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "type": "access",
        "iat": now - timedelta(minutes=10),
        "exp": now - timedelta(minutes=5),
    }
    return jose_jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


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


@pytest.mark.asyncio
async def test_get_current_user_rejects_refresh_token(auth_test_app, mock_db):
    """A well-formed, unexpired *refresh* token must not authenticate a request."""
    await mock_db["users"].insert_one({
        "_id": "user123",
        "email": "a@b.com",
        "password_hash": hash_password("pw"),
        "role": "analyst",
        "is_active": True,
    })
    token, _jti, _expires_at = create_refresh_token(user_id="user123")
    async with AsyncClient(transport=ASGITransport(app=auth_test_app), base_url="http://t") as c:
        resp = await c.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_inactive_user(auth_test_app, mock_db):
    await mock_db["users"].insert_one({
        "_id": "user123",
        "email": "a@b.com",
        "password_hash": hash_password("pw"),
        "role": "analyst",
        "is_active": False,
    })
    token = create_access_token(user_id="user123", email="a@b.com", role="analyst")
    async with AsyncClient(transport=ASGITransport(app=auth_test_app), base_url="http://t") as c:
        resp = await c.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_unknown_user(auth_test_app, mock_db):
    """Token is validly signed and unexpired, but `sub` matches no user document."""
    token = create_access_token(user_id="ghost-user", email="ghost@b.com", role="analyst")
    async with AsyncClient(transport=ASGITransport(app=auth_test_app), base_url="http://t") as c:
        resp = await c.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_expired_token(auth_test_app, mock_db):
    """Token parses and verifies structurally, but `exp` is in the past."""
    await mock_db["users"].insert_one({
        "_id": "user123",
        "email": "a@b.com",
        "password_hash": hash_password("pw"),
        "role": "analyst",
        "is_active": True,
    })
    token = _make_expired_access_token(user_id="user123", email="a@b.com", role="analyst")
    async with AsyncClient(transport=ASGITransport(app=auth_test_app), base_url="http://t") as c:
        resp = await c.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
