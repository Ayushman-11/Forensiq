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
