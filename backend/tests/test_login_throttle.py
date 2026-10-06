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
