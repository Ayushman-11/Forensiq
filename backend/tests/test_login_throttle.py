import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.v1.endpoints import auth as auth_module
from app.core.config import settings
from app.core.security import hash_password, verify_password
from app.schemas.auth import LoginRequest
from app.database.session import get_db
from app.services.login_throttle import clear_failures, reserve_attempt, throttle_key


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
async def test_expired_window_resets_on_next_reservation(db):
    key = throttle_key("a@b.test", "1.2.3.4")
    expired = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
    await db["login_attempts"].insert_one({"_id": key, "attempts": 99, "expires_at": expired})
    assert await reserve_attempt(db, key) == 0
    assert (await db["login_attempts"].find_one({"_id": key}))["attempts"] == 1
    await clear_failures(db, key)
    assert await db["login_attempts"].find_one({"_id": key}) is None


def test_throttle_key_differs_by_ip():
    assert throttle_key("a@b.test", "1.1.1.1") != throttle_key("a@b.test", "2.2.2.2")
    assert throttle_key("A@B.test ", "1.1.1.1") == throttle_key("a@b.test", "1.1.1.1")


def test_72_byte_ascii_password_passes_validation():
    LoginRequest(email="a@forensiq.ai", password="x" * 72)


class _YColl:
    def __init__(self, c):
        self._c = c

    def __getattr__(self, name):
        attr = getattr(self._c, name)
        if name in ("find_one", "find_one_and_update", "update_one", "delete_one", "insert_one"):
            async def wrapped(*a, **kw):
                await asyncio.sleep(0.001)
                return await attr(*a, **kw)
            return wrapped
        return attr


class _YDB:
    def __init__(self, d):
        self._d = d

    def __getitem__(self, k):
        return _YColl(self._d[k])


@pytest.mark.asyncio
async def test_concurrent_burst_cannot_exceed_the_failure_budget(db, user):
    app = FastAPI()
    app.include_router(auth_module.router, prefix="/auth")

    async def override_get_db():
        return _YDB(db)

    app.dependency_overrides[get_db] = override_get_db
    pws = ["wrong%d" % i for i in range(19)] + ["s3cret-pw"]
    with patch.object(auth_module, "verify_password", wraps=verify_password) as spy:
        rs = await asyncio.gather(*[_login(app, "analyst@forensiq.ai", p) for p in pws])
    codes = [r.status_code for r in rs]
    assert spy.call_count <= settings.LOGIN_MAX_FAILURES
    assert codes.count(429) >= 20 - settings.LOGIN_MAX_FAILURES
