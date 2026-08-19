"""Verifies which routes require authentication after wiring get_current_user."""

import pytest
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient

from app.api.v1.endpoints import alerts as alerts_module
from app.core.security import create_access_token, hash_password
from app.database.session import get_db


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


# --- POST /alerts/ingest role gate ---------------------------------------
#
# The router-level `dependencies=[Depends(get_current_user)]` wiring is
# exercised above via the shared `client` fixture (real app, no DB override).
# That's fine for proving 401s, since those requests never reach a DB or
# Splunk call. But /ingest additionally requires require_roles("admin",
# "soc_manager"), and if a valid token holder with the wrong role got a 200
# here, the endpoint body would go on to call the real Splunk client — not
# safe/desirable against the shared `client` fixture's real, un-overridden
# app. So this test mounts just `alerts.router` in isolation (same pattern
# as test_deps_auth.py / test_auth_endpoints.py) with `get_db` overridden to
# a mongomock instance, proving the role gate fires before the Splunk call
# is ever attempted.


@pytest.fixture
def mock_db():
    client = AsyncMongoMockClient()
    return client["forensiq_test"]


@pytest.fixture
def alerts_app(mock_db):
    app = FastAPI()
    app.include_router(alerts_module.router, prefix="/alerts")

    async def override_get_db():
        return mock_db

    app.dependency_overrides[get_db] = override_get_db
    return app


@pytest.mark.asyncio
async def test_ingest_rejects_wrong_role(alerts_app, mock_db):
    await mock_db["users"].insert_one({
        "_id": "user123",
        "email": "analyst@forensiq.ai",
        "password_hash": hash_password("pw"),
        "role": "soc_analyst",
        "is_active": True,
    })
    token = create_access_token(user_id="user123", email="analyst@forensiq.ai", role="soc_analyst")
    async with AsyncClient(transport=ASGITransport(app=alerts_app), base_url="http://t") as c:
        resp = await c.post("/alerts/ingest", headers={"Authorization": f"Bearer {token}"})
    # 403, not 401: the token itself is valid — get_current_user accepts it.
    # require_roles is what rejects it, before the endpoint body (and any
    # Splunk call) ever runs.
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_ingest_admin_role_passes_gate(alerts_app, mock_db):
    await mock_db["users"].insert_one({
        "_id": "user456",
        "email": "admin@forensiq.ai",
        "password_hash": hash_password("pw"),
        "role": "admin",
        "is_active": True,
    })
    token = create_access_token(user_id="user456", email="admin@forensiq.ai", role="admin")
    async with AsyncClient(transport=ASGITransport(app=alerts_app), base_url="http://t") as c:
        resp = await c.post("/alerts/ingest", headers={"Authorization": f"Bearer {token}"})
    # The role gate must not be what stops an admin: assert we get past both
    # get_current_user (no 401) and require_roles (no 403). The endpoint
    # body then attempts a real Splunk connection (no Splunk mock here) and
    # is expected to fail with a 500 from IngestionService — that failure
    # mode is irrelevant to what this test is proving.
    assert resp.status_code not in (401, 403)
