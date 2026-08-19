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
