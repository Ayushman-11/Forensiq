"""
Tests for split liveness / readiness health endpoints (1.7).

Also verifies the legacy /api/v1/health route still responds so
backwards-compatible callers are not broken.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    """Root landing page is alive and lists /metrics."""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["platform"] == "Forensiq Security Operations Platform"
    assert data["status"] == "operational"
    assert "metrics" in data  # new field added in 1.7


@pytest.mark.asyncio
async def test_liveness_probe_always_200(client: AsyncClient):
    """
    Liveness probe must return 200 even with no real MongoDB available.
    It is intentionally dependency-free so a slow DB does not cause pod restarts.
    """
    response = await client.get("/api/v1/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"
    assert "uptime_seconds" in data
    assert isinstance(data["uptime_seconds"], float)


@pytest.mark.asyncio
async def test_readiness_probe_structure(client: AsyncClient):
    """
    Readiness probe returns a JSON body with a 'mongo' key.
    The exact status code depends on whether mongomock responds to ping,
    but the structure must always be present.
    """
    response = await client.get("/api/v1/health/ready")
    # mongomock may not support the ping command – accept 200 or 503
    assert response.status_code in (200, 503)
    data = response.json()
    assert "status" in data
    assert "mongo" in data
    assert data["status"] in ("ready", "not_ready")


@pytest.mark.asyncio
async def test_readiness_probe_no_siem_key(client: AsyncClient):
    """
    Readiness probe must NOT contain 'siem_connected' –
    SIEM state belongs on the dashboard, not in the readiness probe.
    """
    response = await client.get("/api/v1/health/ready")
    data = response.json()
    assert "siem_connected" not in data


@pytest.mark.asyncio
async def test_legacy_health_route_still_works(client: AsyncClient):
    """
    The legacy /api/v1/health endpoint must still respond (backwards compat).
    It should NOT contain 'siem_connected' now that it delegates to readiness.
    """
    response = await client.get("/api/v1/health")
    assert response.status_code in (200, 503)
    data = response.json()
    assert "status" in data
    assert "siem_connected" not in data


@pytest.mark.asyncio
async def test_request_id_header_present(client: AsyncClient):
    """Every response must carry an X-Request-ID header (request-id middleware)."""
    response = await client.get("/api/v1/health/live")
    assert "x-request-id" in response.headers


@pytest.mark.asyncio
async def test_request_id_is_echoed(client: AsyncClient):
    """If a caller sends X-Request-ID, the same value is echoed back."""
    sent_id = "test-req-abc123"
    response = await client.get(
        "/api/v1/health/live",
        headers={"X-Request-ID": sent_id},
    )
    assert response.headers.get("x-request-id") == sent_id
