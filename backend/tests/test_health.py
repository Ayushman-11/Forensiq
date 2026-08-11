"""
Tests for Health Check API endpoints.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    """Test landing root route."""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["platform"] == "Forensiq Security Operations Platform"
    assert data["status"] == "operational"


@pytest.mark.asyncio
async def test_health_check_endpoint(client: AsyncClient):
    """Test health check route."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "siem_connected" in data
