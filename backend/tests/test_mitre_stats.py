import pytest
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.core.security import create_access_token
from app.database.session import get_db
from app.main import app


@pytest.fixture
def mock_db():
    client = AsyncMongoMockClient()
    return client["test_forensiq"]


@pytest.mark.asyncio
async def test_get_mitre_stats_unauthorized(client: AsyncClient):
    res = await client.get("/api/v1/alerts/stats/mitre")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_get_mitre_stats_authorized(mock_db):
    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        await mock_db["users"].insert_one({
            "_id": "user-mitre-1",
            "email": "analyst@test.com",
            "role": "analyst",
            "is_active": True,
            "org_id": "default",
        })
        await mock_db["alerts"].insert_one({
            "_id": "alert-mitre-1",
            "title": "Suspicious PowerShell Execution",
            "severity": "critical",
            "tenant_id": "default",
            "mitre_technique": "T1059.001",
            "mitre_tactic": "Execution",
            "mitre_mappings": [
                {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell"}
            ]
        })

        token = create_access_token("user-mitre-1", "analyst@test.com", "analyst")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/api/v1/alerts/stats/mitre", headers={"Authorization": f"Bearer {token}"})
            assert res.status_code == 200
            data = res.json()
            assert "techniques" in data
            assert "tactics_summary" in data
            assert "total_mapped_alerts" in data
            assert isinstance(data["techniques"], list)
            assert len(data["techniques"]) == 1
            assert data["techniques"][0]["id"] == "T1059.001"
            assert data["techniques"][0]["count"] == 1
    finally:
        app.dependency_overrides.pop(get_db, None)
