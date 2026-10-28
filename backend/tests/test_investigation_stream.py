import pytest
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient
from app.main import app
from app.database.session import get_db
from app.core.security import create_access_token


@pytest.fixture
def mock_db():
    client = AsyncMongoMockClient()
    return client["test_forensiq"]


@pytest.mark.asyncio
async def test_investigate_stream_requires_auth(client: AsyncClient):
    resp = await client.post("/api/v1/alerts/any-id/investigate/stream")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_investigate_stream_execution(mock_db):
    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        # Seed an alert
        alert_doc = {
            "_id": "stream-alert-1",
            "title": "Powershell Encoded Command Detected",
            "host": "fin-srv-01",
            "user": "corp\\jdoe",
            "severity": "high",
            "status": "New",
            "created_at": datetime.now(timezone.utc),
            "raw_logs": "powershell -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
            "src_ip": "45.33.32.1",
        }
        await mock_db["alerts"].insert_one(alert_doc)

        # Seed user
        await mock_db["users"].insert_one({
            "_id": "user-1",
            "email": "analyst@test.com",
            "role": "analyst",
            "is_active": True,
            "org_id": "default",
        })

        token = create_access_token("user-1", "analyst@test.com", "analyst")
        headers = {"Authorization": f"Bearer {token}"}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            async with ac.stream("POST", "/api/v1/alerts/stream-alert-1/investigate/stream", headers=headers) as response:
                assert response.status_code == 200
                assert "text/event-stream" in response.headers.get("content-type", "")

                received_events = []
                async for line in response.aiter_lines():
                    if line.startswith("event:"):
                        received_events.append(line.split("event:")[1].strip())

        assert "init" in received_events
        assert "node_complete" in received_events
        assert "complete" in received_events

        # Verify DB alert updated
        updated_alert = await mock_db["alerts"].find_one({"_id": "stream-alert-1"})
        assert updated_alert["status"] == "Investigated"
        assert "risk_score" in updated_alert
        assert "timeline" in updated_alert
        assert "recommendation" in updated_alert

    finally:
        app.dependency_overrides.clear()
