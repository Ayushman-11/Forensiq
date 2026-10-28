from datetime import UTC, datetime

import pytest
from mongomock_motor import AsyncMongoMockClient
from starlette.testclient import TestClient

from app.core.config import settings
from app.core.security import create_access_token
from app.database.session import db_config
from app.main import app


@pytest.fixture
def test_setup():
    mock_client = AsyncMongoMockClient()
    mock_db = mock_client[settings.MONGO_DB_NAME]
    old_client = db_config.client
    db_config.client = mock_client
    yield mock_db
    db_config.client = old_client


def test_ws_investigate_unauthorized(test_setup):
    client = TestClient(app)
    # Connecting without a token should receive error event and be closed
    with client.websocket_connect("/api/v1/alerts/some-alert/ws") as ws:
        msg = ws.receive_json()
        assert msg["event"] == "error"
        assert "Authentication failed" in msg["data"]["error"]



@pytest.mark.asyncio
async def test_ws_investigate_streaming_lifecycle(test_setup):
    mock_db = test_setup

    # 1. Seed user
    await mock_db["users"].insert_one({
        "_id": "analyst-ws-1",
        "email": "analyst@forensiq.ai",
        "role": "analyst",
        "is_active": True,
        "org_id": "default",
    })

    # 2. Seed alert
    await mock_db["alerts"].insert_one({
        "_id": "alert-ws-test-1",
        "title": "Suspicious LSASS Memory Dump via ProcDump",
        "host": "dc-srv-01",
        "user": "NT AUTHORITY\\SYSTEM",
        "severity": "high",
        "status": "New",
        "created_at": datetime.now(UTC),
        "raw_logs": "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp",
        "src_ip": "10.0.0.50",
    })

    token = create_access_token("analyst-ws-1", "analyst@forensiq.ai", "analyst")

    client = TestClient(app)
    with client.websocket_connect(f"/api/v1/alerts/alert-ws-test-1/ws?token={token}&auto_start=true") as ws:
        # First message: connected
        connected_msg = ws.receive_json()
        assert connected_msg["event"] == "connected"
        assert connected_msg["data"]["alert_id"] == "alert-ws-test-1"

        # Pipeline init
        init_msg = ws.receive_json()
        assert init_msg["event"] == "init"
        assert init_msg["data"]["status"] == "running"
        assert init_msg["data"]["total_steps"] == 7

        # 7 node completions
        received_nodes = []
        for _ in range(7):
            msg = ws.receive_json()
            assert msg["event"] == "node_complete"
            node_name = msg["data"]["node"]
            received_nodes.append(node_name)
            assert "summary" in msg["data"]
            assert "data" in msg["data"]

        expected_nodes = [
            "extract_context",
            "enrich_iocs",
            "correlate_events",
            "map_mitre",
            "build_timeline",
            "assess_risk",
            "generate_recommendations",
        ]
        assert set(expected_nodes) == set(received_nodes)

        # Complete event
        complete_msg = ws.receive_json()
        assert complete_msg["event"] == "complete"
        assert complete_msg["data"]["status"] == "complete"
        assert "alert" in complete_msg["data"]

        # Ping-Pong test
        ws.send_json({"action": "ping"})
        pong_msg = ws.receive_json()
        assert pong_msg["event"] == "pong"

    # Verify MongoDB state was finalized
    updated_alert = await mock_db["alerts"].find_one({"_id": "alert-ws-test-1"})
    assert updated_alert is not None
    assert updated_alert["status"] == "Investigated"
    assert "risk_score" in updated_alert
    assert "timeline" in updated_alert
    assert "recommendation" in updated_alert


@pytest.mark.asyncio
async def test_ws_investigate_already_investigated(test_setup):
    mock_db = test_setup

    await mock_db["users"].insert_one({
        "_id": "analyst-ws-2",
        "email": "analyst2@forensiq.ai",
        "role": "analyst",
        "is_active": True,
        "org_id": "default",
    })

    await mock_db["alerts"].insert_one({
        "_id": "alert-ws-already-investigated",
        "title": "Known Malicious Cobalt Strike Beacon",
        "host": "ws-srv-02",
        "user": "corp\\analyst",
        "severity": "critical",
        "status": "Investigated",
        "risk_score": 92,
        "ai_confidence": 95,
        "extracted_iocs": ["198.51.100.2"],
        "enrichments": [{"ioc": "198.51.100.2", "reputation": "malicious"}],
        "mitre_mappings": [{"tactic": "Command and Control", "technique": "T1071.001"}],
        "timeline": [{"timestamp": "2026-10-16T12:00:00Z", "phase": "Command and Control"}],
        "recommendation": "Isolate host and revoke credentials immediately.",
        "created_at": datetime.now(UTC),
    })

    token = create_access_token("analyst-ws-2", "analyst2@forensiq.ai", "analyst")

    client = TestClient(app)
    # Connecting with auto_start=false to test replay of existing steps
    with client.websocket_connect(f"/api/v1/alerts/alert-ws-already-investigated/ws?token={token}&auto_start=false") as ws:
        connected = ws.receive_json()
        assert connected["event"] == "connected"

        status_msg = ws.receive_json()
        assert status_msg["event"] == "status"
        assert status_msg["data"]["status"] == "already_investigated"

        # Reconstructed node steps
        for _ in range(7):
            msg = ws.receive_json()
            assert msg["event"] == "node_complete"

        complete_msg = ws.receive_json()
        assert complete_msg["event"] == "complete"
        assert complete_msg["data"]["alert"]["risk_score"] == 92


@pytest.mark.asyncio
async def test_ws_investigate_observe_only_by_default(test_setup):
    """
    Production-readiness 1.5: WebSocket is observe-only by default.
    Viewing a New alert must NOT automatically trigger pipeline execution or spend LLM compute.
    """
    mock_db = test_setup

    await mock_db["users"].insert_one({
        "_id": "analyst-ws-observe",
        "email": "observer@forensiq.ai",
        "role": "analyst",
        "is_active": True,
        "org_id": "default",
    })

    await mock_db["alerts"].insert_one({
        "_id": "alert-observe-only",
        "title": "Uninvestigated New Alert",
        "host": "srv-observe",
        "user": "corp\\observer",
        "severity": "medium",
        "status": "New",
        "created_at": datetime.now(timezone.utc),
    })

    token = create_access_token("analyst-ws-observe", "observer@forensiq.ai", "analyst")

    client = TestClient(app)
    # Connect without auto_start query param (should default to False)
    with client.websocket_connect(f"/api/v1/alerts/alert-observe-only/ws?token={token}") as ws:
        connected = ws.receive_json()
        assert connected["event"] == "connected"

        # Observe-only status message received
        status_msg = ws.receive_json()
        assert status_msg["event"] == "status"
        assert status_msg["data"]["status"] == "ready"

    # Confirm the alert status in DB remains 'New' (no compute was spent!)
    alert_in_db = await mock_db["alerts"].find_one({"_id": "alert-observe-only"})
    assert alert_in_db["status"] == "New"

