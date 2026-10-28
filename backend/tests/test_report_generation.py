from datetime import UTC, datetime

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
async def test_download_report_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/alerts/some-alert/report/pdf")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_download_report_not_found(mock_db):
    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        await mock_db["users"].insert_one({
            "_id": "user-pdf-1",
            "email": "analyst@test.com",
            "role": "analyst",
            "is_active": True,
            "org_id": "default",
        })
        token = create_access_token("user-pdf-1", "analyst@test.com", "analyst")
        headers = {"Authorization": f"Bearer {token}"}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/api/v1/alerts/nonexistent-alert/report/pdf", headers=headers)
            assert resp.status_code == 404
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_download_report_pdf_full_and_executive(mock_db):
    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        # Seed user
        await mock_db["users"].insert_one({
            "_id": "user-pdf-2",
            "email": "secops@forensiq.ai",
            "role": "analyst",
            "is_active": True,
            "org_id": "default",
        })

        # Seed alert
        alert_data = {
            "_id": "alert-pdf-test-1",
            "title": "Pass the Hash Attack Detected via Sysmon",
            "host": "dc-corp-01",
            "user": "corp\\adm_jdoe",
            "severity": "critical",
            "status": "Investigated",
            "risk_score": 88,
            "ai_confidence": 92,
            "priority": "critical",
            "created_at": datetime.now(UTC),
            "raw_logs": "mimikatz.exe sekurlsa::pth /user:Administrator",
            "extracted_iocs": ["10.0.0.15", "evil.com"],
            "enrichments": [{"ioc": "evil.com", "reputation": "malicious"}],
            "mitre_mappings": [{"tactic": "Lateral Movement", "technique": "T1550.002", "name": "Pass the Hash"}],
            "timeline": [{"timestamp": "2026-10-17 12:00:00", "description": "LSASS memory access", "phase": "Execution"}],
            "recommendation": "1. Isolate dc-corp-01 immediately.\n2. Invalidate Kerberos TGT tickets.",
        }
        await mock_db["alerts"].insert_one(alert_data)

        token = create_access_token("user-pdf-2", "secops@forensiq.ai", "analyst")
        headers = {"Authorization": f"Bearer {token}"}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. Test /report/pdf (default full)
            resp_full = await ac.get("/api/v1/alerts/alert-pdf-test-1/report/pdf", headers=headers)
            assert resp_full.status_code == 200
            assert resp_full.headers["content-type"] == "application/pdf"
            assert "attachment;" in resp_full.headers["content-disposition"]
            assert resp_full.content.startswith(b"%PDF-")

            # 2. Test /report/pdf?report_type=executive
            resp_exec = await ac.get("/api/v1/alerts/alert-pdf-test-1/report/pdf?report_type=executive", headers=headers)
            assert resp_exec.status_code == 200
            assert resp_exec.headers["content-type"] == "application/pdf"
            assert resp_exec.content.startswith(b"%PDF-")

            # 3. Test inline=true
            resp_inline = await ac.get("/api/v1/alerts/alert-pdf-test-1/report/pdf?inline=true", headers=headers)
            assert resp_inline.status_code == 200
            assert "inline;" in resp_inline.headers["content-disposition"]

            # 4. Test shortcuts /report/full and /report/executive
            resp_full_sc = await ac.get("/api/v1/alerts/alert-pdf-test-1/report/full", headers=headers)
            assert resp_full_sc.status_code == 200
            assert resp_full_sc.content.startswith(b"%PDF-")

            resp_exec_sc = await ac.get("/api/v1/alerts/alert-pdf-test-1/report/executive", headers=headers)
            assert resp_exec_sc.status_code == 200
            assert resp_exec_sc.content.startswith(b"%PDF-")

    finally:
        app.dependency_overrides.clear()
