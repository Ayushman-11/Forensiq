from datetime import datetime, timedelta, timezone

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.agents.context_agent import extract_context_node
from app.api.v1.endpoints.dashboard import ingestion_health
from app.database.indexes import ensure_indexes


@pytest.mark.asyncio
async def test_ensure_indexes_creates_expected_indexes():
    db = AsyncMongoMockClient()["idx"]
    await ensure_indexes(db)
    alert_idx = await db["alerts"].index_information()
    assert any("extracted_iocs" in name for name in alert_idx)
    assert any("org_id" in name and "created_at" in name for name in alert_idx)
    runs_idx = await db["ingestion_runs"].index_information()
    assert any(v.get("expireAfterSeconds") for v in runs_idx.values())
    attempts_idx = await db["login_attempts"].index_information()
    assert any(v.get("expireAfterSeconds") == 0 for v in attempts_idx.values())


@pytest.mark.asyncio
async def test_ingestion_health_is_tenant_scoped_and_aggregates():
    db = AsyncMongoMockClient()["health"]
    now = datetime.now(timezone.utc)
    await db["ingestion_runs"].insert_many([
        {"_id": "r1", "org_id": "default", "started_at": now - timedelta(minutes=2), "status": "ok",
         "fetched": 10, "suppressed": {"a": 3, "b": 1}, "alerts_new": 2},
        {"_id": "r2", "org_id": "default", "started_at": now, "status": "error",
         "fetched": 0, "suppressed": {}, "alerts_new": 0, "errors": [{"stage": "fetch", "error": "down"}]},
        {"_id": "r3", "org_id": "other", "started_at": now, "status": "ok", "fetched": 99, "suppressed": {}, "alerts_new": 9},
    ])
    body = await ingestion_health(db=db, user={"org_id": "default"})
    assert body["last_run"]["_id"] == "r2" and body["last_run"]["status"] == "error"
    assert [r["_id"] for r in body["runs"]] == ["r2", "r1"]
    assert body["totals"] == {"fetched": 10, "suppressed": 4, "alerts_new": 2}


def test_context_agent_uses_global_ip_check(splunk_rows):
    row = dict(splunk_rows["3"][0])
    state = {"alert_data": {"_id": "x", "raw_event": row, "extracted_iocs": []}, "investigation_log": []}
    iocs = extract_context_node(state)["extracted_iocs"]
    assert "34.206.0.173" in iocs
    assert not any(i.startswith(("10.", "192.168.", "172.16.", "169.254.")) for i in iocs)
