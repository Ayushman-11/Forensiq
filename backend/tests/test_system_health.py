from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user, get_siem_client
from app.api.v1.endpoints import dashboard as dashboard_module
from app.core.config import settings
from app.database.session import get_db


class FakeSiem:
    def __init__(self, ok):
        self.ok = ok

    async def authenticate(self):
        if self.ok is None:
            raise RuntimeError("unreachable")
        return self.ok


async def health(db, siem_ok=True, org="acme"):
    app = FastAPI()
    app.include_router(dashboard_module.router, prefix="/dashboard")

    async def _db():
        return db

    async def _user():
        return {"id": "u1", "email": "a@b.test", "role": "soc_analyst", "org_id": org}

    async def _siem():
        yield FakeSiem(siem_ok)

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    app.dependency_overrides[get_siem_client] = _siem
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/dashboard/system-health")
    assert r.status_code == 200
    return r.json()


@pytest.fixture
def db():
    return AsyncMongoMockClient()["system_health"]


@pytest.fixture
def no_keys(monkeypatch):
    monkeypatch.setattr(settings, "VT_API_KEY", "")
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr(settings, "XAI_API_KEY", "")


@pytest.mark.asyncio
async def test_nothing_is_reported_healthy_without_evidence(db, no_keys):
    body = await health(db, siem_ok=None)
    assert body["siem"]["state"] == "down"
    assert body["ingestion"]["state"] == "never"
    assert body["threat_intel"]["state"] == "down"
    assert {f["state"] for f in body["threat_intel"]["feeds"]} == {"not_configured"}
    assert body["ai"]["mode"] == "rules"


@pytest.mark.asyncio
async def test_ingestion_state_follows_the_tenants_last_run(db, no_keys):
    now = datetime.now(timezone.utc)
    await db["ingestion_runs"].insert_many([
        {"_id": "1", "org_id": "acme", "status": "ok", "started_at": now - timedelta(hours=2), "finished_at": now - timedelta(hours=2)},
        {"_id": "2", "org_id": "other", "status": "ok", "started_at": now, "finished_at": now},
    ])
    assert (await health(db))["ingestion"]["state"] == "stale"

    await db["ingestion_runs"].insert_one(
        {"_id": "3", "org_id": "acme", "status": "error", "started_at": now, "finished_at": now, "errors": [{"stage": "fetch"}]}
    )
    ingestion = (await health(db))["ingestion"]
    assert ingestion["state"] == "error" and "fetch" in ingestion["detail"]


@pytest.mark.asyncio
async def test_threat_intel_degrades_on_recent_feed_errors(db, monkeypatch):
    monkeypatch.setattr(settings, "VT_API_KEY", "k")
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "")
    await db["alerts"].insert_one({
        "_id": "a1", "org_id": "acme", "status": "Investigated", "created_at": datetime.now(timezone.utc),
        "enrichments": [{"source": "VirusTotal", "status": "error"}],
    })
    ti = (await health(db))["threat_intel"]
    assert ti["state"] == "degraded"
    assert {"feed": "VirusTotal", "state": "error", "recent_errors": 1} in ti["feeds"]


async def config_as(db, role):
    app = FastAPI()
    app.include_router(dashboard_module.router, prefix="/dashboard")

    async def _db():
        return db

    async def _user():
        return {"id": "u1", "email": "a@b.test", "role": role, "org_id": "acme"}

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.get("/dashboard/config")


@pytest.mark.asyncio
async def test_config_is_admin_only_and_never_returns_secrets(db, monkeypatch):
    monkeypatch.setattr(settings, "VT_API_KEY", "vt-secret-value")
    assert (await config_as(db, "soc_analyst")).status_code == 403
    r = await config_as(db, "admin")
    assert r.status_code == 200
    assert r.json()["threat_intel"]["virustotal_configured"] is True
    assert "vt-secret-value" not in r.text and settings.SPLUNK_PASSWORD not in r.text
