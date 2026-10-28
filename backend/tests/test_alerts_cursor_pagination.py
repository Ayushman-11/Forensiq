from datetime import datetime, timezone, timedelta
import pytest
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import alerts as alerts_module
from app.database.session import get_db
from fastapi import FastAPI


@pytest.fixture
def db():
    return AsyncMongoMockClient()["alerts_cursor_test"]


def make_app(db, org="acme"):
    app = FastAPI()
    app.include_router(alerts_module.router, prefix="/alerts")

    async def _db():
        return db

    async def _user():
        return {"id": "u1", "email": "a@b.test", "role": "soc_analyst", "org_id": org}

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    return app


@pytest.mark.asyncio
async def test_alerts_cursor_pagination(db):
    base_time = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
    docs = []
    for i in range(1, 16):
        docs.append({
            "_id": f"alert-{i:03d}",
            "org_id": "acme",
            "title": f"Suspicious Activity #{i}",
            "severity": "high",
            "status": "New",
            "created_at": base_time - timedelta(minutes=i),
            "detected_at": base_time - timedelta(minutes=i),
        })
    await db["alerts"].insert_many(docs)

    app = make_app(db, "acme")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Fetch first page of 5 items
        res1 = await client.get("/alerts/?limit=5&sort=newest")
        assert res1.status_code == 200
        items1 = res1.json()
        assert len(items1) == 5
        assert res1.headers.get("x-total-count") == "15"
        cursor1 = res1.headers.get("x-next-cursor")
        assert cursor1 is not None

        # Fetch second page using cursor
        res2 = await client.get(f"/alerts/?limit=5&sort=newest&cursor={cursor1}")
        assert res2.status_code == 200
        items2 = res2.json()
        assert len(items2) == 5
        assert [a["_id"] for a in items2] == [f"alert-{i:03d}" for i in range(6, 11)]
        cursor2 = res2.headers.get("x-next-cursor")
        assert cursor2 is not None

        # Fetch third page using cursor
        res3 = await client.get(f"/alerts/?limit=5&sort=newest&cursor={cursor2}")
        assert res3.status_code == 200
        items3 = res3.json()
        assert len(items3) == 5
        assert [a["_id"] for a in items3] == [f"alert-{i:03d}" for i in range(11, 16)]


@pytest.mark.asyncio
async def test_mitre_stats_aggregates_past_500(db):
    # Insert 600 alerts with MITRE techniques
    docs = []
    for i in range(1, 601):
        docs.append({
            "_id": f"mitre-alert-{i:04d}",
            "org_id": "acme",
            "title": f"Process Injection #{i}",
            "severity": "critical" if i % 2 == 0 else "high",
            "mitre_technique": "T1055",
            "mitre_tactic": "Defense Evasion",
            "mitre_mappings": [{"technique": "T1055", "tactic": "Defense Evasion", "name": "Process Injection"}],
            "created_at": datetime.now(timezone.utc),
        })
    await db["alerts"].insert_many(docs)

    app = make_app(db, "acme")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/alerts/stats/mitre")
        assert res.status_code == 200
        data = res.json()
        assert data["total_mapped_alerts"] == 600
        tech = next((t for t in data["techniques"] if t["id"] == "T1055"), None)
        assert tech is not None
        assert tech["count"] == 600
        assert data["tactics_summary"].get("Defense Evasion") == 600
