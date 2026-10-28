from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import alerts as alerts_module
from app.database.session import get_db


@pytest.fixture
def db():
    return AsyncMongoMockClient()["alerts_hardening"]


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


async def get(app, path):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.get(path)


NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def alert(i, org, **kw):
    return {"_id": f"a{i}", "org_id": org, "title": f"alert {i}", "severity": "high", "host": "h", "user": "u",
            "status": "New", "created_at": NOW, "rule_name": "r1", **kw}


@pytest.mark.asyncio
async def test_regex_metacharacters_in_search_are_literal(db):
    await db["alerts"].insert_many([alert(1, "acme"), alert(2, "acme")])
    resp = await get(make_app(db), "/alerts/?search=.*")
    assert resp.status_code == 200 and resp.json() == []
    resp = await get(make_app(db), "/alerts/?search=alert 1")
    assert [a["_id"] for a in resp.json()] == ["a1"]


@pytest.mark.asyncio
@pytest.mark.parametrize("qs", ["limit=0", "limit=201", "limit=-5", "severity=catastrophic", "status=Hacked", f"search={'x' * 101}"])
async def test_invalid_list_parameters_are_rejected(db, qs):
    assert (await get(make_app(db), f"/alerts/?{qs}")).status_code == 422


@pytest.mark.asyncio
async def test_valid_filters_still_work_case_insensitively(db):
    await db["alerts"].insert_many([alert(1, "acme", severity="critical", status="Investigated"), alert(2, "acme")])
    resp = await get(make_app(db), "/alerts/?severity=CRITICAL&status=investigated&limit=200")
    assert [a["_id"] for a in resp.json()] == ["a1"]
    assert len((await get(make_app(db), "/alerts/?severity=all&status=all")).json()) == 2


@pytest.mark.asyncio
async def test_investigation_status_is_tenant_scoped(db):
    await db["investigation_jobs"].insert_many([
        {"_id": "mine", "alert_id": "a1", "org_id": "acme", "status": "complete"},
        {"_id": "theirs", "alert_id": "a9", "org_id": "other", "status": "complete"},
    ])
    app = make_app(db, "acme")
    assert (await get(app, "/alerts/investigation/mine")).status_code == 200
    assert (await get(app, "/alerts/investigation/theirs")).status_code == 404


@pytest.mark.asyncio
async def test_stats_endpoints_only_count_the_callers_tenant(db):
    await db["alerts"].insert_many([alert(1, "acme"), alert(2, "acme"), alert(3, "other"), alert(4, "other"), alert(5, "other")])
    by_rule = (await get(make_app(db, "acme"), "/alerts/stats/by-rule")).json()
    assert by_rule == [{"rule_name": "r1", "count": 2}]
    timeline = (await get(make_app(db, "acme"), "/alerts/stats/timeline")).json()
    assert sum(t["count"] for t in timeline) == 2


@pytest.mark.asyncio
async def test_background_investigation_reuses_the_job_row_created_by_post(db, monkeypatch):
    """POST /investigate inserts the job first; the run must update it, not insert a duplicate _id."""
    from app.services import investigation_streamer

    async def fake_astream(state):
        yield {"assess_risk": {"risk_assessment": {"risk_score": 40, "confidence_score": 60, "engine": "deterministic_fallback"}}}
        yield {"generate_recommendations": {"recommendation": "r", "recommendation_engine": "deterministic_fallback"}}

    monkeypatch.setattr(investigation_streamer.investigation_graph, "astream", fake_astream)
    monkeypatch.setattr(investigation_streamer, "correlate_alert", lambda *a, **k: _empty())
    await db["alerts"].insert_one(alert(1, "acme"))
    await db["investigation_jobs"].insert_one({"_id": "job-1", "alert_id": "a1", "org_id": "acme", "status": "pending"})

    await alerts_module.run_investigation_background("a1", "job-1", db)

    job = await db["investigation_jobs"].find_one({"_id": "job-1"})
    saved = await db["alerts"].find_one({"_id": "a1"})
    assert job["status"] == "complete"
    assert saved["status"] == "Investigated"
    assert saved["ai_confidence"] == 60
    assert saved["engines"] == {"risk": "deterministic_fallback", "recommendation": "deterministic_fallback"}


async def _empty():
    return []


@pytest.mark.asyncio
async def test_timeline_buckets_by_detection_time_not_event_time(db):
    month_ago = NOW - timedelta(days=30)
    await db["alerts"].insert_many([
        alert(1, "acme", created_at=month_ago, detected_at=NOW),  # backfilled event, detected now
        alert(2, "acme", created_at=month_ago, detected_at=month_ago),
    ])
    timeline = (await get(make_app(db, "acme"), "/alerts/stats/timeline")).json()
    assert sum(t["count"] for t in timeline) == 1
