import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user, get_siem_client
from app.api.v1.endpoints import search as search_module
from app.database.session import get_db


class FakeSiem:
    def __init__(self, fail=False):
        self.queries, self.fail = [], fail

    async def search(self, query, earliest_time, latest_time, limit):
        if self.fail:
            raise RuntimeError("splunk down")
        self.queries.append((query, earliest_time, latest_time, limit))
        return []


@pytest.fixture
def db():
    return AsyncMongoMockClient()["search_test"]


def make_app(db, siem, user):
    app = FastAPI()
    app.include_router(search_module.router, prefix="/search")

    async def _db():
        return db

    async def _siem():
        yield siem

    async def _user():
        return user

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_siem_client] = _siem
    app.dependency_overrides[get_current_user] = _user
    return app


async def post(app, **body):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.post("/search", json=body)


ANALYST = {"id": "u1", "email": "a@b.test", "role": "soc_analyst", "org_id": "default"}


@pytest.mark.asyncio
async def test_valid_query_reaches_siem_rewritten_with_index(db, monkeypatch):
    monkeypatch.setattr(search_module.settings, "SPLUNK_DETECTION_INDEX", "windows")  # local .env may override
    siem = FakeSiem()
    resp = await post(make_app(db, siem, ANALYST), query="EventCode=4625 | head 5", earliest_time="-1h")
    assert resp.status_code == 200
    assert siem.queries[0][0] == "search index=windows EventCode=4625 | head 5"


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["index=* | delete", "EventCode=1 | outputlookup x", "| rest /services/x"])
async def test_dangerous_queries_are_rejected_before_reaching_siem(db, query):
    siem = FakeSiem()
    resp = await post(make_app(db, siem, ANALYST), query=query)
    assert resp.status_code == 400 and siem.queries == []
    assert "Traceback" not in resp.text


@pytest.mark.asyncio
async def test_time_range_over_limit_is_rejected(db):
    siem = FakeSiem()
    resp = await post(make_app(db, siem, ANALYST), query="EventCode=1", earliest_time="-90d")
    assert resp.status_code == 400 and siem.queries == []


@pytest.mark.asyncio
async def test_unknown_role_is_forbidden(db):
    resp = await post(make_app(db, FakeSiem(), {**ANALYST, "role": "guest"}), query="EventCode=1")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_search_is_audited(db):
    await post(make_app(db, FakeSiem(), ANALYST), query="EventCode=1")
    entry = await db["audit_logs"].find_one({"action": "search.execute"})
    assert entry["actor_id"] == "u1" and "EventCode=1" in entry["metadata"]["query"]


@pytest.mark.asyncio
async def test_mongo_fallback_is_tenant_scoped(db):
    base = {"severity": "high", "host": "h", "user": "u", "status": "New", "title": "powershell alert"}
    await db["alerts"].insert_many([
        {"_id": "a", "org_id": "acme", **base},
        {"_id": "b", "org_id": "other", **base},
    ])
    resp = await post(make_app(db, FakeSiem(fail=True), {**ANALYST, "org_id": "acme"}), query="powershell")
    assert resp.status_code == 200
    ids = {e["raw_payload"]["_id"] for e in resp.json()["events"]}
    assert ids == {"a"}
