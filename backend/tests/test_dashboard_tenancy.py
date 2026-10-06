import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import dashboard as dashboard_module
from app.database.session import get_db


def make_app(db, org):
    app = FastAPI()
    app.include_router(dashboard_module.router, prefix="/dashboard")

    async def _db():
        return db

    async def _user():
        return {"id": "u1", "email": "a@b.test", "role": "soc_analyst", "org_id": org}

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    return app


async def last_ingested(db, org):
    async with AsyncClient(transport=ASGITransport(app=make_app(db, org)), base_url="http://t") as c:
        r = await c.get("/dashboard/metrics")
    assert r.status_code == 200
    return r.json()["last_ingested_at"]


@pytest.mark.asyncio
async def test_last_ingested_is_scoped_to_the_tenant():
    db = AsyncMongoMockClient()["dash_tenancy"]
    await db["ingestion_state"].insert_many([
        {"_id": "cursor:acme:splunk", "ts": "2026-01-01T00:00:00Z"},
        {"_id": "cursor:other:splunk", "ts": "2026-02-02T00:00:00Z"},
        {"_id": "last_ingested", "ts": "2025-12-12T00:00:00Z"},
    ])
    assert await last_ingested(db, "acme") == "2026-01-01T00:00:00Z"
    assert await last_ingested(db, "other") == "2026-02-02T00:00:00Z"


@pytest.mark.asyncio
async def test_non_default_tenant_never_sees_legacy_or_other_cursor():
    db = AsyncMongoMockClient()["dash_tenancy2"]
    await db["ingestion_state"].insert_many([
        {"_id": "cursor:other:splunk", "ts": "2026-02-02T00:00:00Z"},
        {"_id": "last_ingested", "ts": "2025-12-12T00:00:00Z"},
    ])
    assert await last_ingested(db, "acme") is None


@pytest.mark.asyncio
async def test_default_tenant_falls_back_to_legacy_doc():
    db = AsyncMongoMockClient()["dash_tenancy3"]
    await db["ingestion_state"].insert_many([
        {"_id": "cursor:other:splunk", "ts": "2026-02-02T00:00:00Z"},
        {"_id": "last_ingested", "ts": "2025-12-12T00:00:00Z"},
    ])
    assert await last_ingested(db, "default") == "2025-12-12T00:00:00Z"
    await db["ingestion_state"].insert_one({"_id": "cursor:default:splunk", "ts": "2026-03-03T00:00:00Z"})
    assert await last_ingested(db, "default") == "2026-03-03T00:00:00Z"
