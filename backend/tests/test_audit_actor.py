import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.audit import record_audit


@pytest.mark.asyncio
async def test_actor_id_is_the_authenticated_users_id():
    db = AsyncMongoMockClient()["audit_test"]
    await record_audit(db, {"id": "user-1", "email": "a@b.test", "org_id": "default"}, "alert.close", "alert", "a1")
    doc = await db["audit_logs"].find_one({})
    assert doc["actor_id"] == "user-1" and doc["actor_email"] == "a@b.test"


@pytest.mark.asyncio
async def test_legacy_underscore_id_and_system_fallbacks():
    db = AsyncMongoMockClient()["audit_test2"]
    await record_audit(db, {"_id": "legacy"}, "x", "alert", "a1")
    await record_audit(db, None, "y", "alert", "a2")
    docs = {d["action"]: d["actor_id"] async for d in db["audit_logs"].find({})}
    assert docs == {"x": "legacy", "y": "system"}
