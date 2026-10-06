from datetime import datetime

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.api.v1.endpoints.alerts import get_alert, list_alerts


@pytest.mark.asyncio
async def test_list_omits_raw_events_but_detail_keeps_them():
    db = AsyncMongoMockClient()["alerts_list_test"]
    await db["alerts"].insert_one({
        "_id": "a1", "org_id": "default", "title": "t", "created_at": datetime(2026, 8, 11),
        "raw_event": {"x": 1}, "raw_events": [{"x": 1}, {"x": 2}],
    })
    user = {"org_id": "default"}
    result = await list_alerts(limit=50, severity=None, status=None, search=None, db=db, user=user)
    assert len(result) == 1
    assert "raw_events" not in result[0]
    assert result[0]["raw_event"] == {"x": 1}
    detail = await get_alert("a1", db=db, user=user)
    assert len(detail["raw_events"]) == 2
