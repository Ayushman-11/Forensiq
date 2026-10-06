from unittest.mock import AsyncMock, patch

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.lease import acquire_lease, release_lease
from app.services.poller import AlertPoller


@pytest.fixture
def db():
    return AsyncMongoMockClient()["lease_test"]


@pytest.mark.asyncio
async def test_only_one_owner_holds_the_lease(db):
    assert await acquire_lease(db, "poller", "a", 60)
    assert not await acquire_lease(db, "poller", "b", 60)
    assert await acquire_lease(db, "poller", "a", 60)  # owner can renew


@pytest.mark.asyncio
async def test_expired_lease_can_be_taken_over(db):
    assert await acquire_lease(db, "poller", "a", -1)  # already expired
    assert await acquire_lease(db, "poller", "b", 60)
    assert not await acquire_lease(db, "poller", "a", 60)


@pytest.mark.asyncio
async def test_release_frees_the_lease(db):
    await acquire_lease(db, "poller", "a", 60)
    await release_lease(db, "poller", "a")
    assert await acquire_lease(db, "poller", "b", 60)
    await release_lease(db, "poller", "a")  # non-owner release is a no-op
    assert not await acquire_lease(db, "poller", "a", 60)


@pytest.mark.asyncio
async def test_cycle_skips_ingestion_when_lease_is_held_elsewhere(db):
    await acquire_lease(db, "alert_poller", "someone-else", 60)
    poller = AlertPoller(db, interval_seconds=30)
    with patch("app.services.poller.IngestionService") as svc:
        assert await poller._run_cycle() == 0
        svc.assert_not_called()


@pytest.mark.asyncio
async def test_cycle_uses_a_fresh_service_each_time_and_schedules_investigations(db):
    poller = AlertPoller(db, interval_seconds=30)
    created = []

    def make_service(*a, **k):
        inst = AsyncMock()
        inst.fetch_and_store_alerts.return_value = [{"_id": f"a{len(created)}", "rule_name": "r"}]
        created.append(inst)
        return inst

    poller._investigate_alert = AsyncMock()
    with patch("app.services.poller.IngestionService", side_effect=make_service):
        assert await poller._run_cycle() == 1
        assert await poller._run_cycle() == 1
    import asyncio
    await asyncio.gather(*list(poller._tasks))
    assert len(created) == 2
    assert poller._investigate_alert.await_count == 2
