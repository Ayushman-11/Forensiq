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


@pytest.mark.asyncio
async def test_stop_releases_lease_and_cancels_inflight_investigations(db):
    import asyncio

    poller = AlertPoller(db, interval_seconds=30)
    started = asyncio.Event()

    async def slow(alert):
        started.set()
        await asyncio.sleep(60)

    def make_service(*a, **k):
        inst = AsyncMock()
        inst.fetch_and_store_alerts.return_value = [{"_id": "a1", "rule_name": "r"}]
        return inst

    poller._investigate_alert = slow
    with patch("app.services.poller.IngestionService", side_effect=make_service):
        assert await poller._run_cycle() == 1
    await started.wait()
    inflight = list(poller._tasks)
    assert inflight
    await poller.stop()
    assert all(t.cancelled() for t in inflight)
    assert await acquire_lease(db, "alert_poller", "other", 60)


@pytest.mark.asyncio
async def test_heartbeat_renews_lease_during_slow_cycle(db, monkeypatch):
    import asyncio

    from app.core.config import settings

    monkeypatch.setattr(settings, "POLLER_LEASE_TTL_SECONDS", 0.3)
    poller = AlertPoller(db, interval_seconds=30)
    seen = {}

    def make_service(*a, **k):
        inst = AsyncMock()

        async def slow():
            seen["first"] = (await db["leases"].find_one({"_id": "alert_poller"}))["expires_at"]
            await asyncio.sleep(1)
            seen["last"] = (await db["leases"].find_one({"_id": "alert_poller"}))["expires_at"]
            seen["other"] = await acquire_lease(db, "alert_poller", "other", 60)
            return []

        inst.fetch_and_store_alerts.side_effect = slow
        return inst

    with patch("app.services.poller.IngestionService", side_effect=make_service):
        assert await poller._run_cycle() == 0
    assert seen["other"] is False
    assert seen["last"] > seen["first"]


@pytest.mark.asyncio
async def test_heartbeat_task_does_not_outlive_cycle(db):
    import asyncio

    poller = AlertPoller(db, interval_seconds=30)

    def make_service(*a, **k):
        inst = AsyncMock()
        inst.fetch_and_store_alerts.return_value = []
        return inst

    before = asyncio.all_tasks()
    with patch("app.services.poller.IngestionService", side_effect=make_service):
        await poller._run_cycle()
    leftover = [t for t in asyncio.all_tasks() - before if not t.done()]
    assert leftover == []


@pytest.mark.asyncio
async def test_heartbeat_survives_a_failed_renewal(db, monkeypatch):
    import asyncio

    from app.core.config import settings

    monkeypatch.setattr(settings, "POLLER_LEASE_TTL_SECONDS", 0.03)
    poller = AlertPoller(db, interval_seconds=30)
    calls = []

    async def flaky(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("mongo hiccup")
        return True

    with patch("app.services.poller.acquire_lease", new=flaky):
        hb = asyncio.create_task(poller._heartbeat())
        await asyncio.sleep(0.5)
        assert not hb.done()
        assert len(calls) >= 2
        hb.cancel()
        await asyncio.gather(hb, return_exceptions=True)
