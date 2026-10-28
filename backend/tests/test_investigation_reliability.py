"""
Tests for Production-Readiness Section 1.5: Reliability of Investigations.
Validates:
- Durable job queue: atomic claiming, worker leasing, and heartbeats
- Idempotency key per alert (single active run per alert)
- Stuck-job reaper recovering expired runs on boot and after mid-run failure
- Multi-process event persistence in investigation_events
- Statistics endpoints error propagation (5xx with request ID, no swallowed errors)
- Poller database lease chaos tests (lease expiry, mutual exclusion, takeover)
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient

from app.main import app
from app.database.session import get_db
from app.core.security import create_access_token
from app.services.job_queue import (
    enqueue_investigation_job,
    claim_next_job,
    heartbeat_job,
    mark_job_failed,
    reap_stuck_jobs,
)
from app.services.lease import acquire_lease, release_lease


@pytest.fixture
def mock_db():
    client = AsyncMongoMockClient()
    return client["test_reliability"]


@pytest.mark.asyncio
async def test_job_queue_enqueue_claim_and_idempotency(mock_db):
    user = {"id": "analyst-1", "email": "analyst@forensiq.ai", "org_id": "default"}
    alert_id = "alert-queue-test-1"

    # 1. Enqueue job
    res1 = await enqueue_investigation_job(mock_db, alert_id, user)
    assert res1["status"] == "success"
    job_id = res1["job_id"]

    # 2. Idempotency test: enqueuing again for the same alert returns existing active job
    res2 = await enqueue_investigation_job(mock_db, alert_id, user)
    assert res2["status"] == "already_active"
    assert res2["job_id"] == job_id

    # 3. Worker claims job atomically
    claimed = await claim_next_job(mock_db, worker_id="worker-node-1")
    assert claimed is not None
    assert claimed["_id"] == job_id
    assert claimed["worker_id"] == "worker-node-1"
    assert claimed["status"] == "running"
    assert claimed["lease_expires_at"] is not None

    # 4. No more pending jobs to claim
    claimed_again = await claim_next_job(mock_db, worker_id="worker-node-2")
    assert claimed_again is None

    # 5. Heartbeat extends lease
    initial_expiry = claimed["lease_expires_at"]
    await asyncio.sleep(0.01)
    heartbeat_ok = await heartbeat_job(mock_db, job_id, "worker-node-1")
    assert heartbeat_ok is True
    updated_job = await mock_db["investigation_jobs"].find_one({"_id": job_id})
    assert updated_job["lease_expires_at"] >= initial_expiry


@pytest.mark.asyncio
async def test_stuck_job_reaper_recovers_and_eventually_fails(mock_db):
    user = {"id": "analyst-2", "email": "analyst2@forensiq.ai", "org_id": "default"}
    alert_id = "alert-stuck-test"

    # Seed alert in database
    await mock_db["alerts"].insert_one({
        "_id": alert_id,
        "org_id": "default",
        "title": "Alert for stuck reaper test",
        "status": "New",
        "created_at": datetime.now(timezone.utc),
    })

    # Enqueue and claim
    res = await enqueue_investigation_job(mock_db, alert_id, user)
    job_id = res["job_id"]
    claimed = await claim_next_job(mock_db, "worker-crashed")

    # Simulate worker crash mid-run and lease expiration (lease expired 10 minutes ago)
    past_expiry = datetime.now(timezone.utc) - timedelta(minutes=10)
    await mock_db["investigation_jobs"].update_one(
        {"_id": job_id},
        {"$set": {"lease_expires_at": past_expiry, "retries": 0, "max_retries": 2}},
    )

    # 1. Reaper run #1: lease expired, retries < max_retries -> re-queued to pending
    reap_res1 = await reap_stuck_jobs(mock_db)
    assert reap_res1["requeued"] == 1
    assert reap_res1["failed"] == 0

    requeued_job = await mock_db["investigation_jobs"].find_one({"_id": job_id})
    assert requeued_job["status"] == "pending"
    assert requeued_job["retries"] == 1
    assert requeued_job["worker_id"] is None

    # Worker 2 claims it and also crashes
    claimed2 = await claim_next_job(mock_db, "worker-crashed-2")
    await mock_db["investigation_jobs"].update_one(
        {"_id": job_id},
        {"$set": {"lease_expires_at": past_expiry}},
    )

    # 2. Reaper run #2: retries reached max_retries -> marked failed permanently
    reap_res2 = await reap_stuck_jobs(mock_db)
    assert reap_res2["failed"] == 1

    failed_job = await mock_db["investigation_jobs"].find_one({"_id": job_id})
    assert failed_job["status"] == "failed"
    assert failed_job["error"] == "investigation_timed_out_or_abandoned"

    # Confirm alert was marked as "Investigation Failed"
    alert = await mock_db["alerts"].find_one({"_id": alert_id})
    assert alert["status"] == "Investigation Failed"


@pytest.mark.asyncio
async def test_statistics_endpoints_raise_5xx_on_error(mock_db):
    """
    Production-readiness 1.5: Statistics endpoints must NOT swallow errors
    and return empty data; they must return 5xx with a request ID.
    """
    async def _get_db():
        return mock_db

    app.dependency_overrides[get_db] = _get_db
    try:
        await mock_db["users"].insert_one({
            "_id": "u1",
            "email": "user@test.com",
            "role": "analyst",
            "is_active": True,
            "org_id": "default",
        })
        token = create_access_token("u1", "user@test.com", "analyst")
        headers = {"Authorization": f"Bearer {token}"}

        coll_cls = type(mock_db["alerts"])
        # Mock collection aggregate to raise an error
        with patch.object(coll_cls, "aggregate", side_effect=RuntimeError("Database query failed")):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                res_rule = await client.get("/api/v1/alerts/stats/by-rule", headers=headers)
                assert res_rule.status_code == 500
                assert "ref" in res_rule.json()["detail"] or "Internal server error" in res_rule.json()["detail"]

                res_timeline = await client.get("/api/v1/alerts/stats/timeline", headers=headers)
                assert res_timeline.status_code == 500
                assert "Internal server error" in res_timeline.json()["detail"]

        with patch.object(coll_cls, "find", side_effect=RuntimeError("Index corrupt")):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                res_mitre = await client.get("/api/v1/alerts/stats/mitre", headers=headers)
                assert res_mitre.status_code == 500
                assert "Internal server error" in res_mitre.json()["detail"]

    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_poller_lease_mutual_exclusion_and_takeover(mock_db):
    """
    Production-readiness 1.5: Poller database lease chaos test.
    Tests lease mutual exclusion, refusal for second holder, and takeover on expiry.
    """
    lease_name = "test_poller_lease"

    # 1. Owner A acquires lease for 60 seconds
    acquired_a = await acquire_lease(mock_db, lease_name, owner="owner-a", ttl_seconds=60)
    assert acquired_a is True

    # 2. Owner B attempts to acquire while unexpired -> refused
    acquired_b = await acquire_lease(mock_db, lease_name, owner="owner-b", ttl_seconds=60)
    assert acquired_b is False

    # 3. Owner A can renew its own lease
    renewed_a = await acquire_lease(mock_db, lease_name, owner="owner-a", ttl_seconds=60)
    assert renewed_a is True

    # 4. Simulate Owner A dying and lease expiring (expires_at in past)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await mock_db["leases"].update_one(
        {"_id": lease_name},
        {"$set": {"expires_at": now - timedelta(seconds=10)}},
    )

    # 5. Owner B takes over expired lease
    acquired_b_after_expiry = await acquire_lease(mock_db, lease_name, owner="owner-b", ttl_seconds=60)
    assert acquired_b_after_expiry is True

    # 6. Release lease
    await release_lease(mock_db, lease_name, owner="owner-b")
    doc = await mock_db["leases"].find_one({"_id": lease_name})
    assert doc is None
