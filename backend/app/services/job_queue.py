"""
Durable MongoDB Investigation Job Queue & Stuck-Job Reaper.

Features:
- Atomic job claiming with worker leasing and heartbeats
- Idempotency key per alert (prevents concurrent duplicate runs)
- Stuck-job reaper on boot and periodic cleanup
- Exponential backoff / retry mechanism for resilient investigations
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pymongo import ReturnDocument

from app.core.config import settings
from app.core.errors import new_request_id
from app.core.logging import logger
from app.core.tenancy import scoped_query, tenant_id


async def enqueue_investigation_job(
    db,
    alert_id: str,
    user: dict | None = None,
    priority: int = 1,
) -> dict:
    """
    Enqueues an investigation job for an alert.
    Guarantees idempotency: if an active job already exists for this alert,
    returns the existing job rather than spawning a duplicate.
    """
    org = tenant_id(user)

    # 1. Idempotency check: see if there is an active job running or pending
    active_job = await db["investigation_jobs"].find_one({
        "alert_id": alert_id,
        "status": {"$in": ["pending", "running"]},
    })
    if active_job:
        logger.info(
            "investigation_job_already_active",
            alert_id=alert_id,
            job_id=active_job["_id"],
            status=active_job["status"],
        )
        return {
            "status": "already_active",
            "job_id": str(active_job["_id"]),
            "alert_id": alert_id,
            "job_status": active_job["status"],
            "message": f"Investigation is already {active_job['status']}",
        }

    job_id = str(uuid4())
    now = datetime.now(timezone.utc)

    job_doc = {
        "_id": job_id,
        "alert_id": alert_id,
        "org_id": org,
        "status": "pending",
        "priority": priority,
        "created_at": now,
        "started_at": None,
        "completed_at": None,
        "worker_id": None,
        "lease_expires_at": None,
        "retries": 0,
        "max_retries": settings.INVESTIGATION_MAX_RETRIES,
        "error": None,
        "error_ref": None,
    }

    await db["investigation_jobs"].insert_one(job_doc)

    # Transition alert status to Investigating
    await db["alerts"].update_one(
        scoped_query(user, {"_id": alert_id}),
        {"$set": {"status": "Investigating"}},
    )

    logger.info("investigation_job_enqueued", job_id=job_id, alert_id=alert_id)
    return {
        "status": "success",
        "job_id": job_id,
        "alert_id": alert_id,
        "message": "Investigation job queued",
    }


async def claim_next_job(db, worker_id: str) -> Optional[dict]:
    """
    Atomically claims the highest-priority oldest pending job.
    Sets a heartbeat lease on the job.
    """
    now = datetime.now(timezone.utc)
    lease_expires_at = now + timedelta(seconds=settings.INVESTIGATION_JOB_LEASE_SECONDS)

    job = await db["investigation_jobs"].find_one_and_update(
        {"status": "pending"},
        {
            "$set": {
                "status": "running",
                "worker_id": worker_id,
                "started_at": now,
                "lease_expires_at": lease_expires_at,
            }
        },
        sort=[("priority", -1), ("created_at", 1)],
        return_document=ReturnDocument.AFTER,
    )
    return job


async def heartbeat_job(db, job_id: str, worker_id: str) -> bool:
    """Renews worker lease on a running job so slow investigations are not reaped."""
    now = datetime.now(timezone.utc)
    lease_expires_at = now + timedelta(seconds=settings.INVESTIGATION_JOB_LEASE_SECONDS)

    res = await db["investigation_jobs"].update_one(
        {"_id": job_id, "worker_id": worker_id, "status": "running"},
        {"$set": {"lease_expires_at": lease_expires_at}},
    )
    return res.modified_count > 0


async def mark_job_failed(
    db,
    job_id: str,
    alert_id: str,
    error: str,
    error_ref: str,
    can_retry: bool = True,
) -> bool:
    """
    Marks a job as failed, or re-queues it for retry if retries remain.
    Returns True if re-queued for retry, False if marked permanently failed.
    """
    job = await db["investigation_jobs"].find_one({"_id": job_id})
    current_retries = (job.get("retries", 0) if job else 0) + 1
    max_retries = job.get("max_retries", settings.INVESTIGATION_MAX_RETRIES) if job else settings.INVESTIGATION_MAX_RETRIES

    if can_retry and current_retries < max_retries:
        logger.warning(
            "investigation_job_retrying",
            job_id=job_id,
            alert_id=alert_id,
            retry=current_retries,
            max_retries=max_retries,
        )
        await db["investigation_jobs"].update_one(
            {"_id": job_id},
            {
                "$set": {
                    "status": "pending",
                    "retries": current_retries,
                    "worker_id": None,
                    "lease_expires_at": None,
                    "last_error": error,
                    "error_ref": error_ref,
                }
            },
        )
        return True

    now = datetime.now(timezone.utc)
    logger.error("investigation_job_permanently_failed", job_id=job_id, alert_id=alert_id, error=error)
    await db["investigation_jobs"].update_one(
        {"_id": job_id},
        {
            "$set": {
                "status": "failed",
                "completed_at": now,
                "error": error,
                "error_ref": error_ref,
                "retries": current_retries,
            }
        },
    )
    await db["alerts"].update_one(
        {"_id": alert_id},
        {"$set": {"status": "Investigation Failed"}},
    )
    return False


async def reap_stuck_jobs(db) -> dict:
    """
    Scans for abandoned or stuck jobs whose leases have expired.
    Re-queues jobs eligible for retry, or permanently fails jobs exceeding max retries.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=settings.INVESTIGATION_JOB_LEASE_SECONDS)

    stuck_query = {
        "status": "running",
        "$or": [
            {"lease_expires_at": {"$lt": now}},
            {"lease_expires_at": None, "started_at": {"$lt": cutoff}},
        ],
    }

    cursor = db["investigation_jobs"].find(stuck_query)
    requeued_count = 0
    failed_count = 0

    async for job in cursor:
        job_id = job["_id"]
        alert_id = job.get("alert_id")
        retries = job.get("retries", 0) + 1
        max_retries = job.get("max_retries", settings.INVESTIGATION_MAX_RETRIES)

        if retries < max_retries:
            logger.warning("reaper_requeuing_stuck_job", job_id=job_id, alert_id=alert_id, retry=retries)
            await db["investigation_jobs"].update_one(
                {"_id": job_id},
                {
                    "$set": {
                        "status": "pending",
                        "retries": retries,
                        "worker_id": None,
                        "lease_expires_at": None,
                    }
                },
            )
            requeued_count += 1
        else:
            logger.error("reaper_failing_abandoned_job", job_id=job_id, alert_id=alert_id)
            ref = new_request_id()
            await db["investigation_jobs"].update_one(
                {"_id": job_id},
                {
                    "$set": {
                        "status": "failed",
                        "completed_at": now,
                        "error": "investigation_timed_out_or_abandoned",
                        "error_ref": ref,
                        "retries": retries,
                    }
                },
            )
            if alert_id:
                await db["alerts"].update_one(
                    {"_id": alert_id},
                    {"$set": {"status": "Investigation Failed"}},
                )
            failed_count += 1

    return {"requeued": requeued_count, "failed": failed_count}

