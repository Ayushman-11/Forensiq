"""
Durable Background Investigation Worker.

Pulls jobs from MongoDB investigation_jobs queue, runs the LangGraph multi-agent pipeline,
maintains heartbeats during execution, and handles retries with backoff.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.errors import new_request_id
from app.core.logging import logger
from app.services.investigation_streamer import investigation_stream_manager
from app.services.job_queue import claim_next_job, heartbeat_job, mark_job_failed


class InvestigationWorker:
    def __init__(self, db: AsyncIOMotorDatabase, poll_interval: float = 2.0):
        self.db = db
        self.poll_interval = poll_interval
        self.worker_id = f"worker-{uuid4().hex[:8]}"
        self._running = False
        self._loop_task: Optional[asyncio.Task] = None
        self._active_tasks: set[asyncio.Task] = set()
        self._semaphore = asyncio.Semaphore(settings.INVESTIGATION_CONCURRENCY)

    async def _heartbeat_loop(self, job_id: str):
        """Sends periodic heartbeats while job is executing."""
        hb_interval = max(5.0, settings.INVESTIGATION_JOB_LEASE_SECONDS / 3)
        while True:
            await asyncio.sleep(hb_interval)
            try:
                ok = await heartbeat_job(self.db, job_id, self.worker_id)
                if not ok:
                    logger.warning("worker_lease_heartbeat_failed", job_id=job_id, worker=self.worker_id)
                    return
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("worker_heartbeat_error", job_id=job_id, error=str(exc))

    async def _process_job(self, job: dict):
        job_id = job["_id"]
        alert_id = job["alert_id"]
        org_id = job.get("org_id", "default")

        alert = await self.db["alerts"].find_one({"_id": alert_id})
        if not alert:
            ref = new_request_id()
            logger.error("job_alert_not_found", job_id=job_id, alert_id=alert_id)
            await mark_job_failed(self.db, job_id, alert_id, "alert_not_found", ref, can_retry=False)
            return

        hb_task = asyncio.create_task(self._heartbeat_loop(job_id))
        try:
            async for _ in investigation_stream_manager.run_pipeline_stream(
                alert_id=alert_id,
                alert=alert,
                db=self.db,
                job_id=job_id,
                org_id=org_id,
            ):
                pass
            logger.info("worker_job_completed", job_id=job_id, alert_id=alert_id)
        except Exception as exc:
            ref = new_request_id()
            logger.error("worker_job_execution_failed", job_id=job_id, alert_id=alert_id, error=str(exc))
            await mark_job_failed(self.db, job_id, alert_id, "investigation_failed", ref, can_retry=True)
        finally:
            hb_task.cancel()
            await asyncio.gather(hb_task, return_exceptions=True)

    async def _bounded_process(self, job: dict):
        async with self._semaphore:
            await self._process_job(job)

    async def _worker_loop(self):
        logger.info("investigation_worker_loop_started", worker_id=self.worker_id)
        while self._running:
            try:
                job = await claim_next_job(self.db, self.worker_id)
                if job:
                    task = asyncio.create_task(self._bounded_process(job))
                    self._active_tasks.add(task)
                    task.add_done_callback(self._active_tasks.discard)
                else:
                    await asyncio.sleep(self.poll_interval)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("investigation_worker_loop_error", worker_id=self.worker_id, error=str(exc))
                await asyncio.sleep(self.poll_interval)

    def start(self):
        if not self._running:
            self._running = True
            self._loop_task = asyncio.create_task(self._worker_loop())
            logger.info("investigation_worker_started", worker_id=self.worker_id)

    async def stop(self):
        self._running = False
        if self._loop_task:
            self._loop_task.cancel()
            await asyncio.gather(self._loop_task, return_exceptions=True)
        pending = list(self._active_tasks)
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        logger.info("investigation_worker_stopped", worker_id=self.worker_id)

