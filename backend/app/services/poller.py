"""
Alert poller. One schedule per tenant: each tenant with a SIEM configured is polled on its own interval, under its own
lease (so replicas split the work safely), with its own cursor and credentials. A failing tenant backs off without
slowing the others, and its last run is recorded in `tenant_runtime` for the admin UI.
"""

import asyncio
import time
import uuid
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.logging import logger
from app.services.ingestion import IngestionService
from app.services.investigation_streamer import investigation_stream_manager
from app.services.lease import acquire_lease, release_lease
from app.services.tenants import ingestion_kwargs, resolve_config

LEASE_NAME = "alert_poller"
MAX_BACKOFF_FACTOR = 8
TICK_SECONDS = 5


def lease_name(org_id: str) -> str:
    """The platform tenant keeps the original lease name so a rolling upgrade never runs two pollers for it."""
    return LEASE_NAME if org_id == settings.PLATFORM_ORG_ID else f"{LEASE_NAME}:{org_id}"


class AlertPoller:
    def __init__(self, db: AsyncIOMotorDatabase, interval_seconds: int = 30):
        self.db = db
        self.interval_seconds = interval_seconds
        self.owner = str(uuid.uuid4())
        self._running = False
        self._task = None
        self._tasks: set = set()
        self._semaphore = asyncio.Semaphore(settings.INVESTIGATION_CONCURRENCY)
        self._next_run: dict[str, float] = {}
        self._failures: dict[str, int] = {}

    async def _cycle(self, org_id: str) -> tuple[int, list]:
        """One poll for one tenant: take/renew its lease, ingest with its credentials, schedule investigations.

        Returns (new alert count, ingestion errors). (-1, []) means the tenant was skipped."""
        cfg = await resolve_config(self.db, org_id)
        if cfg.status != "active" or not cfg.siem.enabled:
            return -1, []
        if org_id != settings.PLATFORM_ORG_ID and not cfg.siem.configured:
            return -1, []
        name = lease_name(org_id)
        if not await acquire_lease(self.db, name, self.owner, settings.POLLER_LEASE_TTL_SECONDS):
            logger.info("poller_lease_held_elsewhere", org_id=org_id)
            return -1, []

        hb = asyncio.create_task(self._heartbeat(name))
        errors: list = []
        try:
            # fresh per cycle: counters and errors do not accumulate
            service = IngestionService(self.db, org_id, **await ingestion_kwargs(self.db, org_id))
            new_alerts = await service.fetch_and_store_alerts()
            if isinstance(getattr(service, "errors", None), list):
                errors = service.errors
        finally:
            hb.cancel()
            await asyncio.gather(hb, return_exceptions=True)
        if not new_alerts:
            logger.info("poller_no_new_alerts", org_id=org_id)
            return 0, errors

        logger.info("poller_new_alerts", org_id=org_id, count=len(new_alerts), rules=sorted({a.get("rule_name") for a in new_alerts}))
        for alert in new_alerts:
            task = asyncio.create_task(self._bounded_investigation(alert))
            self._tasks.add(task)  # keep a reference so the task is not garbage-collected
            task.add_done_callback(self._on_investigation_done)
        return len(new_alerts), errors

    async def _run_cycle(self, org_id: str | None = None) -> int:
        """Poll one tenant now (the platform tenant by default). Returns the number of new alerts."""
        count, _ = await self._cycle(org_id or settings.PLATFORM_ORG_ID)
        return max(count, 0)

    async def _due_tenants(self) -> list[tuple[str, int]]:
        """(tenant, interval seconds) for every tenant that should be polled now."""
        orgs = {settings.PLATFORM_ORG_ID}
        async for doc in self.db["tenants"].find({"status": {"$ne": "suspended"}, "config.siem": {"$exists": True}}, {"_id": 1}):
            orgs.add(doc["_id"])
        now = time.monotonic()
        due = []
        for org in sorted(orgs):
            if self._next_run.get(org, 0) <= now:
                cfg = await resolve_config(self.db, org)
                due.append((org, max(int(cfg.siem.poll_interval_seconds or self.interval_seconds), 1)))
        return due

    async def _run_tenant(self, org_id: str, interval: int, gate: asyncio.Semaphore) -> None:
        async with gate:
            started = datetime.now(timezone.utc)
            error = None
            new = 0
            try:
                count, errors = await self._cycle(org_id)
                if count < 0:
                    self._next_run[org_id] = time.monotonic() + interval
                    return
                new = count
                if errors:
                    error = "; ".join(str(e.get("stage", "?")) for e in errors)[:300]
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # one tenant's broken SIEM must never stop the others
                error = f"{type(exc).__name__}: {exc}"[:300]
                logger.error("tenant_poll_failed", org_id=org_id, error=error)
            failures = 0 if error is None else self._failures.get(org_id, 0) + 1
            self._failures[org_id] = failures
            backoff = min(2 ** failures, MAX_BACKOFF_FACTOR) if failures else 1
            self._next_run[org_id] = time.monotonic() + interval * backoff
            try:
                update = {"last_poll_at": started, "last_new_alerts": new, "consecutive_failures": failures, "last_error": error}
                if error is None:
                    update["last_success_at"] = started
                await self.db["tenant_runtime"].update_one({"_id": org_id}, {"$set": update}, upsert=True)
            except Exception as exc:
                logger.warning("tenant_runtime_write_failed", org_id=org_id, error=str(exc))

    async def _poll_once(self) -> None:
        gate = asyncio.Semaphore(max(settings.POLLER_TENANT_CONCURRENCY, 1))
        due = await self._due_tenants()
        await asyncio.gather(*(self._run_tenant(org, interval, gate) for org, interval in due))

    def _on_investigation_done(self, task) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception():
            logger.error("auto_investigation_task_failed", error=str(task.exception()))

    async def _heartbeat(self, name: str = LEASE_NAME) -> None:
        """Renew the lease while a cycle runs so a slow cycle cannot lose it."""
        while True:
            await asyncio.sleep(settings.POLLER_LEASE_TTL_SECONDS / 3)
            try:
                ok = await acquire_lease(self.db, name, self.owner, settings.POLLER_LEASE_TTL_SECONDS)
            except Exception as exc:
                logger.warning("poller_heartbeat_error", error=str(exc))
                continue
            if not ok:
                logger.warning("poller_lease_lost")
                return

    async def _bounded_investigation(self, alert: dict) -> None:
        async with self._semaphore:
            await self._investigate_alert(alert)

    async def _poll_loop(self):
        while self._running:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("alert_poller_error", error=str(e))

            try:
                await asyncio.sleep(max(1, min(self.interval_seconds, TICK_SECONDS)))
            except asyncio.CancelledError:
                break

    async def _investigate_alert(self, alert_data: dict):
        """Auto-investigate through the same pipeline and finalizer as analyst-started runs."""
        alert_id = alert_data.get("_id")
        logger.info("auto_investigating_alert", alert_id=alert_id)
        async for event in investigation_stream_manager.run_pipeline_stream(
            alert_id=alert_id,
            alert=alert_data,
            db=self.db,
            org_id=alert_data.get("org_id", "default"),
        ):
            if event["event"] in ("complete", "error"):
                logger.info("auto_investigation_finished", alert_id=alert_id, outcome=event["event"])

    def start(self):
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._poll_loop())
            logger.info("alert_poller_started", interval=self.interval_seconds)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        pending = list(self._tasks)
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        try:
            for name in {LEASE_NAME, *(lease_name(org) for org in self._next_run)}:
                await release_lease(self.db, name, self.owner)
        except Exception as e:
            logger.error("poller_lease_release_failed", error=str(e))
        logger.info("alert_poller_stopped")
