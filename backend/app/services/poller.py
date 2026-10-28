import asyncio
import uuid

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.logging import logger
from app.services.ingestion import IngestionService
from app.services.investigation_streamer import investigation_stream_manager
from app.services.lease import acquire_lease, release_lease

LEASE_NAME = "alert_poller"


class AlertPoller:
    def __init__(self, db: AsyncIOMotorDatabase, interval_seconds: int = 30):
        self.db = db
        self.interval_seconds = interval_seconds
        self.owner = str(uuid.uuid4())
        self._running = False
        self._task = None
        self._tasks: set = set()
        self._semaphore = asyncio.Semaphore(settings.INVESTIGATION_CONCURRENCY)

    async def _run_cycle(self) -> int:
        """One poll: take/renew the lease, ingest, schedule bounded auto-investigations."""
        if not await acquire_lease(self.db, LEASE_NAME, self.owner, settings.POLLER_LEASE_TTL_SECONDS):
            logger.info("poller_lease_held_elsewhere")
            return 0

        hb = asyncio.create_task(self._heartbeat())
        try:
            service = IngestionService(self.db)  # fresh per cycle: counters and errors do not accumulate
            new_alerts = await service.fetch_and_store_alerts()
        finally:
            hb.cancel()
            await asyncio.gather(hb, return_exceptions=True)
        if not new_alerts:
            logger.info("poller_no_new_alerts")
            return 0

        logger.info("poller_new_alerts", count=len(new_alerts), rules=sorted({a.get("rule_name") for a in new_alerts}))
        for alert in new_alerts:
            task = asyncio.create_task(self._bounded_investigation(alert))
            self._tasks.add(task)  # keep a reference so the task is not garbage-collected
            task.add_done_callback(self._on_investigation_done)
        return len(new_alerts)

    def _on_investigation_done(self, task) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception():
            logger.error("auto_investigation_task_failed", error=str(task.exception()))

    async def _heartbeat(self) -> None:
        """Renew the lease while a cycle runs so a slow cycle cannot lose it."""
        while True:
            await asyncio.sleep(settings.POLLER_LEASE_TTL_SECONDS / 3)
            try:
                ok = await acquire_lease(self.db, LEASE_NAME, self.owner, settings.POLLER_LEASE_TTL_SECONDS)
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
                await self._run_cycle()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("alert_poller_error", error=str(e))

            try:
                await asyncio.sleep(self.interval_seconds)
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
            await release_lease(self.db, LEASE_NAME, self.owner)
        except Exception as e:
            logger.error("poller_lease_release_failed", error=str(e))
        logger.info("alert_poller_stopped")
