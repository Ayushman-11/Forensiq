import asyncio
import uuid

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.agents.graph import investigation_graph
from app.core.config import settings
from app.core.logging import logger
from app.services.ingestion import IngestionService
from app.services.lease import acquire_lease, release_lease
from app.services.notifications import (
    NotificationEventType,
    NotificationPayload,
)
from app.services.sla_monitor import notify_all_channels

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
        """One poll: take/renew the lease, ingest, schedule bounded auto-investigations, dispatch notifications."""
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
            # 1. Trigger notification immediately for new critical alerts
            if (alert.get("severity") or "").lower() == "critical":
                payload = NotificationPayload(
                    event_type=NotificationEventType.NEW_CRITICAL_ALERT,
                    alert_id=str(alert.get("_id")),
                    title=alert.get("title", "Critical Threat Detected"),
                    severity="critical",
                    host=alert.get("host"),
                    user=alert.get("user"),
                    rule_name=alert.get("rule_name"),
                    description=alert.get("description", ""),
                    assigned_to=alert.get("assigned_to"),
                )
                asyncio.create_task(notify_all_channels(self.db, payload, alert.get("org_id", "default")))

            # 2. Schedule bounded auto-investigation
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
                logger.error("poller_heartbeat_failed", error=str(exc))
                return
            if not ok:
                logger.error("poller_lost_lease_during_heartbeat")
                return

    async def _bounded_investigation(self, alert: dict) -> None:
        """Run one investigation under the concurrency limit."""
        async with self._semaphore:
            alert_id = alert.get("_id")
            job_id = str(uuid.uuid4())
            try:
                job_doc = {
                    "_id": job_id,
                    "alert_id": alert_id,
                    "org_id": alert.get("org_id", "default"),
                    "status": "running",
                    "trigger": "poller",
                    "steps": [],
                }
                await self.db["investigation_jobs"].insert_one(job_doc)
                await self.db["alerts"].update_one(
                    {"_id": alert_id},
                    {"$set": {"status": "Investigating"}},
                )

                state = {
                    "alert_id": alert_id,
                    "alert": alert,
                    "raw_events": alert.get("evidence", {}).get("raw_events", []),
                    "extracted_iocs": alert.get("extracted_iocs", []),
                    "mitre_mappings": [],
                    "correlations": [],
                    "timeline": [],
                    "risk_assessment": {},
                    "recommendation": "",
                    "errors": [],
                }
                final_state = await investigation_graph.ainvoke(state)

                update_fields = {
                    "status": "Investigated",
                    "recommendation": final_state.get("recommendation"),
                    "risk_score": final_state.get("risk_assessment", {}).get("score"),
                    "risk_assessment": final_state.get("risk_assessment"),
                    "mitre_mappings": final_state.get("mitre_mappings"),
                    "timeline": final_state.get("timeline"),
                    "correlations": final_state.get("correlations"),
                }
                await self.db["alerts"].update_one(
                    {"_id": alert_id},
                    {"$set": update_fields},
                )
                await self.db["investigation_jobs"].update_one(
                    {"_id": job_id},
                    {"$set": {"status": "completed", "result": update_fields}},
                )
            except Exception as exc:
                logger.error("poller_investigation_failed", alert_id=alert_id, error=str(exc))
                await self.db["alerts"].update_one(
                    {"_id": alert_id},
                    {"$set": {"status": "Investigation Failed"}},
                )
                await self.db["investigation_jobs"].update_one(
                    {"_id": job_id},
                    {"$set": {"status": "failed", "error": str(exc)}},
                )

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        # Drain active investigations
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks.clear()
        try:
            await release_lease(self.db, LEASE_NAME, self.owner)
        except Exception as exc:
            logger.error("poller_release_lease_failed", error=str(exc))

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._run_cycle()
            except Exception as exc:
                logger.error("poller_cycle_failed", error=str(exc))
            await asyncio.sleep(self.interval_seconds)
