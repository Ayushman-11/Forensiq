import asyncio
import time
import uuid

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.agents.graph import investigation_graph
from app.core.config import settings
from app.core.logging import logger
from app.core.metrics import (
    INVESTIGATION_COMPLETED_TOTAL,
    INVESTIGATION_DURATION_SECONDS,
    INVESTIGATION_FAILED_TOTAL,
    INVESTIGATION_QUEUE_DEPTH,
    INVESTIGATION_STARTED_TOTAL,
    POLLER_CYCLES_TOTAL,
    POLLER_IS_LEADER,
    POLLER_LEASE_LOST_TOTAL,
)
from app.services.ingestion import IngestionService
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
        acquired = await acquire_lease(self.db, LEASE_NAME, self.owner, settings.POLLER_LEASE_TTL_SECONDS)
        POLLER_IS_LEADER.set(1 if acquired else 0)
        if not acquired:
            logger.info("poller_lease_held_elsewhere")
            return 0

        hb = asyncio.create_task(self._heartbeat())
        try:
            service = IngestionService(self.db)  # fresh per cycle: counters and errors do not accumulate
            new_alerts = await service.fetch_and_store_alerts()
        finally:
            hb.cancel()
            await asyncio.gather(hb, return_exceptions=True)

        POLLER_CYCLES_TOTAL.inc()

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
                POLLER_LEASE_LOST_TOTAL.inc()
                POLLER_IS_LEADER.set(0)
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
        alert_id = alert_data.get("_id")
        logger.info("auto_investigating_alert", alert_id=alert_id)
        INVESTIGATION_STARTED_TOTAL.inc()
        INVESTIGATION_QUEUE_DEPTH.inc()
        _start = time.monotonic()
        try:
            await self.db["alerts"].update_one(
                {"_id": alert_id},
                {"$set": {"status": "Investigating"}},
            )

            initial_state = {
                "alert_data": alert_data,
                "extracted_iocs": alert_data.get("extracted_iocs", []),
                "enrichment_results": [],
                "ai_analysis": None,
                "risk_assessment": {},
                "mitre_mappings": [],
                "timeline": [],
                "recommendation": None,
            }

            final_state = await investigation_graph.ainvoke(initial_state)

            enrichments = final_state.get("enrichment_results", [])
            extracted_iocs = final_state.get("extracted_iocs", [])

            # Base confidence from severity
            severity_confidence = {
                "critical": 85,
                "high": 70,
                "medium": 55,
                "low": 35,
            }
            ai_confidence = severity_confidence.get(
                str(alert_data.get("severity", "medium")).lower(), 50
            )
            for e in enrichments:
                if e.get("reputation") == "malicious":
                    ai_confidence = min(99, ai_confidence + 15)
                elif e.get("reputation") == "suspicious":
                    ai_confidence = min(99, ai_confidence + 8)

            await self.db["alerts"].update_one(
                {"_id": alert_id},
                {
                    "$set": {
                        "status": "Investigated",
                        "ai_confidence": ai_confidence,
                        "enrichments": enrichments,
                        "extracted_iocs": extracted_iocs,
                        "risk_assessment": final_state.get("risk_assessment", {}),
                        "risk_score": final_state.get("risk_assessment", {}).get("risk_score", 0),
                        "priority": final_state.get("risk_assessment", {}).get("priority", "medium"),
                        "mitre_mappings": final_state.get("mitre_mappings", []),
                        "timeline": final_state.get("timeline", []),
                        "recommendation": final_state.get("recommendation"),
                    }
                },
            )
            duration = time.monotonic() - _start
            INVESTIGATION_DURATION_SECONDS.observe(duration)
            INVESTIGATION_COMPLETED_TOTAL.inc()
            logger.info(
                "auto_investigation_complete",
                alert_id=alert_id,
                confidence=ai_confidence,
                enrichments=len(enrichments),
                duration_seconds=round(duration, 2),
            )
        except Exception as e:
            INVESTIGATION_FAILED_TOTAL.inc()
            logger.error("auto_investigation_failed", alert_id=alert_id, error=str(e))
            await self.db["alerts"].update_one(
                {"_id": alert_id}, {"$set": {"status": "Investigation Failed"}}
            )
        finally:
            INVESTIGATION_QUEUE_DEPTH.dec()

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
