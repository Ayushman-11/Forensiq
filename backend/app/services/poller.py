import asyncio
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.services.ingestion import IngestionService
from app.agents.graph import investigation_graph
from app.core.logging import logger


class AlertPoller:
    def __init__(self, db: AsyncIOMotorDatabase, interval_seconds: int = 30):
        self.db = db
        self.interval_seconds = interval_seconds
        self._running = False
        self._task = None

    async def _poll_loop(self):
        service = IngestionService(self.db)
        while self._running:
            try:
                new_alerts = await service.fetch_and_store_alerts()

                if new_alerts:
                    logger.info(
                        "poller_new_alerts",
                        count=len(new_alerts),
                        rules={a.get("rule_name") for a in new_alerts},
                    )
                    for alert in new_alerts:
                        asyncio.create_task(self._investigate_alert(alert))
                else:
                    logger.info("poller_no_new_alerts")

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
                    }
                },
            )
            logger.info(
                "auto_investigation_complete",
                alert_id=alert_id,
                confidence=ai_confidence,
                enrichments=len(enrichments),
            )
        except Exception as e:
            logger.error("auto_investigation_failed", alert_id=alert_id, error=str(e))
            await self.db["alerts"].update_one(
                {"_id": alert_id}, {"$set": {"status": "Investigation Failed"}}
            )

    def start(self):
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._poll_loop())
            logger.info("alert_poller_started", interval=self.interval_seconds)

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
        logger.info("alert_poller_stopped")
