"""
SLA Watcher and Escalation Background Monitor.
Monitors alerts for:
1. New critical alerts
2. Unacknowledged / Unassigned critical alerts after N minutes (e.g. 15 mins)
3. SLA Acknowledge breach (e.g. Critical: 15m, High: 30m, Medium: 2h)
4. SLA Resolve breach (e.g. Critical: 2h, High: 8h, Medium: 24h)
5. Automatic alert escalation upon critical SLA timeout
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.logging import logger
from app.services.notifications import (
    NotificationEventType,
    NotificationPayload,
    ChannelConfig,
    notification_dispatcher,
)

# Standard SLA target windows (minutes)
SLA_ACK_TARGETS = {
    "critical": 15,
    "high": 30,
    "medium": 120,
    "low": 480,
}

SLA_RESOLVE_TARGETS = {
    "critical": 120, # 2 hours
    "high": 480, # 8 hours
    "medium": 1440, # 24 hours
    "low": 2880, # 48 hours
}

UNASSIGNED_CRITICAL_THRESHOLD_MINUTES = 15


async def get_active_channels(db: AsyncIOMotorDatabase, org_id: str = "default") -> List[ChannelConfig]:
    """Retrieves configured notification channels from MongoDB."""
    cursor = db["notification_channels"].find({"org_id": org_id, "enabled": True})
    channels = []
    async for doc in cursor:
        doc["id"] = str(doc.get("_id", doc.get("id")))
        channels.append(ChannelConfig(**doc))
    return channels


async def notify_all_channels(
    db: AsyncIOMotorDatabase,
    payload: NotificationPayload,
    org_id: str = "default",
):
    """Fans out notification payload across all matching enabled channels in tenant."""
    channels = await get_active_channels(db, org_id)
    if not channels:
        logger.info("no_active_notification_channels", org_id=org_id, event=payload.event_type.value)
        return

    tasks = [notification_dispatcher.dispatch(payload, ch) for ch in channels]
    await asyncio.gather(*tasks, return_exceptions=True)


class SLAEscalationMonitor:
    """
    Background periodic monitor that sweeps open alerts to detect SLA breaches,
    unassigned critical risks, and triggers escalations.
    """

    def __init__(self, db: AsyncIOMotorDatabase, sweep_interval_seconds: int = 60):
        self.db = db
        self.interval = sweep_interval_seconds
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def start(self):
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._monitor_loop())
            logger.info("sla_escalation_monitor_started", interval=self.interval)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
            logger.info("sla_escalation_monitor_stopped")

    async def _monitor_loop(self):
        while self._running:
            try:
                await self.check_alerts_sla()
            except Exception as e:
                logger.error("sla_monitor_sweep_error", error=str(e))
            await asyncio.sleep(self.interval)

    async def check_alerts_sla(self):
        """Scans all non-terminal alerts for SLA breaches and unassigned critical alerts."""
        now = datetime.now(timezone.utc)
        open_statuses = ["New", "Investigating", "Investigated"]
        
        cursor = self.db["alerts"].find({
            "status": {"$in": open_statuses}
        })

        async for alert in cursor:
            alert_id = str(alert["_id"])
            org_id = alert.get("org_id", "default")
            severity = (alert.get("severity") or "medium").lower()
            assigned_to = alert.get("assigned_to")

            # Parse created_at timestamp
            created_at = alert.get("created_at")
            if isinstance(created_at, str):
                try:
                    created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                except Exception:
                    created_dt = now
            elif isinstance(created_at, datetime):
                created_dt = created_at if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)
            else:
                created_dt = now

            age_minutes = (now - created_dt).total_seconds() / 60.0

            # 1. Check Unassigned Critical alert
            if severity == "critical" and not assigned_to:
                if age_minutes >= UNASSIGNED_CRITICAL_THRESHOLD_MINUTES and not alert.get("notified_unassigned_critical"):
                    payload = NotificationPayload(
                        event_type=NotificationEventType.UNASSIGNED_CRITICAL,
                        alert_id=alert_id,
                        title=alert.get("title", "Critical Alert"),
                        severity="critical",
                        host=alert.get("host"),
                        user=alert.get("user"),
                        rule_name=alert.get("rule_name"),
                        description=f"Critical alert unassigned for {int(age_minutes)} minutes!",
                        details={"age_minutes": int(age_minutes)},
                    )
                    await notify_all_channels(self.db, payload, org_id)
                    await self.db["alerts"].update_one(
                        {"_id": alert["_id"]},
                        {"$set": {"notified_unassigned_critical": True}}
                    )

            # 2. Check SLA Acknowledge breach
            ack_target = SLA_ACK_TARGETS.get(severity, 60)
            if not alert.get("acknowledged_at") and not alert.get("notified_sla_ack_breach"):
                if age_minutes > ack_target:
                    payload = NotificationPayload(
                        event_type=NotificationEventType.SLA_ACK_BREACH,
                        alert_id=alert_id,
                        title=f"SLA Acknowledge Breached: {alert.get('title')}",
                        severity=severity,
                        host=alert.get("host"),
                        user=alert.get("user"),
                        rule_name=alert.get("rule_name"),
                        assigned_to=assigned_to,
                        description=f"Alert has exceeded the {ack_target}m acknowledge SLA window ({int(age_minutes)}m elapsed).",
                        details={"target_minutes": ack_target, "elapsed_minutes": int(age_minutes)},
                    )
                    await notify_all_channels(self.db, payload, org_id)
                    await self.db["alerts"].update_one(
                        {"_id": alert["_id"]},
                        {"$set": {"notified_sla_ack_breach": True, "sla_ack_breached": True}}
                    )

            # 3. Check SLA Resolve breach
            resolve_target = SLA_RESOLVE_TARGETS.get(severity, 480)
            if not alert.get("resolved_at") and not alert.get("notified_sla_resolve_breach"):
                if age_minutes > resolve_target:
                    payload = NotificationPayload(
                        event_type=NotificationEventType.SLA_RESOLVE_BREACH,
                        alert_id=alert_id,
                        title=f"SLA Resolve Breached: {alert.get('title')}",
                        severity=severity,
                        host=alert.get("host"),
                        user=alert.get("user"),
                        rule_name=alert.get("rule_name"),
                        assigned_to=assigned_to,
                        description=f"Alert has exceeded the {resolve_target}m resolution SLA window ({int(age_minutes)}m elapsed). Escalating.",
                        details={"target_minutes": resolve_target, "elapsed_minutes": int(age_minutes)},
                    )
                    await notify_all_channels(self.db, payload, org_id)
                    
                    # Automatically escalate critical alerts on resolve breach
                    update_dict = {"notified_sla_resolve_breach": True, "sla_resolve_breached": True}
                    if severity == "critical" and alert.get("status") != "Escalated":
                        update_dict["status"] = "Escalated"
                        update_dict["escalated_reason"] = "Automated escalation: Critical resolution SLA breached"

                    await self.db["alerts"].update_one(
                        {"_id": alert["_id"]},
                        {"$set": update_dict}
                    )

