"""
SLA watcher and escalation monitor.

Sweeps open alerts against the tenant's SLA targets (services/sla.py) and applies the tenant's
escalation policy when a clock is breached: notify the channels, reassign to a named responder,
and/or mark the alert Escalated. Each action runs once per alert and breach, and is audited.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.logging import logger
from app.services.audit import record_audit
from app.services.cases import sync_all_tickets
from app.services.notifications import (
    NotificationEventType,
    NotificationPayload,
    ChannelConfig,
    notification_dispatcher,
)
from app.services.sla import get_escalation_policy, get_sla_targets
from app.services.triage import OPEN_STATUSES, TriageError, assign_alert, detected_at

UNASSIGNED_CRITICAL_THRESHOLD_MINUTES = 15
# Acting as the system: the monitor may assign to any active user, like a manager.
SYSTEM_ACTOR = {"id": "system", "email": "sla-monitor@forensiq", "role": "admin"}


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
    """Background periodic monitor that sweeps open alerts for SLA breaches and applies escalation policy."""

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
        last_ticket_sync = 0.0
        while self._running:
            try:
                await self.check_alerts_sla()
            except Exception as e:
                logger.error("sla_monitor_sweep_error", error=str(e))
            loop_time = asyncio.get_running_loop().time()
            if loop_time - last_ticket_sync >= settings.TICKET_SYNC_INTERVAL_SECONDS:
                last_ticket_sync = loop_time
                try:
                    await sync_all_tickets(self.db)
                except Exception as e:
                    logger.error("ticket_sync_sweep_error", error=str(e))
            await asyncio.sleep(self.interval)

    async def check_alerts_sla(self, now: Optional[datetime] = None) -> int:
        """One sweep over open alerts. Returns how many breaches were handled."""
        now = now or datetime.now(timezone.utc)
        targets_cache: dict = {}
        policy_cache: dict = {}
        handled = 0

        async for alert in self.db["alerts"].find({"status": {"$in": list(OPEN_STATUSES)}}):
            org_id = alert.get("org_id", "default")
            if org_id not in targets_cache:
                targets_cache[org_id] = await get_sla_targets(self.db, org_id)
                policy_cache[org_id] = await get_escalation_policy(self.db, org_id)
            severity = str(alert.get("severity") or "medium").lower()
            start = detected_at(alert)
            sev_targets = targets_cache[org_id].get(severity)
            if not start or not sev_targets:
                continue
            age_minutes = (now - start).total_seconds() / 60.0
            ack_target, resolve_target = sev_targets
            rules = policy_cache[org_id].get(severity, {})

            if (
                severity == "critical"
                and not alert.get("assignee_id")
                and age_minutes >= UNASSIGNED_CRITICAL_THRESHOLD_MINUTES
                and not alert.get("notified_unassigned_critical")
            ):
                await self._notify(
                    alert, org_id, NotificationEventType.UNASSIGNED_CRITICAL, alert.get("title", "Critical alert"),
                    f"Critical alert unassigned for {int(age_minutes)} minutes!", {"age_minutes": int(age_minutes)},
                )
                await self.db["alerts"].update_one({"_id": alert["_id"]}, {"$set": {"notified_unassigned_critical": True}})

            if not alert.get("acknowledged_at") and not alert.get("notified_sla_ack_breach") and age_minutes > ack_target:
                handled += await self._breach(
                    alert, org_id, "ack_breach", rules.get("ack_breach", {}), NotificationEventType.SLA_ACK_BREACH,
                    f"SLA Acknowledge Breached: {alert.get('title')}",
                    f"Alert has exceeded the {ack_target}m acknowledge SLA window ({int(age_minutes)}m elapsed).",
                    {"target_minutes": ack_target, "elapsed_minutes": int(age_minutes)},
                    {"notified_sla_ack_breach": True, "sla_ack_breached": True},
                )

            if not alert.get("resolved_at") and not alert.get("notified_sla_resolve_breach") and age_minutes > resolve_target:
                handled += await self._breach(
                    alert, org_id, "resolve_breach", rules.get("resolve_breach", {}), NotificationEventType.SLA_RESOLVE_BREACH,
                    f"SLA Resolve Breached: {alert.get('title')}",
                    f"Alert has exceeded the {resolve_target}m resolution SLA window ({int(age_minutes)}m elapsed).",
                    {"target_minutes": resolve_target, "elapsed_minutes": int(age_minutes)},
                    {"notified_sla_resolve_breach": True, "sla_resolve_breached": True},
                )
        return handled

    async def _notify(self, alert: dict, org_id: str, event: NotificationEventType, title: str, description: str, details: dict):
        payload = NotificationPayload(
            event_type=event,
            alert_id=str(alert["_id"]),
            title=title,
            severity=str(alert.get("severity") or "medium").lower(),
            host=alert.get("host"),
            user=alert.get("user"),
            rule_name=alert.get("rule_name"),
            assigned_to=alert.get("assignee_email"),
            description=description,
            details=details,
        )
        await notify_all_channels(self.db, payload, org_id)

    async def _breach(self, alert, org_id, kind, rule, event, title, description, details, flags) -> int:
        """Apply one breach's policy: notify, reassign, mark escalated. The flags make it once-only."""
        taken: dict = {}
        update = dict(flags)

        if rule.get("notify", True):
            await self._notify(alert, org_id, event, title, description, details)
            taken["notified"] = True

        target = rule.get("reassign_to")
        if target and target != alert.get("assignee_id"):
            try:
                await assign_alert(self.db, {**SYSTEM_ACTOR, "org_id": org_id}, str(alert["_id"]), target)
                taken["reassigned_to"] = target
            except TriageError as exc:
                taken["reassign_failed"] = exc.detail
                logger.warning("sla_reassign_failed", alert_id=str(alert["_id"]), reason=exc.detail)

        if rule.get("mark_escalated") and alert.get("status") != "Escalated":
            update.update({
                "status": "Escalated",
                "escalated_at": datetime.now(timezone.utc),
                "escalated_by": SYSTEM_ACTOR["email"],
                "escalated_reason": f"Automated escalation: {kind.replace('_', ' ')} (SLA policy)",
            })
            taken["escalated"] = True
            await self._notify(alert, org_id, NotificationEventType.ALERT_ESCALATED,
                               f"Alert Escalated: {alert.get('title')}", description, details)

        await self.db["alerts"].update_one({"_id": alert["_id"]}, {"$set": update})
        await record_audit(self.db, {**SYSTEM_ACTOR, "org_id": org_id}, f"alert.sla_{kind}", "alert", str(alert["_id"]), taken)
        return 1
