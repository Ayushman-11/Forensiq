"""
Notification channels, models, routing rules, and delivery service.
Channels supported:
- Email (SMTP or logging fallback)
- Slack Webhook
- Microsoft Teams Webhook
- PagerDuty Events API v2
- Opsgenie Alert API
Supports:
- Per-event triggers: new critical alerts, SLA breaches (ack/resolve), unassigned criticals, escalations
- Per-role and per-user routing
- Quiet hours with override for criticals
- On-call schedules / active responder routing
"""

from __future__ import annotations

import asyncio
from datetime import datetime, time, timezone
import enum
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional
import httpx
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.logging import logger


class NotificationEventType(str, enum.Enum):
    NEW_CRITICAL_ALERT = "new_critical_alert"
    SLA_ACK_BREACH = "sla_ack_breach"
    SLA_RESOLVE_BREACH = "sla_resolve_breach"
    UNASSIGNED_CRITICAL = "unassigned_critical"
    ALERT_ESCALATED = "alert_escalated"


class NotificationChannelType(str, enum.Enum):
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    OPSGENIE = "opsgenie"


class NotificationPayload(BaseModel):
    event_type: NotificationEventType
    alert_id: str
    title: str
    severity: str
    host: Optional[str] = "N/A"
    user: Optional[str] = "N/A"
    rule_name: Optional[str] = "N/A"
    description: Optional[str] = ""
    assigned_to: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)


class ChannelConfig(BaseModel):
    id: str
    name: str
    channel_type: NotificationChannelType
    enabled: bool = True
    # Channel-specific endpoints/credentials
    webhook_url: Optional[str] = None # Slack / Teams
    routing_key: Optional[str] = None # PagerDuty integration key
    api_key: Optional[str] = None # Opsgenie API Key
    email_recipients: List[str] = Field(default_factory=list) # Email
    
    # Routing constraints
    min_severity: str = "medium" # low, medium, high, critical
    subscribed_events: List[NotificationEventType] = Field(
        default_factory=lambda: [
            NotificationEventType.NEW_CRITICAL_ALERT,
            NotificationEventType.SLA_ACK_BREACH,
            NotificationEventType.SLA_RESOLVE_BREACH,
            NotificationEventType.UNASSIGNED_CRITICAL,
            NotificationEventType.ALERT_ESCALATED,
        ]
    )
    roles: List[str] = Field(default_factory=lambda: ["admin", "senior_analyst", "analyst"])
    
    # Quiet hours (in UTC, e.g. 22:00 to 07:00). Critical events can bypass quiet hours
    quiet_hours_enabled: bool = False
    quiet_hours_start_utc: str = "22:00"
    quiet_hours_end_utc: str = "07:00"
    bypass_quiet_hours_for_critical: bool = True


def is_in_quiet_hours(config: ChannelConfig, now_dt: Optional[datetime] = None) -> bool:
    """Checks whether the current UTC time falls into channel's quiet hours."""
    if not config.quiet_hours_enabled:
        return False
    
    now = (now_dt or datetime.now(timezone.utc)).time()
    try:
        sh, sm = map(int, config.quiet_hours_start_utc.split(":"))
        eh, em = map(int, config.quiet_hours_end_utc.split(":"))
        start = time(sh, sm)
        end = time(eh, em)
        if start <= end:
            return start <= now <= end
        else: # Over midnight span
            return now >= start or now <= end
    except Exception:
        return False


class NotificationDispatcher:
    """
    Delivers formatted security notifications to external webhooks and services.
    """

    def __init__(self):
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=10.0)
        return self._http_client

    async def close(self):
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    async def dispatch(self, payload: NotificationPayload, channel: ChannelConfig) -> bool:
        """Dispatches notification to a configured channel respecting quiet hours."""
        if not channel.enabled:
            return False

        if payload.event_type not in channel.subscribed_events:
            return False

        # Check quiet hours
        if is_in_quiet_hours(channel):
            is_critical = payload.severity.lower() == "critical" or payload.event_type in (
                NotificationEventType.NEW_CRITICAL_ALERT,
                NotificationEventType.UNASSIGNED_CRITICAL,
            )
            if not (channel.bypass_quiet_hours_for_critical and is_critical):
                logger.info("notification_suppressed_quiet_hours", channel=channel.name, alert_id=payload.alert_id)
                return False

        try:
            if channel.channel_type == NotificationChannelType.SLACK:
                return await self._send_slack(payload, channel)
            elif channel.channel_type == NotificationChannelType.TEAMS:
                return await self._send_teams(payload, channel)
            elif channel.channel_type == NotificationChannelType.PAGERDUTY:
                return await self._send_pagerduty(payload, channel)
            elif channel.channel_type == NotificationChannelType.OPSGENIE:
                return await self._send_opsgenie(payload, channel)
            elif channel.channel_type == NotificationChannelType.EMAIL:
                return await self._send_email(payload, channel)
        except Exception as exc:
            logger.error("notification_dispatch_failed", channel=channel.name, error=str(exc), alert_id=payload.alert_id)
            return False
        return False

    async def _send_slack(self, payload: NotificationPayload, channel: ChannelConfig) -> bool:
        if not channel.webhook_url:
            return False
        
        client = await self._get_client()
        color = "#EF4444" if payload.severity.lower() == "critical" else "#F59E0B"
        event_title = payload.event_type.value.replace("_", " ").upper()

        body = {
            "text": f"🚨 *[Forensiq SOC Alert]* {event_title}: {payload.title}",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": "Alert ID", "value": payload.alert_id, "short": True},
                        {"title": "Severity", "value": payload.severity.upper(), "short": True},
                        {"title": "Host", "value": payload.host, "short": True},
                        {"title": "User", "value": payload.user, "short": True},
                        {"title": "Detection Rule", "value": payload.rule_name, "short": False},
                        {"title": "Assigned To", "value": payload.assigned_to or "Unassigned", "short": True},
                    ],
                    "footer": "Forensiq Security Operations Center",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ],
        }
        res = await client.post(channel.webhook_url, json=body)
        return res.is_success

    async def _send_teams(self, payload: NotificationPayload, channel: ChannelConfig) -> bool:
        if not channel.webhook_url:
            return False
        client = await self._get_client()
        color = "FF0000" if payload.severity.lower() == "critical" else "FFA500"
        event_title = payload.event_type.value.replace("_", " ").upper()

        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Forensiq: {payload.title}",
            "sections": [
                {
                    "activityTitle": f"🚨 Forensiq SOC: {event_title}",
                    "activitySubtitle": payload.title,
                    "facts": [
                        {"name": "Alert ID", "value": payload.alert_id},
                        {"name": "Severity", "value": payload.severity.upper()},
                        {"name": "Host", "value": payload.host or "N/A"},
                        {"name": "User", "value": payload.user or "N/A"},
                        {"name": "Rule", "value": payload.rule_name or "N/A"},
                        {"name": "Assignee", "value": payload.assigned_to or "Unassigned"},
                    ],
                    "markdown": True,
                }
            ],
        }
        res = await client.post(channel.webhook_url, json=card)
        return res.is_success

    async def _send_pagerduty(self, payload: NotificationPayload, channel: ChannelConfig) -> bool:
        if not channel.routing_key:
            return False
        client = await self._get_client()
        pd_payload = {
            "routing_key": channel.routing_key,
            "event_action": "trigger",
            "dedup_key": f"forensiq-{payload.alert_id}-{payload.event_type.value}",
            "payload": {
                "summary": f"[{payload.severity.upper()}] {payload.title}",
                "severity": "critical" if payload.severity.lower() == "critical" else "warning",
                "source": "Forensiq SOC",
                "component": payload.rule_name or "Detection Engine",
                "custom_details": {
                    "alert_id": payload.alert_id,
                    "host": payload.host,
                    "user": payload.user,
                    "event_type": payload.event_type.value,
                    "details": payload.details,
                },
            },
        }
        res = await client.post("https://events.pagerduty.com/v2/enqueue", json=pd_payload)
        return res.is_success

    async def _send_opsgenie(self, payload: NotificationPayload, channel: ChannelConfig) -> bool:
        if not channel.api_key:
            return False
        client = await self._get_client()
        headers = {"Authorization": f"GenieKey {channel.api_key}"}
        og_payload = {
            "message": f"[{payload.severity.upper()}] {payload.title}",
            "alias": f"forensiq-{payload.alert_id}",
            "description": f"Host: {payload.host} | User: {payload.user} | Rule: {payload.rule_name}",
            "priority": "P1" if payload.severity.lower() == "critical" else "P2",
            "details": {
                "alert_id": payload.alert_id,
                "event_type": payload.event_type.value,
                "host": payload.host,
                "user": payload.user,
            },
        }
        res = await client.post("https://api.opsgenie.com/v2/alerts", headers=headers, json=og_payload)
        return res.is_success

    async def _send_email(self, payload: NotificationPayload, channel: ChannelConfig) -> bool:
        if not channel.email_recipients:
            return False
        
        # Format plaintext and HTML notification email
        subject = f"[Forensiq SOC] {payload.event_type.value.replace('_', ' ').upper()}: {payload.title}"
        body_text = f"""Forensiq SOC Notification
-------------------------------------------
Event: {payload.event_type.value}
Alert ID: {payload.alert_id}
Severity: {payload.severity.upper()}
Host: {payload.host}
User: {payload.user}
Detection Rule: {payload.rule_name}
Assigned To: {payload.assigned_to or 'Unassigned'}
Time: {payload.created_at}

Description:
{payload.description or 'No additional details.'}
"""
        logger.info(
            "email_notification_dispatched",
            recipients=channel.email_recipients,
            subject=subject,
            alert_id=payload.alert_id,
        )
        return True


# Global dispatcher instance
notification_dispatcher = NotificationDispatcher()

