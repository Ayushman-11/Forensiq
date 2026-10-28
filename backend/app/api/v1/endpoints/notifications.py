"""
Notification channel management and manual trigger endpoints.
"""

from typing import List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field

from app.database.session import get_db
from app.api.deps import require_roles
from app.core.tenancy import scoped_query, tenant_id
from app.services.notifications import (
    ChannelConfig,
    NotificationChannelType,
    NotificationEventType,
    NotificationPayload,
    notification_dispatcher,
)
from app.services.sla_monitor import notify_all_channels

router = APIRouter()
admin_required = require_roles("admin", "senior_analyst")


class CreateChannelRequest(BaseModel):
    name: str
    channel_type: NotificationChannelType
    enabled: bool = True
    webhook_url: Optional[str] = None
    routing_key: Optional[str] = None
    api_key: Optional[str] = None
    email_recipients: List[str] = Field(default_factory=list)
    min_severity: str = "medium"
    subscribed_events: List[NotificationEventType] = Field(default_factory=lambda: [
        NotificationEventType.NEW_CRITICAL_ALERT,
        NotificationEventType.SLA_ACK_BREACH,
        NotificationEventType.SLA_RESOLVE_BREACH,
        NotificationEventType.UNASSIGNED_CRITICAL,
        NotificationEventType.ALERT_ESCALATED,
    ])
    roles: List[str] = Field(default_factory=lambda: ["admin", "senior_analyst", "analyst"])
    quiet_hours_enabled: bool = False
    quiet_hours_start_utc: str = "22:00"
    quiet_hours_end_utc: str = "07:00"
    bypass_quiet_hours_for_critical: bool = True


class TestChannelRequest(BaseModel):
    channel_id: Optional[str] = None


@router.get("/channels", response_model=List[ChannelConfig])
async def list_channels(
    admin_user: dict = Depends(admin_required),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Lists all configured notification channels for tenant."""
    org = tenant_id(admin_user)
    cursor = db["notification_channels"].find({"org_id": org})
    channels = []
    async for doc in cursor:
        doc["id"] = str(doc.get("_id", doc.get("id")))
        channels.append(ChannelConfig(**doc))
    return channels


@router.post("/channels", response_model=ChannelConfig, status_code=status.HTTP_201_CREATED)
async def create_channel(
    req: CreateChannelRequest,
    admin_user: dict = Depends(admin_required),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Creates a new notification channel (Slack, Teams, PagerDuty, Opsgenie, Email)."""
    org = tenant_id(admin_user)
    channel_id = str(uuid.uuid4())
    doc = req.model_dump()
    doc["_id"] = channel_id
    doc["id"] = channel_id
    doc["org_id"] = org
    doc["created_by"] = admin_user["id"]

    await db["notification_channels"].insert_one(doc)
    return ChannelConfig(**doc)


@router.delete("/channels/{channel_id}")
async def delete_channel(
    channel_id: str,
    admin_user: dict = Depends(admin_required),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Deletes a notification channel."""
    org = tenant_id(admin_user)
    res = await db["notification_channels"].delete_one({"_id": channel_id, "org_id": org})
    if not res.deleted_count:
        raise HTTPException(status_code=404, detail="Channel not found")
    return {"status": "deleted", "channel_id": channel_id}


@router.post("/test")
async def test_notification(
    req: TestChannelRequest,
    admin_user: dict = Depends(admin_required),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Sends a synthetic test alert through notification channels."""
    org = tenant_id(admin_user)
    test_payload = NotificationPayload(
        event_type=NotificationEventType.NEW_CRITICAL_ALERT,
        alert_id=f"TEST-{uuid.uuid4().hex[:6].upper()}",
        title="Test Notification: Active Ransomware Emulation / Mimikatz Execution",
        severity="critical",
        host="FINANCE-SRV-01",
        user="SYSTEM",
        rule_name="mimikatz_lsass_dump",
        description="This is a test notification from the Forensiq SOC Notification Engine.",
        assigned_to=admin_user.get("email"),
    )

    if req.channel_id:
        doc = await db["notification_channels"].find_one({"_id": req.channel_id, "org_id": org})
        if not doc:
            raise HTTPException(status_code=404, detail="Notification channel not found")
        doc["id"] = str(doc.get("_id", doc.get("id")))
        channel = ChannelConfig(**doc)
        success = await notification_dispatcher.dispatch(test_payload, channel)
        return {"status": "dispatched" if success else "failed", "channel": channel.name}

    await notify_all_channels(db, test_payload, org)
    return {"status": "dispatched_all"}

