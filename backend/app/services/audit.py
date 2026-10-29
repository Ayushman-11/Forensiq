"""
Audit trail service for Forensiq.
Enforces append-only immutable recording, indexing, and compliance export.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.config import settings
from app.core.tenancy import scoped_query


async def record_audit(
    db,
    user: dict | None,
    action: str,
    entity_type: str,
    entity_id: str,
    metadata: dict | None = None,
) -> dict:
    """
    Append-only insertion into audit_logs.
    Audit log entries are immutable once written.
    """
    actor_id = str((user or {}).get("id") or (user or {}).get("_id") or "system")
    actor_email = (user or {}).get("email", "system")
    org_id = (user or {}).get("org_id", "default")

    entry = {
        "_id": str(uuid4()),
        "org_id": org_id,
        "actor_id": actor_id,
        "actor_email": actor_email,
        "action": action,
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "metadata": metadata or {},
        "created_at": datetime.now(timezone.utc),
    }

    await db["audit_logs"].insert_one(entry)
    try:
        from app.services.events import emit_audit_event  # late import: events record their own audit entries

        await emit_audit_event(db, entry)
    except Exception as exc:  # an event that cannot be queued must never undo or fail the audited action
        from app.core.logging import logger

        logger.error("audit_event_emit_failed", action=action, error=str(exc))
    return entry


async def get_audit_trail(
    db,
    user: dict | None,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    limit: int = 100,
    skip: int = 0,
) -> List[dict]:
    """Retrieves tenant-scoped audit trail for an entity or collection."""
    conditions = []
    if entity_type:
        conditions.append({"entity_type": entity_type})
    if entity_id:
        conditions.append({"entity_id": str(entity_id)})

    query = scoped_query(user, *conditions) if conditions else scoped_query(user)
    cursor = db["audit_logs"].find(query).sort("created_at", -1).skip(skip).limit(limit)
    return [doc async for doc in cursor]


async def export_audit_logs(
    db,
    user: dict | None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 5000,
) -> List[dict]:
    """Exports audit logs for external SIEM / S3 object lock compliance storage."""
    conditions = []
    if start_time:
        conditions.append({"created_at": {"$gte": start_time}})
    if end_time:
        conditions.append({"created_at": {"$lte": end_time}})

    query = scoped_query(user, *conditions) if conditions else scoped_query(user)
    cursor = db["audit_logs"].find(query).sort("created_at", 1).limit(limit)
    logs = []
    async for entry in cursor:
        entry["_id"] = str(entry["_id"])
        if isinstance(entry.get("created_at"), datetime):
            entry["created_at"] = entry["created_at"].isoformat()
        logs.append(entry)
    return logs
