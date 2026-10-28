from datetime import UTC, datetime
from uuid import uuid4

from app.core.tenancy import scoped_query


async def record_audit(
    db,
    user: dict | None,
    action: str,
    entity_type: str,
    entity_id: str,
    metadata: dict | None = None,
):
    entry = {
        "_id": str(uuid4()),
        "org_id": (user or {}).get("org_id", "default"),
        "actor_id": str((user or {}).get("id") or (user or {}).get("_id") or "system"),
        "actor_email": (user or {}).get("email", "system"),
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "metadata": metadata or {},
        "created_at": datetime.now(UTC),
    }
    await db["audit_logs"].insert_one(entry)
    return entry


async def get_audit_trail(
    db,
    user: dict | None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    action: str | None = None,
    limit: int = 100,
) -> list[dict]:
    filters: list[dict] = []
    if entity_type:
        filters.append({"entity_type": entity_type})
    if entity_id:
        filters.append({"entity_id": entity_id})
    if action:
        filters.append({"action": action})

    cursor = db["audit_logs"].find(scoped_query(user, *filters)).sort("created_at", -1).limit(limit)
    return [doc async for doc in cursor]


async def export_audit_logs(
    db,
    user: dict | None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = 1000,
) -> list[dict]:
    filters: list[dict] = []
    if start_time or end_time:
        time_query: dict = {}
        if start_time:
            time_query["$gte"] = start_time
        if end_time:
            time_query["$lte"] = end_time
        filters.append({"created_at": time_query})

    cursor = db["audit_logs"].find(scoped_query(user, *filters)).sort("created_at", -1).limit(limit)
    return [doc async for doc in cursor]
