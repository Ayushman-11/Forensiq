from datetime import UTC, datetime
from uuid import uuid4


async def record_audit(
    db,
    user: dict | None,
    action: str,
    entity_type: str,
    entity_id: str,
    metadata: dict | None = None,
) -> dict:
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
    *,
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = 100,
) -> list[dict]:
    query = {"org_id": (user or {}).get("org_id", "default")}
    if entity_type is not None:
        query["entity_type"] = entity_type
    if entity_id is not None:
        query["entity_id"] = entity_id

    cursor = db["audit_logs"].find(query).sort("created_at", -1).limit(limit)
    entries: list[dict] = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        entries.append(doc)
    return entries


async def export_audit_logs(
    db,
    user: dict | None,
    *,
    limit: int = 1000,
) -> list[dict]:
    return await get_audit_trail(db, user, limit=limit)
