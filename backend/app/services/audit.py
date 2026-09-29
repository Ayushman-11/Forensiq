from datetime import datetime, timezone
from uuid import uuid4

async def record_audit(db, user: dict | None, action: str, entity_type: str, entity_id: str, metadata: dict | None = None):
    await db["audit_logs"].insert_one({
        "_id": str(uuid4()),
        "org_id": (user or {}).get("org_id", "default"),
        "actor_id": str((user or {}).get("_id", "system")),
        "actor_email": (user or {}).get("email", "system"),
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "metadata": metadata or {},
        "created_at": datetime.now(timezone.utc),
    })
