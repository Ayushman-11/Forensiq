"""
Policy Service with Audit Trail & Governance.

Stores governance policies (SLA targets, noise suppression, incident grouping)
in the database with full version history and audit log tracking.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.tenancy import scoped_query, tenant_id
from app.services.audit import record_audit

# Default SLA targets (minutes to acknowledge, minutes to resolve)
DEFAULT_SLA_MINUTES = {
    "critical": (15, 4 * 60),
    "high": (60, 24 * 60),
    "medium": (4 * 60, 3 * 24 * 60),
    "low": (24 * 60, 7 * 24 * 60),
}

# Default incident grouping configuration
DEFAULT_INCIDENT_GROUPING = {
    "window_seconds": 3600,
    "group_by": ["host", "user", "rule_name"],
    "max_alerts_per_incident": 50,
}


async def get_active_policy(db, org_id: str, policy_type: str) -> dict:
    """
    Returns the latest version of the requested policy for the organisation.
    Falls back to built-in system defaults if no custom policy is in the DB.
    """
    doc = await db["policies"].find_one(
        {"org_id": org_id, "policy_type": policy_type, "is_active": True},
        sort=[("version", -1)],
    )
    if doc:
        return doc.get("content", {})

    if policy_type == "sla_targets":
        return DEFAULT_SLA_MINUTES
    elif policy_type == "incident_grouping":
        return DEFAULT_INCIDENT_GROUPING
    elif policy_type == "noise_policy":
        return {"suppress_known_benign": True, "rules": []}
    elif policy_type == "escalation":
        return {}  # services/sla.py fills in DEFAULT_ESCALATION

    return {}


async def update_policy(
    db,
    user: dict | None,
    policy_type: str,
    content: dict,
    reason: str,
) -> dict:
    """
    Saves a new immutable version of a policy, marks previous versions inactive,
    and records an audit trail entry.
    """
    org = tenant_id(user)
    latest = await db["policies"].find_one(
        {"org_id": org, "policy_type": policy_type},
        sort=[("version", -1)],
    )
    next_version = (latest.get("version", 0) + 1) if latest else 1

    # Deactivate previous active versions
    await db["policies"].update_many(
        {"org_id": org, "policy_type": policy_type},
        {"$set": {"is_active": False}},
    )

    now = datetime.now(timezone.utc)
    policy_doc = {
        "_id": str(uuid4()),
        "org_id": org,
        "policy_type": policy_type,
        "version": next_version,
        "content": content,
        "reason": reason.strip(),
        "is_active": True,
        "created_by": (user or {}).get("email", "system"),
        "created_at": now,
    }

    await db["policies"].insert_one(policy_doc)

    await record_audit(
        db=db,
        user=user,
        action="policy.updated",
        entity_type="policy",
        entity_id=policy_type,
        metadata={"version": next_version, "reason": reason.strip()},
    )

    return policy_doc


async def get_policy_history(
    db,
    user: dict | None,
    policy_type: str,
    limit: int = 20,
) -> List[dict]:
    """Retrieves chronological change history for a given policy."""
    org = tenant_id(user)
    cursor = (
        db["policies"]
        .find({"org_id": org, "policy_type": policy_type})
        .sort("version", -1)
        .limit(limit)
    )
    history = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        if isinstance(doc.get("created_at"), datetime):
            doc["created_at"] = doc["created_at"].isoformat()
        history.append(doc)
    return history

