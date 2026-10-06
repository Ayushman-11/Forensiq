"""Tiny Mongo-backed lease so only one process runs the alert poller."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError


def _now() -> datetime:
    # Mongo returns naive UTC datetimes, so keep stored and compared values naive UTC.
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def acquire_lease(db, name: str, owner: str, ttl_seconds: int) -> bool:
    """True if `owner` now holds the lease (new, renewed, or taken over after expiry)."""
    now = _now()
    try:
        doc = await db["leases"].find_one_and_update(
            {"_id": name, "$or": [{"owner": owner}, {"expires_at": {"$lte": now}}]},
            {"$set": {"owner": owner, "expires_at": now + timedelta(seconds=ttl_seconds)}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
    except DuplicateKeyError:  # another owner holds an unexpired lease
        return False
    return bool(doc and doc.get("owner") == owner)


async def release_lease(db, name: str, owner: str) -> None:
    await db["leases"].delete_one({"_id": name, "owner": owner})
