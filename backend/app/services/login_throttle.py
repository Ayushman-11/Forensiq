"""Mongo-backed login throttle keyed by (email, client IP). Documents expire via a TTL index on `expires_at`."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from pymongo import ReturnDocument

from app.core.config import settings

COLLECTION = "login_attempts"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # Mongo returns naive UTC


def throttle_key(email: str, ip: str) -> str:
    return hashlib.sha256(f"{email.strip().lower()}|{ip}".encode()).hexdigest()


async def reserve_attempt(db, key: str) -> int:
    """Atomically count this attempt. Returns 0 when allowed, else seconds until the window ends.

    The window is fixed from the first attempt (expires_at is set only on insert), so locked
    requests never extend it. Counting before verification closes the check-then-act race.
    """
    now = _now()
    # The TTL monitor runs about once a minute, so drop an expired window explicitly.
    await db[COLLECTION].delete_one({"_id": key, "expires_at": {"$lte": now}})
    doc = await db[COLLECTION].find_one_and_update(
        {"_id": key},
        {"$inc": {"attempts": 1},
         "$setOnInsert": {"expires_at": now + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    if doc["attempts"] <= settings.LOGIN_MAX_FAILURES:
        return 0
    return max(1, int((doc["expires_at"] - now).total_seconds()) + 1)


async def clear_failures(db, key: str) -> None:
    await db[COLLECTION].delete_one({"_id": key})
