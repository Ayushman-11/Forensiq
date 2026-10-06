"""Mongo-backed login throttle keyed by (email, client IP). Documents expire via a TTL index on `expires_at`."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from app.core.config import settings

COLLECTION = "login_attempts"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # Mongo returns naive UTC


def throttle_key(email: str, ip: str) -> str:
    return hashlib.sha256(f"{email.strip().lower()}|{ip}".encode()).hexdigest()


async def locked_for(db, key: str) -> int:
    """Seconds until the key unlocks; 0 when not locked."""
    doc = await db[COLLECTION].find_one({"_id": key})
    if not doc or doc.get("failures", 0) < settings.LOGIN_MAX_FAILURES:
        return 0
    remaining = (doc["expires_at"] - _now()).total_seconds()
    return int(remaining) + 1 if remaining > 0 else 0


async def record_failure(db, key: str) -> None:
    now = _now()
    # The TTL monitor runs about once a minute, so drop an expired window explicitly before counting.
    await db[COLLECTION].delete_one({"_id": key, "expires_at": {"$lte": now}})
    await db[COLLECTION].update_one(
        {"_id": key},
        {"$inc": {"failures": 1}, "$set": {"expires_at": now + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)}},
        upsert=True,
    )


async def clear_failures(db, key: str) -> None:
    await db[COLLECTION].delete_one({"_id": key})
